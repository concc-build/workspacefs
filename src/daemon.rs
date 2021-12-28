use anyhow::Result;
use bytes::Bytes;
use globset::Glob;
use globset::GlobSet;
use globset::GlobSetBuilder;
use polyfuse::Operation;
use polyfuse::Request;
use polyfuse::op;
use polyfuse::reply::*;
use static_assertions;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::mem;
use std::path::Path;
use std::path::PathBuf;
use std::ptr::NonNull;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tracing;
use tracing::Instrument;
use crate::config::Config;
use crate::config::IdMap;
use crate::remote;
use crate::sftp;

const BSIZE: u64 = if cfg!(target_os = "macos") { 0 } else { 4096 };

pub(crate) fn init(
    config: &Config,
    sftp: sftp::Session,
) -> Result<(Sender<Message>, Daemon)> {
    let (sender, receiver) = mpsc::channel(100);
    let daemon = Daemon::new(config, sftp, receiver)?;
    Ok((sender, daemon))
}

pub(crate) enum Message {
    Request(Request),
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Request(..) => write!(f, "Message::Request"),
        }
    }
}

pub(crate) struct Daemon {
    context: Context,
    receiver: Receiver<Message>,
}

impl Daemon {
    pub(crate) fn new(
        config: &Config,
        remote: sftp::Session,
        receiver: Receiver<Message>,
    ) -> Result<Self> {
        Ok(Self {
            context: Context::new(config, remote)?,
            receiver,
        })
    }

    pub(crate) async fn run(mut self) -> Result<()> {
        while let Some(msg) = self.receiver.recv().await {
            match msg {
                Message::Request(req) => self.context.handle_request(req).await?,
            }
        }

        Ok(())
    }
}

struct Context {
    remote: sftp::Session,
    path_table: PathTable,

    // id maps: remote -> local
    uid_map: HashMap<u32, u32>,
    uid_rmap: HashMap<u32, u32>,
    gid_map: HashMap<u32, u32>,
    gid_rmap: HashMap<u32, u32>,

    // timeout values for caching
    entry_timeout: Duration,
    attr_timeout: Duration,
    negative_timeout: Duration,

    // cache
    attr_cache: HashMap<PathBuf, Arc<remote::Stat>>,
    dirent_cache: HashMap<PathBuf, Arc<Vec<DirEntry>>>,

    page_cache_xglobset: GlobSet,
    dentry_cache_xglobset: GlobSet,
    negative_xglobset: GlobSet,
}

impl Context {
    fn new(config: &Config, remote: sftp::Session) -> Result<Self> {
        let mut context = Self {
            remote,
            path_table: PathTable::new(),
            uid_map: Self::make_map(&config.uid_map),
            uid_rmap: Self::make_rmap(&config.uid_map),
            gid_map: Self::make_map(&config.gid_map),
            gid_rmap: Self::make_rmap(&config.gid_map),
            entry_timeout: config.cache.entry.timeout.clone().into(),
            attr_timeout: config.cache.attr.timeout.clone().into(),
            negative_timeout: config.cache.negative.timeout.clone().into(),
            attr_cache: HashMap::new(),
            dirent_cache: HashMap::new(),
            page_cache_xglobset: Self::make_globset(
                &config.cache.page_cache.excludes, &config.cache.excludes)?,
            dentry_cache_xglobset: Self::make_globset(
                &config.cache.dentry_cache.excludes, &config.cache.excludes)?,
            negative_xglobset: Self::make_globset(
                &config.cache.negative.excludes, &config.cache.excludes)?,
        };

        context.attr_cache.insert(PathBuf::from(".netfs.d"), Arc::new(remote::Stat {
            size: Some(0),
            atime: Some(0),
            mtime: Some(0),
            mode: Some(libc::S_IFDIR | 0o0755),
            uid: Some(0),
            gid: Some(0),
        }));
        context.dirent_cache.insert(PathBuf::from(".netfs.d"), Arc::new(vec![]));

        Ok(context)
    }

    #[tracing::instrument(level = "debug", skip_all, fields(id = req.unique(), uid = req.uid(), gid = req.gid(), pid = req.pid()))]
    async fn handle_request(&mut self, req: Request) -> Result<()> {
        match req.operation()? {
            Operation::Lookup(op) => self.lookup(&req, op).await?,
            Operation::Forget(forgets) => self.forget(forgets.as_ref()),
            Operation::Getattr(op) => self.getattr(&req, op).await?,
            Operation::Setattr(op) => self.setattr(&req, op).await?,
            Operation::Readlink(op) => self.readlink(&req, op).await?,
            Operation::Symlink(op) => self.symlink(&req, op).await?,
            Operation::Mkdir(op) => self.mkdir(&req, op).await?,
            Operation::Unlink(op) => self.unlink(&req, op).await?,
            Operation::Rmdir(op) => self.rmdir(&req, op).await?,
            Operation::Rename(op) => self.rename(&req, op).await?,
            Operation::Opendir(op) => self.opendir(&req, op).await?,
            Operation::Readdir(op) => self.readdir(&req, op)?,
            Operation::Releasedir(op) => self.releasedir(&req, op)?,
            Operation::Open(op) => self.open(&req, op)?,
            Operation::Create(op) => self.create(&req, op).await?,
            Operation::Read(op) => self.read(&req, op).await?,
            Operation::Write(op, data) => self.write(&req, op, data).await?,
            Operation::Release(op) => self.release(&req, op)?,
            Operation::Statfs(op) => self.statfs(&req, op)?,
            Operation::Interrupt(op) => self.interrupt(&req,op)?,
            op @ _ => {
                tracing::trace!(?op);
                req.reply_error(libc::ENOSYS)?
            }
        }

        Ok(())
    }

    #[tracing::instrument(level = "debug", skip_all, fields(parent = op.parent(), name = ?op.name()))]
    async fn lookup(&mut self, req: &Request, op: op::Lookup<'_>) -> io::Result<()> {
        let path = match self.path_table.get(op.parent()) {
            Some(parent) => parent.join(op.name()),
            None => {
                tracing::error!("no inode registered");
                return req.reply_error(libc::EINVAL);
            }
        };
        tracing::debug!(?path);

        if let Some(stat) = self.attr_cache.get(&path) {
            tracing::debug!("hit cache");
            let inode = self.path_table.recognize(&path);
            let ino = inode.ino;
            let generation = inode.generation;

            let mut out = EntryOut::default();
            self.fill_attr(&stat, out.attr());
            out.ttl_attr(self.attr_timeout);
            out.ttl_entry(self.entry_timeout);
            out.ino(ino);
            out.generation(generation);
            out.attr().ino(ino);
            return req.reply(out);
        }

        match self.remote.lstat(&path).await {
            Ok(stat) => {
                tracing::debug!(?path, attr = ?stat, "cache attr");
                let stat = Arc::new(stat);
                self.attr_cache.insert(path.clone(), stat.clone());

                let inode = self.path_table.recognize(&path);
                let ino = inode.ino;
                let generation = inode.generation;

                let mut out = EntryOut::default();
                self.fill_attr(&stat, out.attr());
                out.ttl_attr(self.attr_timeout);
                out.ttl_entry(self.entry_timeout);
                out.ino(ino);
                out.generation(generation);
                out.attr().ino(ino);

                req.reply(out)
            }
            Err(libc::ENOENT) if self.can_cache_negative_lookup(&path) => {
                tracing::debug!("cache negative lookup");
                // negative cache
                let mut out = EntryOut::default();
                out.ttl_entry(self.negative_timeout);
                req.reply(out)
            }
            Err(errno) => {
                tracing::warn!(?errno);
                req.reply_error(errno)
            }
        }
    }

    fn can_cache_negative_lookup<P>(&self, path: P) -> bool
    where
        P: AsRef<Path>,
    {
        if self.negative_timeout.is_zero() {
            false
        } else if self.negative_xglobset.is_match(path) {
            false
        } else {
            true
        }
    }

    #[tracing::instrument(level = "debug", skip_all)]
    fn forget(&mut self, forgets: &[op::Forget]) {
        for forget in forgets {
            tracing::debug!(ino = forget.ino(), nlookup = forget.nlookup());
            self.path_table.forget(forget.ino(), forget.nlookup());
        }
    }

    #[tracing::instrument(level = "debug", skip_all, fields(ino = op.ino(), fh = op.fh()))]
    async fn getattr(&mut self, req: &Request, op: op::Getattr<'_>) -> io::Result<()> {
        let path = match self.path_table.get(op.ino()) {
            Some(path) => path,
            None => {
                tracing::error!("no inode registered");
                return req.reply_error(libc::EINVAL);
            }
        };
        tracing::debug!(?path);

        if let Some(stat) = self.attr_cache.get(path) {
            tracing::debug!("hit cache");
            let mut out = AttrOut::default();
            self.fill_attr(&stat, out.attr());
            out.attr().ino(op.ino());
            out.ttl(Duration::from_secs(60));
            return req.reply(out);
        }

        let stat = match self.remote.lstat(&path).await {
            Ok(stat) => stat,
            Err(errno) => {
                tracing::error!(?errno);
                return req.reply_error(errno);
            }
        };

        tracing::debug!(?path, attr = ?stat, "cache attr");
        let stat = Arc::new(stat);
        self.attr_cache.insert(path.to_owned(), stat.clone());

        let mut out = AttrOut::default();
        self.fill_attr(&stat, out.attr());
        out.attr().ino(op.ino());
        out.ttl(Duration::from_secs(60));
        req.reply(out)
    }

    #[tracing::instrument(level = "debug", skip_all, fields(ino = op.ino(), fh = op.fh()))]
    async fn setattr(&mut self, req: &Request, op: op::Setattr<'_>) -> io::Result<()> {
        let path = match self.path_table.get(op.ino()) {
            Some(path) => path,
            None => return req.reply_error(libc::EINVAL),
        };
        tracing::debug!(?path);

        fn convert_time(
            time: Option<op::SetAttrTime>,
            now: Option<u32>
        ) -> Option<u32> {
            time.map(|time| match time {
                op::SetAttrTime::Timespec(time) => Some(time.as_secs() as u32),
                op::SetAttrTime::Now => now,
                _ => None,
            })
            .flatten()
        }

        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|dur| dur.as_secs() as u32)
            .ok();

        let mut stat = remote::Stat::default();
        stat.size = op.size();
        stat.mode = op.mode();
        stat.atime = convert_time(op.atime(), now);
        stat.mtime = convert_time(op.mtime(), now);
        stat.uid = op.uid().map(|uid| self.rmap_uid(uid));
        stat.gid = op.gid().map(|gid| self.rmap_gid(gid));
        if let Err(errno) = self.remote.setstat(&path, stat).await {
            tracing::error!(?errno);
            return req.reply_error(errno);
        }

        let stat = match self.remote.lstat(&path).await {
            Ok(stat) => stat,
            Err(errno) => return req.reply_error(errno),
        };

        tracing::debug!(?path, attr = ?stat, "cache attr");
        let stat = Arc::new(stat);
        self.attr_cache.insert(path.to_owned(), stat.clone());

        let mut out = AttrOut::default();
        self.fill_attr(&stat, out.attr());
        out.attr().ino(op.ino());
        out.ttl(Duration::from_secs(60));
        req.reply(out)
    }

    #[tracing::instrument(level = "debug", skip_all, fields(ino = op.ino()))]
    async fn readlink(&mut self, req: &Request, op: op::Readlink<'_>) -> io::Result<()> {
        let path = match self.path_table.get(op.ino()) {
            Some(path) => path,
            None => return req.reply_error(libc::EINVAL),
        };
        tracing::debug!(?path);

        let link = match self.remote.readlink(&path).await {
            Ok(link) => link,
            Err(errno) => return req.reply_error(errno),
        };

        req.reply(link)
    }

    #[tracing::instrument(level = "debug", skip_all, fields(parent = op.parent(), name = ?op.name(), link = ?op.link()))]
    async fn symlink(&mut self, req: &Request, op: op::Symlink<'_>) -> io::Result<()> {
        let parent_path = match self.path_table.get(op.parent()) {
            Some(path) => path,
            None => return req.reply_error(libc::EINVAL),
        };

        let link_path = parent_path.join(op.name());
        let target_path = op.link();
        tracing::debug!(?link_path, ?target_path);

        match self.remote.symlink(&link_path, &target_path).await {
            Ok(()) => {
                tracing::debug!("created");
            }
            Err(errno) => {
                tracing::error!(?errno);
                return req.reply_error(errno);
            }
        }

        let stat = match self.remote.lstat(&link_path).await {
            Ok(stat) => stat,
            Err(errno) => return req.reply_error(errno),
        };

        tracing::debug!(?link_path, attr = ?stat, "cache attr");
        let stat = Arc::new(stat);
        self.attr_cache.insert(link_path.clone(), stat.clone());

        tracing::debug!(?parent_path, "invalidate cache");
        self.attr_cache.remove(parent_path);
        self.dirent_cache.remove(parent_path);

        let inode = self.path_table.recognize(&link_path);
        let ino = inode.ino;
        let generation = inode.generation;

        let mut out = EntryOut::default();
        self.fill_attr(&stat, out.attr());
        out.ttl_attr(self.attr_timeout);
        out.ttl_entry(self.entry_timeout);
        out.ino(ino);
        out.generation(generation);
        out.attr().ino(ino);
        req.reply(out)
    }

    #[tracing::instrument(level = "debug", skip_all, fields(parent = op.parent(), name = ?op.name()))]
    async fn mkdir(&mut self, req: &Request, op: op::Mkdir<'_>) -> io::Result<()> {
        let parent_path = match self.path_table.get(op.parent()) {
            Some(path) => path.to_owned(),
            None => return req.reply_error(libc::EINVAL),
        };
        let path = parent_path.join(op.name());
        tracing::debug!(?path, mode = op.mode());

        if let Err(errno) = self.remote.mkdir(&path, op.mode()).await {
            tracing::error!(?errno);
            return req.reply_error(errno);
        }

        let stat = match self.remote.lstat(&path).await {
            Ok(stat) => stat,
            Err(errno) => {
                tracing::error!(?errno);
                return req.reply_error(errno);
            }
        };

        tracing::debug!(?path, attr = ?stat, "cache attr");
        let stat = Arc::new(stat);
        self.attr_cache.insert(path.clone(), stat.clone());

        tracing::debug!(?parent_path, "invalidate cache");
        self.attr_cache.remove(&parent_path);
        self.dirent_cache.remove(&parent_path);

        let inode = self.path_table.recognize(&path);
        let ino = inode.ino;
        let generation = inode.generation;

        let mut entry_out = EntryOut::default();
        self.fill_attr(&stat, entry_out.attr());
        entry_out.ttl_attr(self.entry_timeout);
        entry_out.ttl_entry(self.attr_timeout);
        entry_out.ino(ino);
        entry_out.generation(generation);
        entry_out.attr().ino(ino);

        req.reply(entry_out)
    }

    #[tracing::instrument(level = "debug", skip_all, fields(parent = op.parent(), name = ?op.name()))]
    async fn unlink(&mut self, req: &Request, op: op::Unlink<'_>) -> io::Result<()> {
        let parent_path = match self.path_table.get(op.parent()) {
            Some(path) => path,
            None => return req.reply_error(libc::EINVAL),
        };

        let path = parent_path.join(op.name());
        tracing::debug!(?path);

        match self.remote.remove(&path).await {
            Ok(_) => {
                tracing::debug!(?path, "invalidate cache");
                self.attr_cache.remove(&path);
                self.dirent_cache.remove(&path);
                tracing::debug!(?parent_path, "invalidate cache");
                self.attr_cache.remove(parent_path);
                self.dirent_cache.remove(parent_path);
                req.reply(())
            }
            Err(errno) => {
                tracing::error!(?errno);
                req.reply_error(errno)
            }
        }
    }

    #[tracing::instrument(level = "debug", skip_all, fields(parent = op.parent(), name = ?op.name()))]
    async fn rmdir(&mut self, req: &Request, op: op::Rmdir<'_>) -> io::Result<()> {
        let parent_path = match self.path_table.get(op.parent()) {
            Some(path) => path,
            None => return req.reply_error(libc::EINVAL),
        };

        let path = parent_path.join(op.name());
        tracing::debug!(?path);

        match self.remote.rmdir(&path).await {
            Ok(_) => {
                tracing::debug!(?path, "invalidate cache");
                self.attr_cache.remove(&path);
                self.dirent_cache.remove(&path);
                tracing::debug!(?parent_path, "invalidate cache");
                self.attr_cache.remove(parent_path);
                self.dirent_cache.remove(parent_path);
                req.reply(())
            }
            Err(errno) => {
                tracing::error!(?errno);
                req.reply_error(errno)
            }
        }
    }

    #[tracing::instrument(level = "debug", skip_all, fields(parent = op.parent(), newparent = op.newparent(), name = ?op.name(), newname = ?op.newname()))]
    async fn rename(&mut self, req: &Request, op: op::Rename<'_>) -> io::Result<()> {
        let old_parent_path = match self.path_table.get(op.parent()) {
            Some(path) => path.to_owned(),
            None => return req.reply_error(libc::EINVAL),
        };

        let new_parent_path = match self.path_table.get(op.newparent()) {
            Some(path) => path.to_owned(),
            None => return req.reply_error(libc::EINVAL),
        };

        let old_path = old_parent_path.join(op.name());
        let new_path = new_parent_path.join(op.newname());
        tracing::debug!(?old_path, ?new_path);

        if old_path == new_path {
            tracing::debug!("same path");
            return req.reply(());
        }

        if op.flags() & libc::RENAME_NOREPLACE == 0 {
            tracing::debug!(?new_path, "Trying to remove it first...");
            match self.remote.remove(&new_path).await {
                Ok(_) => {
                    tracing::debug!("removed");
                }
                Err(libc::ENOENT) => {
                    tracing::debug!("no such file");
                }
                Err(errno) => {
                    tracing::debug!(?errno);
                    return req.reply_error(libc::EEXIST);
                }
            }
        }

        match self.remote.rename(&old_path, &new_path).await {
            Ok(()) => {
                self.path_table.rename(&old_path, &new_path);
                tracing::debug!(?old_path, "invalidate cache");
                self.attr_cache.remove(&old_path);
                self.dirent_cache.remove(&old_path);
                if old_path != new_path {
                    tracing::debug!(?new_path, "invalidate cache");
                    self.attr_cache.remove(&new_path);
                    self.dirent_cache.remove(&new_path);
                }
                tracing::debug!(?old_parent_path, "invalidate cache");
                self.attr_cache.remove(&old_parent_path);
                self.dirent_cache.remove(&old_parent_path);
                if old_parent_path != new_parent_path {
                    tracing::debug!(?new_parent_path, "invalidate cache");
                    self.attr_cache.remove(&new_parent_path);
                    self.dirent_cache.remove(&new_parent_path);
                }
                tracing::debug!("done");
                req.reply(())
            }
            Err(errno) => {
                tracing::error!(?errno);
                req.reply_error(errno)
            }
        }
    }

    #[tracing::instrument(level = "debug", skip_all, fields(ino = op.ino()))]
    async fn opendir(
        &mut self,
        req: &Request,
        op: op::Opendir<'_>
    ) -> io::Result<()> {
        let path = match self.path_table.get(op.ino()) {
            Some(path) => path.to_owned(),
            None => return req.reply_error(libc::EINVAL),
        };
        tracing::debug!(?path);

        if let Some(entries) = self.dirent_cache.get(&path) {
            tracing::debug!("hit cache");
            let handle = Box::new(DirHandle {
                entries: entries.clone()
            });
            let fh = DirHandle::into_fh(handle);
            let mut out = OpenOut::default();
            out.fh(fh);
            if !self.dentry_cache_xglobset.is_match(&path) {
                out.cache_dir(true);
            }
            return req.reply(out);
        }

        let handle = match self.remote.opendir(&path).await {
            Ok(handle) => handle,
            Err(errno) => {
                tracing::error!(?errno);
                return req.reply_error(errno)
            }
        };

        let mut entries = vec![];
        if op.ino() == ROOT_INO {
            entries.push(DirEntry {
                name: ".netfs.d".to_string(),
                ino: NO_INO,
                typ: libc::S_IFDIR,
            });
        }
        loop {
            match self.remote.readdir(&handle).await {
                Ok(new_entries) => {
                    for entry in new_entries.into_iter() {
                        if entry.name == "." || entry.name == ".." {
                            continue;
                        }
                        let ino = if cfg!(target_os = "linux") {
                            NO_INO
                        } else {
                            let entry_path = path.join(&entry.name);
                            self.path_table
                                .lookup_ino(&entry_path)
                                .unwrap_or(NO_INO)
                        };
                        entries.push(DirEntry {
                            name: entry.name,
                            typ: entry.kind,
                            ino,
                        });
                    }
                }
                Err(0) => break,
                Err(errno) => {
                    tracing::error!(?errno);
                    return req.reply_error(errno)
                }
            }
        }
        tracing::debug!(num = entries.len());

        self.invoke_close(handle);

        let entries = Arc::new(entries);
        self.dirent_cache.insert(path.clone(), entries.clone());

        let handle = Box::new(DirHandle { entries });
        let fh = DirHandle::into_fh(handle);

        let mut out = OpenOut::default();
        out.fh(fh);
        if !self.dentry_cache_xglobset.is_match(&path) {
            out.cache_dir(true);
        }

        req.reply(out)
    }

    #[tracing::instrument(level = "debug", skip_all, fields(ino = op.ino(), fh = op.fh()))]
    fn readdir(&mut self, req: &Request, op: op::Readdir<'_>) -> io::Result<()> {
        tracing::debug!(offset = op.offset(), size = op.size());

        if op.mode() == op::ReaddirMode::Plus {
            tracing::error!("not supported");
            return req.reply_error(libc::ENOSYS);
        }

        let handle_ref = match HandleRef::<DirHandle>::from_fh(op.fh()) {
            Some(handle_ref) => handle_ref,
            None => return req.reply_error(libc::EINVAL),
        };

        let offset = op.offset() as usize;
        if offset >= handle_ref.entries.len() {
            tracing::debug!("no entry to read");
            return req.reply(());
        }

        let mut nread = 0;
        let mut out = ReaddirOut::new(op.size() as usize);
        for (i, entry) in handle_ref.entries.iter().enumerate().skip(offset) {
            if out.entry(OsStr::new(&entry.name), entry.ino, entry.typ, (i + 1) as u64) {
                tracing::debug!("buffer fulled");
                break;
            }
            nread += 1;
        }

        tracing::debug!("read {} entries", nread);
        req.reply(out)
    }

    #[tracing::instrument(level = "debug", skip_all, fields(ino = op.ino(), fh = op.fh()))]
    fn releasedir(&mut self, req: &Request, op: op::Releasedir<'_>) -> io::Result<()> {
        let _ = DirHandle::from_fh(op.fh());
        tracing::debug!("released");

        req.reply(())
    }

    #[tracing::instrument(level = "debug", skip_all, fields(ino = op.ino()))]
    fn open(&mut self, req: &Request, op: op::Open<'_>) -> io::Result<()> {
        let path = match self.path_table.get(op.ino()) {
            Some(path) => path,
            None => return req.reply_error(libc::EINVAL),
        };
        tracing::debug!(?path);

        let mut open_flags = match op.flags() as i32 & libc::O_ACCMODE {
            libc::O_RDONLY => sftp::OpenFlag::READ,
            libc::O_WRONLY => sftp::OpenFlag::WRITE,
            libc::O_RDWR => sftp::OpenFlag::READ | sftp::OpenFlag::WRITE,
            _ => sftp::OpenFlag::empty(),
        };
        if op.flags() as i32 & libc::O_CREAT == libc::O_CREAT {
            open_flags = open_flags | sftp::OpenFlag::CREAT;
        }
        if op.flags() as i32 & libc::O_EXCL == libc::O_EXCL {
            open_flags = open_flags | sftp::OpenFlag::EXCL;
        }
        if op.flags() as i32 & libc::O_TRUNC == libc::O_TRUNC {
            open_flags = open_flags | sftp::OpenFlag::TRUNC;
        }
        if op.flags() as i32 & libc::O_APPEND == libc::O_APPEND {
            open_flags = open_flags | sftp::OpenFlag::APPEND;
        }

        // TODO: Keep inode until the handle is released.
        let handle = Box::new(FileHandle {
            path: path.to_owned(),
            open_flags,
            handle: None,
        });
        let fh = FileHandle::into_fh(handle);
        tracing::debug!(?fh);

        let mut out = OpenOut::default();
        out.fh(fh);
        if !self.page_cache_xglobset.is_match(&path) {
            out.keep_cache(true);
        }

        req.reply(out)
    }

    #[tracing::instrument(level = "debug", name = "create", skip_all, fields(parent = op.parent(), name = ?op.name()))]
    async fn create(&mut self, req: &Request, op: op::Create<'_>) -> io::Result<()> {
        let parent_path = match self.path_table.get(op.parent()) {
            Some(path) => path.to_owned(),
            None => return req.reply_error(libc::EINVAL),
        };

        let path = parent_path.join(op.name());
        tracing::debug!(?path);

        let mut open_flags = match op.open_flags() as i32 & libc::O_ACCMODE {
            libc::O_RDONLY => sftp::OpenFlag::READ,
            libc::O_WRONLY => sftp::OpenFlag::WRITE,
            libc::O_RDWR => sftp::OpenFlag::READ | sftp::OpenFlag::WRITE,
            _ => return req.reply_error(libc::EINVAL),
        };
        if op.open_flags() as i32 & libc::O_CREAT == libc::O_CREAT {
            open_flags = open_flags | sftp::OpenFlag::CREAT;
        }
        if op.open_flags() as i32 & libc::O_EXCL == libc::O_EXCL {
            open_flags = open_flags | sftp::OpenFlag::EXCL;
        }
        if op.open_flags() as i32 & libc::O_TRUNC == libc::O_TRUNC {
            open_flags = open_flags | sftp::OpenFlag::TRUNC;
        }
        if op.open_flags() as i32 & libc::O_APPEND == libc::O_APPEND {
            open_flags = open_flags | sftp::OpenFlag::APPEND;
        }

        let handle = match self.remote.open(&path, open_flags, Some(op.mode())).await {
            Ok(file) => file,
            Err(errno) => {
                tracing::error!(?errno);
                return req.reply_error(errno);
            }
        };

        let stat = match self.remote.lstat(&path).await {
            Ok(stat) => stat,
            Err(errno) => {
                self.invoke_close(handle);
                tracing::error!(?errno);
                return req.reply_error(errno);
            }
        };

        tracing::debug!(?path, attr = ?stat, "cache attr");
        let stat = Arc::new(stat);
        self.attr_cache.insert(path.clone(), stat.clone());

        tracing::debug!(?parent_path, "invalidate cache");
        self.attr_cache.remove(&parent_path);
        self.dirent_cache.remove(&parent_path);

        let inode = self.path_table.recognize(&path);
        let ino = inode.ino;
        let generation = inode.generation;

        let handle = Box::new(FileHandle {
            path: path.clone(),
            open_flags,
            handle: Some(handle),
        });
        let fh = FileHandle::into_fh(handle);
        tracing::debug!(?fh);

        let mut entry_out = EntryOut::default();
        self.fill_attr(&stat, entry_out.attr());
        entry_out.ttl_attr(self.entry_timeout);
        entry_out.ttl_entry(self.attr_timeout);
        entry_out.ino(ino);
        entry_out.generation(generation);
        entry_out.attr().ino(ino);

        let mut open_out = OpenOut::default();
        open_out.fh(fh);
        if !self.page_cache_xglobset.is_match(&path) {
            open_out.keep_cache(true);
        }

        req.reply((entry_out, open_out))
    }

    #[tracing::instrument(level = "debug", skip_all, fields(ino = op.ino(), fh = op.fh(), offset = op.offset(), size = op.size()))]
    async fn read(&mut self, req: &Request, op: op::Read<'_>) -> io::Result<()> {
        let remote = self.remote.clone();
        let fh = op.fh();
        let offset = op.offset();
        let size = op.size();
        let req = req.clone();
        tokio::spawn(async move {
            let handle = match Self::ensure_open(fh, &remote).await {
                Ok(handle) => handle,
                Err(errno) => {
                    tracing::error!(?errno);
                    let _ = req.reply_error(errno);
                    return;
                }
            };
            tracing::debug!("start reading...");
            let _ = match remote.read(&handle, offset, size).await {
                Ok((nread, chunks)) => {
                    tracing::debug!(nread);
                    req.reply(chunks)
                }
                Err(errno) => {
                    tracing::error!(?errno);
                    req.reply_error(errno)
                }
            };
        }.instrument(tracing::debug_span!("task")));

        Ok(())
    }

    #[tracing::instrument(level = "debug", skip_all, fields(ino = op.ino(), fh = op.fh(), offset = op.offset(), size = op.size()))]
    async fn write(
        &mut self,
        req: &Request,
        op: op::Write<'_>,
        data: Bytes,
    ) -> io::Result<()> {
        let path = match self.path_table.get(op.ino()) {
            Some(path) => path,
            None => return req.reply_error(libc::EINVAL),
        };
        tracing::debug!(?path, "invalidate cache");
        self.attr_cache.remove(path);

        let remote = self.remote.clone();
        let fh = op.fh();
        let offset = op.offset();
        let size = op.size();
        let req = req.clone();
        tokio::spawn(async move {
            let handle = match Self::ensure_open(fh, &remote).await {
                Ok(handle) => handle,
                Err(errno) => {
                    tracing::error!(?errno);
                    let _ = req.reply_error(errno);
                    return;
                }
            };
            tracing::debug!("start writing...");
            let _ = match remote.write(&handle, offset, data).await {
                Ok(()) => {
                    tracing::debug!(nwritten = size);
                    let mut out = WriteOut::default();
                    out.size(size);
                    req.reply(out)
                }
                Err(errno) => {
                    tracing::error!(?errno);
                    req.reply_error(errno)
                }
            };
        }.instrument(tracing::debug_span!("task")));

        Ok(())
    }

    #[tracing::instrument(level = "debug", skip_all, fields(ino = op.ino(), fh = op.fh()))]
    fn release(&self, req: &Request, op: op::Release<'_>) -> io::Result<()> {
        // Assumed that all operations using the file handle have been finished.
        let mut handle = match FileHandle::from_fh(op.fh()) {
            Some(handle) => handle,
            None => return req.reply_error(libc::EINVAL),
        };

        if let Some(handle) = handle.handle.take() {
            self.invoke_close(handle);
        }
        tracing::debug!("released");

        req.reply(())
    }

    #[tracing::instrument(level = "debug", skip_all, fields(ino = op.ino()))]
    fn statfs(&self, req: &Request, op: op::Statfs<'_>) -> io::Result<()> {
        let path = match self.path_table.get(op.ino()) {
            Some(path) => path.to_owned(),
            None => return req.reply_error(libc::EINVAL),
        };
        tracing::debug!(?path);

        let remote = self.remote.clone();
        let req = req.clone();
        tokio::spawn(async move {
            let _ = match remote.statfs(&path).await {
                Ok(statfs) => {
                    tracing::debug!(?statfs);
                    let mut out = StatfsOut::default();
                    Self::fill_statfs(&statfs, out.statfs());
                    req.reply(out)
                }
                Err(errno) => {
                    tracing::error!(?errno);
                    req.reply_error(errno)
                }
            };
        }.instrument(tracing::debug_span!("task")));

        Ok(())
    }

    #[tracing::instrument(level = "debug", skip_all)]
    fn interrupt(&mut self, _req: &Request, _op: op::Interrupt<'_>
    ) -> io::Result<()> {
        // Currrently, a request is processed on a single thread.
        // So, stopping the processing of the request is not needed.
        tracing::debug!("interrupted");
        Ok(())
    }

    fn map_uid(&self, uid: u32) -> u32 {
        self.uid_map.get(&uid).cloned().unwrap_or(uid)
    }

    fn rmap_uid(&self, uid: u32) -> u32 {
        self.uid_rmap.get(&uid).cloned().unwrap_or(uid)
    }

    fn map_gid(&self, gid: u32) -> u32 {
        self.gid_map.get(&gid).cloned().unwrap_or(gid)
    }

    fn rmap_gid(&self, gid: u32) -> u32 {
        self.gid_rmap.get(&gid).cloned().unwrap_or(gid)
    }

    fn fill_attr(&self, stat: &remote::Stat, attr: &mut FileAttr) {
        let size = stat.size.unwrap_or(0);
        let uid = stat.uid.map(|uid| self.map_uid(uid)).unwrap_or(0);
        let gid = stat.gid.map(|gid| self.map_gid(gid)).unwrap_or(0);
        let atime = Duration::from_secs(stat.atime.unwrap_or(0).into());
        let mtime = Duration::from_secs(stat.mtime.unwrap_or(0).into());

        attr.size(size);
        attr.mode(stat.mode.unwrap_or(0));
        attr.uid(uid);
        attr.gid(gid);
        attr.atime(atime);
        attr.mtime(mtime);
        attr.ctime(mtime);

        attr.nlink(1);

        if cfg!(target_os = "linux") {
            let blocks = ((size + BSIZE - 1) & !(BSIZE - 1)) >> 9;
            attr.blksize(BSIZE as u32);
            attr.blocks(blocks);
        }
    }

    fn fill_statfs(src: &remote::Statfs, dest: &mut Statfs) {
        dest.bsize(src.bsize);
        dest.frsize(src.frsize);
        dest.blocks(src.blocks);
        dest.bfree(src.bfree);
        dest.bavail(src.bavail);
        dest.files(src.files);
        dest.ffree(src.ffree);
        dest.namelen(src.namelen);
    }

    #[tracing::instrument(level = "debug", skip_all)]
    async fn ensure_open(
        fh: u64,
        remote: &sftp::Session,
    ) -> Result<sftp::FileHandle, i32> {
        let remote_handle = match HandleRef::<FileHandle>::from_fh(fh) {
            Some(handle_ref) => handle_ref.handle.clone(),
            None => return Err(libc::EINVAL),
        };

        if let Some(remote_handle) = remote_handle {
            tracing::debug!("already opened");
            return Ok(remote_handle);
        }

        let (path, open_flags) = match HandleRef::<FileHandle>::from_fh(fh) {
            Some(handle_ref) => (handle_ref.path.clone(), handle_ref.open_flags),
            None => return Err(libc::EINVAL),
        };

        let remote_handle = match remote.open(&path, open_flags, None).await {
            Ok(handle) => handle,
            Err(errno) => return Err(errno),
        };

        HandleRef::<FileHandle>::from_fh(fh).unwrap().handle = Some(remote_handle.clone());

        Ok(remote_handle)
    }

    fn make_map(idmap: &[IdMap]) -> HashMap<u32, u32> {
        let mut map = HashMap::new();
        for id in idmap.iter() {
            map.insert(id.remote, id.local);
        }
        map
    }

    fn make_rmap(idmap: &[IdMap]) -> HashMap<u32, u32> {
        let mut map = HashMap::new();
        for id in idmap.iter() {
            map.insert(id.local, id.remote);
        }
        map
    }

    fn make_globset(globs: &[String], global_globs: &[String]) -> Result<GlobSet> {
        let mut builder = GlobSetBuilder::new();
        for glob in global_globs.iter() {
            builder.add(Glob::new(glob)?);
        }
        for glob in globs.iter() {
            builder.add(Glob::new(glob)?);
        }
        Ok(builder.build()?)
    }

    fn invoke_close(&self, handle: sftp::FileHandle) {
        let sftp = self.remote.clone();
        tokio::spawn(async move {
            match sftp.close(&handle).await {
                Ok(_) => tracing::debug!("closed successfully"),
                Err(err) => tracing::error!(?err, "sftp.close failed"),
            }
        }.instrument(tracing::debug_span!("task")));
    }
}

struct DirHandle {
    entries: Arc<Vec<DirEntry>>,
}

impl DirHandle {
    fn into_fh(b: Box<Self>) -> u64 {
        static_assertions::const_assert!(
            mem::size_of::<u64>() >= mem::size_of::<*mut DirHandle>());
        let raw = Box::into_raw(b);
        raw as u64
    }

    fn from_fh(fh: u64) -> Option<Box<Self>> {
        unsafe {
            match fh {
                0 => None,
                _ => Some(Box::from_raw(fh as *mut DirHandle)),
            }
        }
    }
}

struct FileHandle {
    path: PathBuf,
    open_flags: sftp::OpenFlag,
    handle: Option<sftp::FileHandle>,
}

impl FileHandle {
    fn into_fh(b: Box<Self>) -> u64 {
        static_assertions::const_assert!(
            mem::size_of::<u64>() >= mem::size_of::<*mut FileHandle>());
        let raw = Box::into_raw(b);
        raw as u64
    }

    fn from_fh(fh: u64) -> Option<Box<Self>> {
        unsafe {
            match fh {
                0 => None,
                _ => Some(Box::from_raw(fh as *mut FileHandle)),
            }
        }
    }
}

struct HandleRef<T> {
    inner: NonNull<T>,
}

impl<T> HandleRef<T> {
    fn from_fh(fh: u64) -> Option<Self> {
        NonNull::new(fh as *mut T)
            .map(|inner| Self { inner })
    }
}

impl<T> std::ops::Deref for HandleRef<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe {
            self.inner.as_ref()
        }
    }
}

impl<T> std::ops::DerefMut for HandleRef<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe {
            self.inner.as_mut()
        }
    }
}

#[derive(Debug)]
struct DirEntry {
    name: String,
    typ: u32,
    ino: u64,
}

/// Data structure that holds the correspondence between inode number and path.
struct PathTable {
    inodes: HashMap<u64, INode>,
    path_to_ino: HashMap<PathBuf, u64>,
    count: u64,
    generation: u64,
}

struct INode {
    refcount: u64,
    ino: u64,
    generation: u64,
    path: PathBuf,
}

const ROOT_INO: u64 = 1;
const NO_INO: u64 = 0xFFFFFFFF;

impl PathTable {
    fn new() -> Self {
        let mut inodes = HashMap::new();
        inodes.insert(
            ROOT_INO,
            INode {
                refcount: u64::MAX / 2,
                ino: 1,
                generation: 0,
                path: PathBuf::new(),
            },
        );

        let mut path_to_ino = HashMap::new();
        path_to_ino.insert(PathBuf::new(), ROOT_INO);

        Self {
            inodes,
            path_to_ino,
            count: 1,
            generation: 0,
        }
    }

    fn make_next_ino(&mut self) -> (u64, u64) {
        let mut count = self.count;
        let mut generation = self.generation;
        loop {
            count += 1;
            if count == NO_INO {
                let (new_generation, overflow) = generation.overflowing_add(1);
                assert!(!overflow);
                generation = new_generation;
                count = 1;
                continue;
            }
            debug_assert!(count > 1);
            if self.inodes.contains_key(&count) {
                continue;
            }
            break;
        }
        self.count = count;
        self.generation = generation;
        (count, generation)
    }

    fn get(&self, ino: u64) -> Option<&Path> {
        self.inodes.get(&ino).map(|inode| &*inode.path)
    }

    fn lookup_ino(&self, path: &Path) -> Option<u64> {
        self.path_to_ino.get(path).cloned()
    }

    fn recognize(&mut self, path: &Path) -> &mut INode {
        match self.path_to_ino.get(path) {
            Some(&ino) => {
                let mut inode = self.inodes.get_mut(&ino).expect("inode is missing");
                inode.refcount += 1;
                inode
            }
            None => {
                let (ino, generation) = self.make_next_ino();
                let inode = self.inodes.entry(ino).or_insert_with(|| INode {
                    refcount: 1,
                    ino,
                    generation,
                    path: path.to_owned(),
                });
                self.path_to_ino.insert(path.to_owned(), ino);
                inode
            }
        }
    }

    fn forget(&mut self, ino: u64, nlookup: u64) {
        use std::collections::hash_map::Entry;
        if let Entry::Occupied(mut entry) = self.inodes.entry(ino) {
            let refcount = {
                let inode = entry.get_mut();
                inode.refcount = inode.refcount.saturating_sub(nlookup);
                inode.refcount
            };
            if refcount == 0 {
                tracing::debug!(ino, "dropped");
                let inode = entry.remove();
                self.path_to_ino.remove(&inode.path);
            }
        }
    }

    fn rename(&mut self, old: &Path, new: &Path) {
        if let Some(ino) = self.path_to_ino.get(new) {
            // TODO: keep inode while someone uses it
            tracing::debug!(ino, "removed");
            self.inodes.remove(ino);
            self.path_to_ino.remove(new);
        }
        let ino = self.path_to_ino.remove(old).expect("ino is missing");
        self.path_to_ino.insert(new.to_owned(), ino);
        if let Some(inode) = self.inodes.get_mut(&ino) {
            inode.path = new.to_owned();
        }
        tracing::debug!(?new, ino, "inserted");
    }
}
