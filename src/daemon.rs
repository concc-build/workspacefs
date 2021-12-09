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
use std::ffi::OsString;
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
use crate::Opt;
use crate::sftp;

pub(crate) fn init(
    opt: &Opt,
    sftp: sftp::Session,
) -> Result<(Sender<Message>, Daemon)> {
    let (sender, receiver) = mpsc::channel(100);
    Ok((sender, Daemon::new(opt, sftp, receiver)?))
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
    sftp: sftp::Session,
    receiver: Receiver<Message>,
    base_dir: PathBuf,
    path_table: PathTable,

    // timeout values for caching
    entry_timeout: Duration,
    attr_timeout: Duration,
    negative_timeout: Duration,

    // cache
    attr_cache: HashMap<PathBuf, Arc<sftp::FileAttr>>,
    dirent_cache: HashMap<PathBuf, Arc<Vec<DirEntry>>>,

    negative_xglobset: GlobSet,
}

impl Daemon {
    pub(crate) fn new(
        opt: &Opt,
        sftp: sftp::Session,
        receiver: Receiver<Message>,
    ) -> Result<Self> {
        let mut globset_builder = GlobSetBuilder::new();
        for glob in opt.negative_xglobs.iter() {
            globset_builder.add(Glob::new(glob)?);
        }
        Ok(Self {
            sftp,
            receiver,
            base_dir: PathBuf::from(opt.remote.path()),
            path_table: PathTable::new(),
            entry_timeout: opt.entry_timeout,
            attr_timeout: opt.attr_timeout,
            negative_timeout: opt.negative_timeout,
            attr_cache: HashMap::new(),
            dirent_cache: HashMap::new(),
            negative_xglobset: globset_builder.build()?,
        })
    }

    pub(crate) async fn run(mut self) -> Result<()> {
        while let Some(msg) = self.receiver.recv().await {
            match msg {
                Message::Request(req) => self.handle_request(req).await?,
            }
        }

        Ok(())
    }

    #[tracing::instrument(name = "handle_request", level = "debug", skip_all,
                          fields(id = req.unique()))]
    pub async fn handle_request(&mut self, req: Request) -> Result<()> {
        match req.operation()? {
            Operation::Lookup(op) => self.do_lookup(&req, op).await?,
            Operation::Forget(forgets) => self.do_forget(forgets.as_ref()),
            Operation::Getattr(op) => self.do_getattr(&req, op).await?,
            Operation::Setattr(op) => self.do_setattr(&req, op).await?,
            Operation::Readlink(op) => self.do_readlink(&req, op).await?,
            Operation::Symlink(op) => self.do_symlink(&req, op).await?,
            Operation::Unlink(op) => self.do_unlink(&req, op).await?,
            Operation::Rename(op) => self.do_rename(&req, op).await?,
            Operation::Opendir(op) => self.do_opendir(&req, op).await?,
            Operation::Readdir(op) => self.do_readdir(&req, op)?,
            Operation::Releasedir(op) => self.do_releasedir(&req, op)?,
            Operation::Open(op) => self.do_open(&req, op)?,
            Operation::Create(op) => self.do_create(&req, op).await?,
            Operation::Read(op) => self.do_read(&req, op).await?,
            Operation::Write(op, data) => self.do_write(&req, op, data).await?,
            Operation::Release(op) => self.do_release(&req, op).await?,

            op @ _ => {
                tracing::trace!(?op);
                req.reply_error(libc::ENOSYS)?
            }
        }

        Ok(())
    }

    #[tracing::instrument(name = "lookup", level = "debug", skip_all,
                          fields(parent = op.parent(), name = ?op.name()))]
    async fn do_lookup(&mut self, req: &Request, op: op::Lookup<'_>) -> io::Result<()> {
        let path = match self.path_table.get(op.parent()) {
            Some(parent) => parent.join(op.name()),
            None => {
                tracing::error!("no inode registered");
                return req.reply_error(libc::EINVAL);
            }
        };

        let full_path = self.base_dir.join(&path);
        tracing::debug!(?full_path);

        if let Some(stat) = self.attr_cache.get(&full_path) {
            tracing::debug!("hit cache");
            let inode = self.path_table.recognize(&path);

            let mut out = EntryOut::default();
            fill_attr(out.attr(), &stat);
            out.ttl_attr(self.attr_timeout);
            out.ttl_entry(self.entry_timeout);
            out.ino(inode.ino);
            out.generation(inode.generation);
            out.attr().ino(inode.ino);
            return req.reply(out);
        }

        match self.sftp.lstat(&full_path).await {
            Ok(stat) => {
                tracing::debug!(?stat);

                let stat = Arc::new(stat);
                self.attr_cache.insert(full_path.clone(), stat.clone());

                let path = full_path.strip_prefix(&self.base_dir).unwrap();
                let inode = self.path_table.recognize(&path);

                let mut out = EntryOut::default();
                fill_attr(out.attr(), &stat);
                out.ttl_attr(self.attr_timeout);
                out.ttl_entry(self.entry_timeout);
                out.ino(inode.ino);
                out.generation(inode.generation);
                out.attr().ino(inode.ino);

                req.reply(out)
            }
            Err(err) => {
                tracing::debug!(?err);
                let errno = sftp_error_to_errno(&err);
                match errno {
                    libc::ENOENT if self.can_cache_negative_lookup(&full_path) => {
                        tracing::debug!("cache negative lookup");
                        // negative cache
                        let mut out = EntryOut::default();
                        out.ttl_entry(self.negative_timeout);
                        req.reply(out)
                    }
                    err => {
                        req.reply_error(err)
                    }
                }
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

    #[tracing::instrument(name = "forget", level = "debug", skip_all)]
    fn do_forget(&mut self, forgets: &[op::Forget]) {
        for forget in forgets {
            tracing::debug!(ino = forget.ino(), nlookup = forget.nlookup());
            self.path_table.forget(forget.ino(), forget.nlookup());
        }
    }

    #[tracing::instrument(name = "getattr", level = "debug", skip_all, fields(ino = op.ino()))]
    async fn do_getattr(&mut self, req: &Request, op: op::Getattr<'_>) -> io::Result<()> {
        let path = match self.path_table.get(op.ino()) {
            Some(path) => path,
            None => {
                tracing::error!("no inode registered");
                return req.reply_error(libc::EINVAL);
            }
        };

        let full_path = self.base_dir.join(path).clone();
        tracing::debug!(?full_path);

        if let Some(stat) = self.attr_cache.get(&full_path) {
            tracing::debug!("hit cache");
            let mut out = AttrOut::default();
            fill_attr(out.attr(), &stat);
            out.attr().ino(op.ino());
            out.ttl(Duration::from_secs(60));
            return req.reply(out);
        }

        let stat = match self.sftp.lstat(&full_path).await {
            Ok(stat) => stat,
            Err(err) => {
                tracing::debug!(?err);
                return req.reply_error(sftp_error_to_errno(&err));
            }
        };

        tracing::debug!(?stat);

        let stat = Arc::new(stat);
        self.attr_cache.insert(full_path.clone(), stat.clone());

        let path = full_path.strip_prefix(&self.base_dir).unwrap();
        let ino = self.path_table.recognize(&path);

        let mut out = AttrOut::default();
        fill_attr(out.attr(), &stat);
        out.attr().ino(ino.ino);
        out.ttl(Duration::from_secs(60));
        req.reply(out)
    }

    #[tracing::instrument(name = "setattr", level = "debug", skip_all, fields(ino = op.ino()))]
    async fn do_setattr(&mut self, req: &Request, op: op::Setattr<'_>) -> io::Result<()> {
        const NO_UID: u32 = unsafe {
            mem::transmute::<i32, u32>(-1)
        };
        const NO_GID: u32 = unsafe {
            mem::transmute::<i32, u32>(-1)
        };

        let path = match self.path_table.get(op.ino()) {
            Some(path) => path,
            None => return req.reply_error(libc::EINVAL),
        };

        let full_path = self.base_dir.join(path).clone();
        tracing::debug!(?full_path);

        let mut stat = sftp::FileAttr::default();
        stat.size = op.size();
        stat.uid_gid = match (op.uid(), op.gid()) {
            (Some(uid), Some(gid)) => Some((uid, gid)),
            (Some(uid), None) => Some((uid, NO_GID)),
            (None, Some(gid)) => Some((NO_UID, gid)),
            _ => None,
        };
        stat.permissions = op.mode();
        // SFTP protocol does not support changing only one of two.
        stat.ac_mod_time = op.atime().zip(op.mtime())
            .map(|times| {
                let now = SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                    .map(|dur| dur.as_secs() as u32)
                    .ok();
                match (times, now) {
                    ((op::SetAttrTime::Timespec(atime), op::SetAttrTime::Timespec(mtime)), _) =>
                        Some((atime.as_secs() as u32, mtime.as_secs() as u32)),
                    ((op::SetAttrTime::Timespec(atime), op::SetAttrTime::Now), Some(now)) =>
                        Some((atime.as_secs() as u32, now)),
                    ((op::SetAttrTime::Now, op::SetAttrTime::Timespec(mtime)), Some(now)) =>
                        Some((now, mtime.as_secs() as u32)),
                    ((_, _), Some(now)) => Some((now, now)),
                    _ => None,
                }
            })
            .flatten();
        if let Err(err) = self.sftp.setstat(&full_path, &stat).await {
            tracing::error!(?err);
            return req.reply_error(sftp_error_to_errno(&err));
        }

        let stat = match self.sftp.lstat(&full_path).await {
            Ok(stat) => stat,
            Err(err) => return req.reply_error(sftp_error_to_errno(&err)),
        };
        tracing::debug!(?stat);

        let mut out = AttrOut::default();
        fill_attr(out.attr(), &stat);
        out.attr().ino(op.ino());
        out.ttl(Duration::from_secs(60));
        req.reply(out)
    }

    #[tracing::instrument(name = "readlink", level = "debug", skip_all)]
    async fn do_readlink(&mut self, req: &Request, op: op::Readlink<'_>) -> io::Result<()> {
        tracing::debug!(ino = op.ino());

        let path = match self.path_table.get(op.ino()) {
            Some(path) => path,
            None => return req.reply_error(libc::EINVAL),
        };

        let full_path = self.base_dir.join(path);
        tracing::debug!(?full_path);

        let link = match self.sftp.readlink(&full_path).await {
            Ok(link) => link,
            Err(err) => return req.reply_error(sftp_error_to_errno(&err)),
        };

        req.reply(link)
    }

    #[tracing::instrument(name = "symlink", level = "debug", skip_all)]
    async fn do_symlink(&mut self, req: &Request, op: op::Symlink<'_>) -> io::Result<()> {
        let path = match self.path_table.get(op.parent()) {
            Some(path) => path,
            None => return req.reply_error(libc::EINVAL),
        };

        let linkpath = self.base_dir.join(&path).join(op.name());
        let targetpath = self.base_dir.join(op.link());
        tracing::debug!(?linkpath, ?targetpath);

        match self.sftp.symlink(&linkpath, &targetpath).await {
            Ok(()) => {
                tracing::debug!("created");
            }
            Err(err) => {
                tracing::error!(?err, "sftp::symlink failed");
                return req.reply_error(sftp_error_to_errno(&err));
            }
        }

        let stat = match self.sftp.lstat(&linkpath).await {
            Ok(stat) => stat,
            Err(err) => return req.reply_error(sftp_error_to_errno(&err)),
        };
        tracing::debug!(?stat);
        
        let path = linkpath.strip_prefix(&self.base_dir).unwrap();
        let inode = self.path_table.recognize(&path);

        let mut out = EntryOut::default();
        fill_attr(out.attr(), &stat);
        out.ttl_attr(self.attr_timeout);
        out.ttl_entry(self.entry_timeout);
        out.ino(inode.ino);
        out.generation(inode.generation);
        out.attr().ino(inode.ino);
        req.reply(out)
    }

    #[tracing::instrument(name = "unlink", level = "debug", skip_all)]
    async fn do_unlink(&mut self, req: &Request, op: op::Unlink<'_>) -> io::Result<()> {
        tracing::debug!(parent = op.parent(), name = ?op.name());

        let dirpath = match self.path_table.get(op.parent()) {
            Some(path) => path,
            None => return req.reply_error(libc::EINVAL),
        };

        let full_path = self.base_dir.join(dirpath).join(op.name());
        tracing::debug!(?full_path);

        match self.sftp.remove(&full_path).await {
            Ok(_) => (),
            Err(err) => return req.reply_error(sftp_error_to_errno(&err)),
        }

        let _ = self.attr_cache.remove(&full_path);

        let full_dirpath = self.base_dir.join(dirpath);
        let _ = self.attr_cache.remove(&full_dirpath);
        let _ = self.dirent_cache.remove(&full_dirpath);

        req.reply(())
    }

    #[tracing::instrument(name = "rename", level = "debug", skip_all)]
    async fn do_rename(&mut self, req: &Request, op: op::Rename<'_>) -> io::Result<()> {
        let parent = match self.path_table.get(op.parent()) {
            Some(path) => path.to_owned(),
            None => return req.reply_error(libc::EINVAL),
        };

        let new_parent = match self.path_table.get(op.newparent()) {
            Some(path) => path.to_owned(),
            None => return req.reply_error(libc::EINVAL),
        };

        let oldpath = self.base_dir.join(&parent).join(op.name());
        let newpath = self.base_dir.join(&new_parent).join(op.newname());
        tracing::debug!(?oldpath, ?newpath);

        if op.flags() & libc::RENAME_NOREPLACE == 0 {
            tracing::debug!(?newpath, "Trying to remove it first...");
            if let Err(_) = self.sftp.remove(&newpath).await {
                tracing::debug!("sftp.remove failed");
                return req.reply_error(libc::EEXIST)

            }
        }

        match self.sftp.rename(&oldpath, &newpath).await {
            Ok(()) => {
                tracing::debug!("done");
                req.reply(())
            }
            Err(err) => {
                tracing::error!(?err);
                req.reply_error(sftp_error_to_errno(&err))
            }
        }
    }

    #[tracing::instrument(name = "opendir", level = "debug", skip_all)]
    async fn do_opendir(
        &mut self,
        req: &Request,
        op: op::Opendir<'_>
    ) -> io::Result<()> {
        tracing::debug!(ino = op.ino());

        let dirname = match self.path_table.get(op.ino()) {
            Some(path) => path.to_owned(),
            None => return req.reply_error(libc::EINVAL),
        };

        let full_dirname = self.base_dir.join(&dirname);
        tracing::debug!(?full_dirname);

        if let Some(entries) = self.dirent_cache.get(&full_dirname) {
            tracing::debug!("hit cache");
            let handle = Box::new(DirHandle {
                entries: entries.clone()
            });
            let fh = DirHandle::into_fh(handle);
            let mut out = OpenOut::default();
            out.fh(fh);
            out.direct_io(true);
            //out.cache_dir(true);
            return req.reply(out);
        }

        let dir = match self.sftp.opendir(&full_dirname).await {
            Ok(dir) => dir,
            Err(err) => {
                tracing::error!(?err);
                return req.reply_error(sftp_error_to_errno(&err))
            }
        };

        let mut entries = vec![];
        loop {
            match self.sftp.readdir(&dir).await {
                Ok(mut new_entries) => {
                    entries.append(&mut new_entries);
                }
                Err(sftp::Error::Remote(err)) if err.code() == sftp::SSH_FX_EOF => {
                    break;
                }
                Err(err) => {
                    tracing::error!(?err);
                    return req.reply_error(sftp_error_to_errno(&err))
                }
            }
        }

        if let Err(err) = self.sftp.close(&dir).await {
            tracing::error!(?err);
            return req.reply_error(sftp_error_to_errno(&err))
        }

        let mut dst = vec![];
        for entry in entries {
            if entry.filename == "." || entry.filename == ".." {
                continue;
            }

            let ino = self
                .path_table
                .lookup_ino(&dirname.join(&entry.filename))
                .unwrap_or(NO_INO);

            let typ = entry
                .attrs
                .permissions
                .map_or(libc::DT_REG as u32, |perm| {
                    (perm & libc::S_IFMT) >> 12
                });

            let stat = Arc::new(entry.attrs);
            let path = full_dirname.join(&entry.filename);
            tracing::debug!(?path, ?stat, "attr_cache.insert");
            self.attr_cache.insert(path, stat);

            dst.push(DirEntry {
                name: entry.filename,
                ino,
                typ,
            });
        }
        tracing::debug!(num = dst.len());

        let entries = Arc::new(dst);
        self.dirent_cache.insert(full_dirname.clone(), entries.clone());

        let handle = Box::new(DirHandle { entries });
        let fh = DirHandle::into_fh(handle);

        let mut out = OpenOut::default();
        out.fh(fh);
        //out.direct_io(true);
        out.cache_dir(true);

        req.reply(out)
    }

    #[tracing::instrument(name = "readdir", level = "debug", skip_all)]
    fn do_readdir(&mut self, req: &Request, op: op::Readdir<'_>) -> io::Result<()> {
        tracing::debug!(ino = op.ino(), fh = op.fh(), offset = op.offset(),
                        size = op.size());

        if op.mode() == op::ReaddirMode::Plus {
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
            if out.entry(&entry.name, entry.ino, entry.typ, (i + 1) as u64) {
                tracing::debug!("buffer fulled");
                break;
            }
            nread += 1;
        }

        tracing::debug!("read {} entries", nread);
        req.reply(out)
    }

    #[tracing::instrument(name = "releasedir", level = "debug", skip_all)]
    fn do_releasedir(&mut self, req: &Request, op: op::Releasedir<'_>) -> io::Result<()> {
        tracing::debug!(ino = op.ino());

        let _ = DirHandle::from_fh(op.fh());

        req.reply(())
    }

    #[tracing::instrument(name = "open", level = "debug", skip_all, fields(ino = op.ino()))]
    fn do_open(&mut self, req: &Request, op: op::Open<'_>) -> io::Result<()> {
        tracing::debug!(ino = op.ino());

        let path = match self.path_table.get(op.ino()) {
            Some(path) => path,
            None => return req.reply_error(libc::EINVAL),
        };

        let full_path = self.base_dir.join(path);
        tracing::debug!(?full_path);

        let open_flags = match op.flags() as i32 & libc::O_ACCMODE {
            libc::O_RDONLY => sftp::OpenFlag::READ,
            libc::O_WRONLY => sftp::OpenFlag::WRITE,
            libc::O_RDWR => sftp::OpenFlag::READ | sftp::OpenFlag::WRITE,
            _ => sftp::OpenFlag::empty(),
        };

        let handle = Box::new(FileHandle {
            open_flags,
            handle: None,
        });
        let fh = FileHandle::into_fh(handle);
        tracing::debug!(?fh);

        let mut out = OpenOut::default();
        out.fh(fh);
        out.keep_cache(true);

        req.reply(out)
    }

    #[tracing::instrument(level = "debug", name = "create", skip_all)]
    async fn do_create(
        &mut self,
        req: &Request,
        op: op::Create<'_>
    ) -> io::Result<()> {
        tracing::debug!(ino = ?op.parent());
        let dirpath = match self.path_table.get(op.parent()) {
            Some(path) => path,
            None => return req.reply_error(libc::EINVAL),
        };

        let path = dirpath.join(op.name());

        let full_path = self.base_dir.join(&path);
        tracing::debug!(?full_path);

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

        let mut attr = sftp::FileAttr::default();
        attr.permissions = Some(op.mode());

        let handle = match self
            .sftp
            .open(&full_path, open_flags, &attr)
            .await
        {
            Ok(file) => file,
            Err(err) => {
                tracing::error!("reply_err({:?})", err);
                return req.reply_error(sftp_error_to_errno(&err));
            }
        };

        let stat = match self.sftp.lstat(&full_path).await {
            Ok(stat) => stat,
            Err(err) => {
                tracing::error!("reply_err({:?})", err);
                let _ = self.sftp.close(&handle).await;
                return req.reply_error(sftp_error_to_errno(&err));
            }
        };
        tracing::debug!(?stat);

        let stat = Arc::new(stat);
        self.attr_cache.insert(full_path.clone(), stat.clone());

        let full_dirpath = self.base_dir.join(&dirpath);
        let _ = self.attr_cache.remove(&full_dirpath);
        let _ = self.dirent_cache.remove(&full_dirpath);

        let inode = self.path_table.recognize(&path);

        let handle = Box::new(FileHandle {
            open_flags,
            handle: Some(handle),
        });
        let fh = FileHandle::into_fh(handle);
        tracing::debug!(?fh);

        let mut entry_out = EntryOut::default();
        fill_attr(entry_out.attr(), &stat);
        entry_out.ttl_attr(self.entry_timeout);
        entry_out.ttl_entry(self.attr_timeout);
        entry_out.ino(inode.ino);
        entry_out.generation(inode.generation);
        entry_out.attr().ino(inode.ino);

        let mut open_out = OpenOut::default();
        open_out.fh(fh);
        open_out.keep_cache(true);

        req.reply((entry_out, open_out))
    }

    #[tracing::instrument(
        name = "read", level = "debug", skip_all,
        fields(ino = op.ino(), fh = op.fh(), offset = op.offset(), size = op.size()))]
    async fn do_read(&mut self, req: &Request, op: op::Read<'_>) -> io::Result<()> {
        let handle = match self.ensure_open(op.ino(), op.fh()).await {
            Ok(handle) => handle,
            Err(err) => {
                tracing::error!(?err);
                return req.reply_error(err);
            }
        };

        let sftp = self.sftp.clone();
        let offset = op.offset();
        let size = op.size();
        let req = req.clone();
        tokio::spawn(async move {
            tracing::debug!("start reading...");
            let _ = match sftp.read(&handle, offset, size).await {
                Ok((nread, chunks)) => {
                    tracing::debug!(nread);
                    req.reply(chunks)
                }
                Err(err) => {
                    tracing::error!(?err);
                    req.reply_error(sftp_error_to_errno(&err))
                }
            };
        }.instrument(tracing::debug_span!("task")));

        Ok(())
    }

    #[tracing::instrument(
        name = "write", level = "debug", skip_all,
        fields(ino = op.ino(), fh = op.fh(), offset = op.offset(), size = op.size()))]
    async fn do_write(
        &mut self,
        req: &Request,
        op: op::Write<'_>,
        data: Bytes,
    ) -> io::Result<()> {
        tracing::debug!("start");

        let path = match self.path_table.get(op.ino()) {
            Some(path) => path,
            None => return req.reply_error(libc::EINVAL),
        };

        let full_path = self.base_dir.join(path);
        tracing::debug!(?full_path);

        let _ = self.attr_cache.remove(&full_path);

        let handle = match self.ensure_open(op.ino(), op.fh()).await {
            Ok(handle) => handle,
            Err(err) => {
                tracing::error!(?err);
                return req.reply_error(err);
            }
        };

        let sftp = self.sftp.clone();
        let offset = op.offset();
        let size = op.size();
        let req = req.clone();
        tokio::spawn(async move {
            tracing::debug_span!("start writing...");
            let _ = match sftp.write(&handle, offset, data).await {
                Ok(()) => {
                    tracing::debug!(nwritten = size);
                    let mut out = WriteOut::default();
                    out.size(size);
                    req.reply(out)
                }
                Err(err) => {
                    tracing::error!(?err);
                    req.reply_error(sftp_error_to_errno(&err))
                }
            };
        }.instrument(tracing::debug_span!("task")));

        Ok(())
    }

    #[tracing::instrument(name = "release", level = "debug", skip_all, fields(ino = op.ino(), fh = op.fh()))]
    async fn do_release(&mut self, req: &Request, op: op::Release<'_>) -> io::Result<()> {
        let handle = match FileHandle::from_fh(op.fh()) {
            Some(handle) => handle,
            None => return req.reply_error(libc::EINVAL),
        };

        if let Some(ref sftp_handle) = handle.handle {
            match self.sftp.close(sftp_handle).await {
                Ok(()) => tracing::debug!("closed sucessfully"),
                Err(err) => {
                    tracing::error!(?err, "sftp.close failed");
                    return req.reply_error(sftp_error_to_errno(&err));
                }
            }
        }

        tracing::debug!("released");
        req.reply(())
    }

    #[tracing::instrument(name = "ensure_open", level = "debug", skip_all)]
    async fn ensure_open(
        &mut self,
        ino: u64,
        fh: u64
    ) -> Result<sftp::FileHandle, i32> {
        tracing::debug!(ino = ino, fh = fh);

        let path = match self.path_table.get(ino) {
            Some(path) => path,
            None => return Err(libc::EINVAL),
        };

        let full_path = self.base_dir.join(path);
        tracing::debug!(?full_path);

        let (open_flags, sftp_handle) = match HandleRef::<FileHandle>::from_fh(fh) {
            Some(handle_ref) => (handle_ref.open_flags, handle_ref.handle.clone()),
            None => return Err(libc::EINVAL),
        };

        if let Some(sftp_handle) = sftp_handle {
            tracing::debug!("already opened");
            return Ok(sftp_handle);
        }

        let sftp_handle = match self
            .sftp
            .open(&full_path, open_flags, &Default::default())
            .await
        {
            Ok(file) => file,
            Err(err) => return Err(sftp_error_to_errno(&err)),
        };

        HandleRef::<FileHandle>::from_fh(fh).unwrap().handle = Some(sftp_handle.clone());

        Ok(sftp_handle)
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
    name: OsString,
    typ: u32,
    ino: u64,
}

fn fill_attr(attr: &mut FileAttr, st: &sftp::FileAttr) {
    let size = st.size.unwrap_or(0);
    let mtime = Duration::from_secs(st.mtime().unwrap_or(0).into());

    attr.size(size);
    attr.mode(st.permissions.unwrap_or(0));
    attr.uid(st.uid().unwrap_or(0));
    attr.gid(st.gid().unwrap_or(0));
    attr.atime(Duration::from_secs(st.atime().unwrap_or(0).into()));
    attr.mtime(mtime);
    attr.ctime(mtime);

    attr.nlink(1);

    if cfg!(target_os = "linux") {
        const BSIZE: u64 = 4096;
        let blocks = ((size + BSIZE - 1) & !(BSIZE - 1)) >> 9;
        attr.blksize(BSIZE as u32);
        attr.blocks(blocks);
    }
}

fn sftp_error_to_errno(err: &sftp::Error) -> i32 {
    match err {
        sftp::Error::Remote(err) => match err.code() {
            sftp::SSH_FX_OK => 0,
            sftp::SSH_FX_NO_SUCH_FILE => libc::ENOENT,
            sftp::SSH_FX_PERMISSION_DENIED => libc::EPERM,
            sftp::SSH_FX_OP_UNSUPPORTED => libc::ENOTSUP,
            _ => libc::EIO,
        },
        _ => libc::EIO,
    }
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

const NO_INO: u64 = 0xFFFFFFFF;

impl PathTable {
    fn new() -> Self {
        let mut inodes = HashMap::new();
        inodes.insert(
            1,
            INode {
                refcount: u64::MAX / 2,
                ino: 1,
                generation: 0,
                path: PathBuf::new(),
            },
        );

        let mut path_to_ino = HashMap::new();
        path_to_ino.insert(PathBuf::new(), 1);

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
            Some(&ino) => self.inodes.get_mut(&ino).expect("inode is missing"),

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
}
