use anyhow::Result;
use polyfuse::Data;
use polyfuse::Operation;
use polyfuse::Request;
use polyfuse::op;
use polyfuse::reply::*;
use slab::Slab;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt;
use std::io;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tracing;
use crate::Opt;
use crate::sftp;

pub(crate) fn init(
    opt: &Opt,
    sftp: sftp::Session,
) -> (Sender<Message>, Daemon) {
    let (sender, receiver) = mpsc::channel(100);
    (sender.clone(), Daemon::new(opt, sftp, receiver, sender))
}

type SftpResult<T> = std::result::Result<T, sftp::Error>;

pub(crate) enum Message {
    Request(Request),
    ReplyLookup(usize, PathBuf, SftpResult<sftp::FileAttr>),
    ReplyGetattr(usize, PathBuf, SftpResult<sftp::FileAttr>),
    ReplyOpenDir(usize, PathBuf, SftpResult<Vec<sftp::DirEntry>>),
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Request(..) => write!(f, "Message::Request"),
            Self::ReplyLookup(..) => write!(f, "Message::ReplyLookup"),
            Self::ReplyGetattr(..) => write!(f, "Message::ReplyGetattr"),
            Self::ReplyOpenDir(..) => write!(f, "Message::ReplyOpenDir"),
        }
    }
}

pub(crate) struct Daemon {
    sftp: sftp::Session,
    receiver: Receiver<Message>,
    sender: Sender<Message>,
    base_dir: PathBuf,
    path_table: PathTable,
    dir_handles: Slab<DirHandle>,
    file_handles: Slab<FileState>,
    pending_requests: Slab<Request>,

    // cache
    attr_cache: HashMap<PathBuf, Arc<sftp::FileAttr>>,
    dirent_cache: HashMap<PathBuf, Arc<Vec<DirEntry>>>,
}

impl Daemon {
    pub(crate) fn new(
        opt: &Opt,
        sftp: sftp::Session,
        receiver: Receiver<Message>,
        sender: Sender<Message>,
    ) -> Self {
        Self {
            sftp,
            receiver,
            sender,
            base_dir: PathBuf::from(opt.remote.path()),
            path_table: PathTable::new(),
            dir_handles: Slab::new(),
            file_handles: Slab::new(),
            pending_requests: Slab::new(),
            attr_cache: HashMap::new(),
            dirent_cache: HashMap::new(),
        }
    }

    pub(crate) async fn run(mut self) -> Result<()> {
        while let Some(msg) = self.receiver.recv().await {
            match msg {
                Message::Request(req) => self.handle_request(req).await?,
                Message::ReplyLookup(req_id, full_path, result) =>
                    self.do_reply_lookup(req_id, full_path, result).await?,
                Message::ReplyGetattr(req_id, full_path, result) =>
                    self.do_reply_getattr(req_id, full_path, result).await?,
                Message::ReplyOpenDir(req_id, full_dirname, result) =>
                    self.do_reply_opendir(req_id, full_dirname, result).await?,
            }
        }

        Ok(())
    }

    async fn handle_request(&mut self, req: Request) -> Result<()> {
        let span = tracing::debug_span!("handle_request", unique = req.unique());
        let _enter = span.enter();

        match req.operation()? {
            Operation::Lookup(op) => self.do_lookup(&req, op).await?,
            Operation::Forget(forgets) => self.do_forget(forgets.as_ref()),

            Operation::Getattr(op) => self.do_getattr(&req, op)?,
            Operation::Readlink(op) => self.do_readlink(&req, op).await?,

            Operation::Opendir(op) => self.do_opendir(&req, op).await?,
            Operation::Readdir(op) => self.do_readdir(&req, op)?,
            Operation::Releasedir(op) => self.do_releasedir(&req, op)?,

            Operation::Open(op) => self.do_open(&req, op)?,
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

    async fn do_lookup(&mut self, req: &Request, op: op::Lookup<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("lookup", parent = op.parent(), name = ?op.name());
        let _enter = span.enter();

        let path = match self.path_table.get(op.parent()) {
            Some(parent) => parent.join(op.name()),
            None => return req.reply_error(libc::EINVAL),
        };

        let full_path = self.base_dir.join(&path);
        tracing::debug!(?full_path);

        if let Some(stat) = self.attr_cache.get(&full_path) {
            tracing::debug!("hit cache");
            let inode = self.path_table.recognize(&path);
            inode.refcount += 1;

            let mut out = EntryOut::default();
            fill_attr(out.attr(), &stat);
            out.ttl_attr(Duration::from_secs(60));
            out.ttl_entry(Duration::from_secs(60));
            out.ino(inode.ino);
            out.attr().ino(inode.ino);
            return req.reply(out);
        }

        let req_id = self.pending_requests.insert(req.clone());
        let sftp = self.sftp.clone();
        let sender = self.sender.clone();
        let full_path = full_path.clone();
        tokio::spawn(async move {
            let result = sftp.lstat(&full_path).await;
            let _ = sender.send(Message::ReplyLookup(
                req_id, full_path, result)).await;
        });

        Ok(())
    }

    async fn do_reply_lookup(
        &mut self,
        req_id: usize,
        full_path: PathBuf,
        result: SftpResult<sftp::FileAttr>
    ) -> io::Result<()> {
        let req = self.pending_requests.remove(req_id);

        let stat = match result {
            Ok(stat) => stat,
            Err(err) => return req.reply_error(sftp_error_to_errno(&err)),
        };

        tracing::debug!(?stat);

        let stat = Arc::new(stat);
        self.attr_cache.insert(full_path.clone(), stat.clone());

        let path = full_path.strip_prefix(&self.base_dir).unwrap();
        let inode = self.path_table.recognize(&path);
        inode.refcount += 1;

        let mut out = EntryOut::default();
        fill_attr(out.attr(), &stat);
        out.ttl_attr(Duration::from_secs(60));
        out.ttl_entry(Duration::from_secs(60));
        out.ino(inode.ino);
        out.attr().ino(inode.ino);

        req.reply(out)
    }

    fn do_forget(&mut self, forgets: &[op::Forget]) {
        let span = tracing::debug_span!("forget", forgets = ?forgets);
        let _enter = span.enter();

        for forget in forgets {
            tracing::debug!(ino = forget.ino(), nlookup = forget.nlookup());
            self.path_table.forget(forget.ino(), forget.nlookup());
        }
    }

    fn do_getattr(&mut self, req: &Request, op: op::Getattr<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("getattr", ino = op.ino());
        let _enter = span.enter();

        let path = match self.path_table.get(op.ino()) {
            Some(path) => path,
            None => return req.reply_error(libc::EINVAL),
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

        let sftp = self.sftp.clone();
        let sender = self.sender.clone();
        let req_id = self.pending_requests.insert(req.clone());
        tokio::spawn(async move {
            let result = sftp.lstat(&full_path).await;
            let _ = sender.send(Message::ReplyGetattr(
                req_id, full_path, result)).await;
        });

        Ok(())
    }

    async fn do_reply_getattr(
        &mut self,
        req_id: usize,
        full_path: PathBuf,
        result: SftpResult<sftp::FileAttr>,
    ) -> io::Result<()> {
        let req = self.pending_requests.remove(req_id);

        let stat = match result {
            Ok(stat) => stat,
            Err(err) => return req.reply_error(sftp_error_to_errno(&err)),
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

    async fn do_readlink(&mut self, req: &Request, op: op::Readlink<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("readlink", ino = op.ino());
        let _enter = span.enter();

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

    async fn do_opendir(
        &mut self,
        req: &Request,
        op: op::Opendir<'_>
    ) -> io::Result<()> {
        let span = tracing::debug_span!("opendir", ino = op.ino());
        let _enter = span.enter();

        let dirname = match self.path_table.get(op.ino()) {
            Some(path) => path.to_owned(),
            None => return req.reply_error(libc::EINVAL),
        };

        let full_dirname = self.base_dir.join(&dirname);
        tracing::debug!(?full_dirname);

        if let Some(entries) = self.dirent_cache.get(&full_dirname) {
            tracing::debug!("hit cache");
            let fh = self.dir_handles.insert(DirHandle {
                entries: entries.clone()
            }) as u64;
            let mut out = OpenOut::default();
            out.fh(fh);
            //out.direct_io(true);
            out.cache_dir(true);
            return req.reply(out);
        }

        let sftp = self.sftp.clone();
        let sender = self.sender.clone();
        let req_id = self.pending_requests.insert(req.clone());
        let full_dirname = full_dirname.clone();
        tokio::spawn(async move {
            let dir = match sftp.opendir(&full_dirname).await {
                Ok(dir) => dir,
                Err(err) => {
                    let _ = sender.send(Message::ReplyOpenDir(
                        req_id, full_dirname, Err(err))).await;
                    return;
                }
            };

            let entries = match sftp.readdir(&dir).await {
                Ok(entries) => entries,
                Err(sftp::Error::Remote(err)) if err.code() == sftp::SSH_FX_EOF => {
                    vec![]
                }
                Err(err) => {
                    let _ = sender.send(Message::ReplyOpenDir(
                        req_id, full_dirname, Err(err))).await;
                    return;
                }
            };

            if let Err(err) = sftp.close(&dir).await {
                tracing::error!(?err);
            }

            let _ = sender.send(Message::ReplyOpenDir(
                req_id, full_dirname, Ok(entries))).await;
        });

        Ok(())
    }

    async fn do_reply_opendir(
        &mut self,
        req_id: usize,
        full_dirname: PathBuf,
        result: SftpResult<Vec<sftp::DirEntry>>,
    ) -> io::Result<()> {
        let req = self.pending_requests.remove(req_id);

        let entries = match result {
            Ok(entries) => entries,
            Err(err) => return req.reply_error(sftp_error_to_errno(&err)),
        };

        let dirname = full_dirname.strip_prefix(&self.base_dir).unwrap();

        let mut dst = vec![];
        for entry in entries {
            if entry.filename == "." || entry.filename == ".." {
                continue;
            }

            let ino = self
                .path_table
                .recognize(&dirname.join(&entry.filename))
                .ino;

            let typ = entry
                .attrs
                .permissions
                .map_or(libc::DT_REG as u32, |perm| {
                    (perm & libc::S_IFMT) >> 12
                });

            let stat = Arc::new(entry.attrs);
            let path = full_dirname.join(&entry.filename);
            self.attr_cache.insert(path, stat);

            dst.push(DirEntry {
                name: entry.filename,
                ino,
                typ,
            });
        }
        tracing::debug!(?dst);

        let entries = Arc::new(dst);
        self.dirent_cache.insert(full_dirname.clone(), entries.clone());

        let fh = self.dir_handles.insert(DirHandle { entries }) as u64;

        let mut out = OpenOut::default();
        out.fh(fh);
        //out.direct_io(true);
        out.cache_dir(true);

        req.reply(out)
    }

    fn do_readdir(&mut self, req: &Request, op: op::Readdir<'_>) -> io::Result<()> {
        let span = tracing::debug_span!(
            "readdir", ino = op.ino(), fh = op.fh(), offset = op.offset(),
            size = op.size());
        let _enter = span.enter();

        if op.mode() == op::ReaddirMode::Plus {
            return req.reply_error(libc::ENOSYS);
        }

        let handle = match self.dir_handles.get_mut(op.fh() as usize) {
            Some(handle) => handle,
            None => return req.reply_error(libc::EINVAL),
        };

        let offset = op.offset() as usize;
        if offset >= handle.entries.len() {
            tracing::debug!("no entry to read");
            return req.reply(());
        }

        let mut nread = 0;
        let mut out = ReaddirOut::new(op.size() as usize);
        for (i, entry) in handle.entries.iter().enumerate().skip(offset) {
            if out.entry(&entry.name, entry.ino, entry.typ, (i + 1) as u64) {
                tracing::debug!("buffer fulled");
                break;
            }
            nread += 1;
        }

        tracing::debug!("read {} entries", nread);
        req.reply(out)
    }

    fn do_releasedir(&mut self, req: &Request, op: op::Releasedir<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("releasedir", ino = op.ino());
        let _enter = span.enter();

        drop(self.dir_handles.remove(op.fh() as usize));
        req.reply(())
    }

    fn do_open(&mut self, req: &Request, op: op::Open<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("open", ino = op.ino());
        let _enter = span.enter();

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

        let state = FileState {
            open_flags,
            handle: None,
        };

        let fh = self.file_handles.insert(state) as u64;
        tracing::debug!(?fh);

        let mut out = OpenOut::default();
        out.fh(fh);
        out.keep_cache(true);

        req.reply(out)
    }

    async fn do_read(&mut self, req: &Request, op: op::Read<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("read", ino = op.ino(), fh = op.fh());
        let _enter = span.enter();

        let handle = match self.ensure_open(op.ino(), op.fh()).await {
            Ok(handle) => handle,
            Err(err) => return req.reply_error(err),
        };

        let sftp = self.sftp.clone();
        let offset = op.offset();
        let size = op.size();
        let req = req.clone();
        tokio::spawn(async move {
            let _ = match sftp.read(&handle, offset, size).await {
                Ok(data) => req.reply(data),
                Err(err) => req.reply_error(sftp_error_to_errno(&err)),
            };
        });

        Ok(())
    }

    async fn do_write(
        &mut self,
        req: &Request,
        op: op::Write<'_>,
        mut data: Data<'_>,
    ) -> io::Result<()> {
        let span = tracing::debug_span!("write", ino = op.ino(), fh = op.fh());
        let _enter = span.enter();

        let handle = match self.ensure_open(op.ino(), op.fh()).await {
            Ok(handle) => handle,
            Err(err) => return req.reply_error(err),
        };

        let mut content = vec![];
        data.by_ref()
            .take(op.size() as u64)
            .read_to_end(&mut content)?;

        let sftp = self.sftp.clone();
        let offset = op.offset();
        let size = op.size();
        let req = req.clone();
        tokio::spawn(async move {
            let _ = match sftp.write(&handle, offset, &content[..]).await {
                Ok(()) => {
                    let mut out = WriteOut::default();
                    out.size(size);
                    req.reply(out)
                }
                Err(err) => req.reply_error(sftp_error_to_errno(&err)),
            };
        });

        Ok(())
    }

    async fn do_release(&mut self, req: &Request, op: op::Release<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("release", ino = op.ino());
        let _enter = span.enter();

        let state = self.file_handles.remove(op.fh() as usize);

        let sftp = self.sftp.clone();
        tokio::spawn(async move {
            if let Some(handle) = state.handle {
                if let Err(err) = sftp.close(&handle).await {
                    tracing::error!(?err);
                }
            }
        });

        req.reply(())
    }

    async fn ensure_open(
        &mut self,
        ino: u64,
        fh: u64
    ) -> Result<sftp::FileHandle, i32> {
        let span = tracing::debug_span!("ensure_open", ino = ino, fh = fh);
        let _enter = span.enter();

        let path = match self.path_table.get(ino) {
            Some(path) => path,
            None => return Err(libc::EINVAL),
        };

        let full_path = self.base_dir.join(path);
        tracing::debug!(?full_path);

        let state = match self.file_handles.get(fh as usize) {
            Some(state) => state.clone(),
            None => return Err(libc::EINVAL),
        };

        if let Some(handle) = state.handle {
            return Ok(handle);
        }

        let handle = match self
            .sftp
            .open(&full_path, state.open_flags, &Default::default())
            .await
        {
            Ok(file) => file,
            Err(err) => {
                tracing::error!("reply_err({:?})", err);
                return Err(sftp_error_to_errno(&err));
            }
        };

        self.file_handles
            .get_mut(fh as usize)
            .unwrap().handle = Some(handle.clone());

        Ok(handle)
    }
}

#[derive(Clone)]
struct FileState {
    open_flags: sftp::OpenFlag,
    handle: Option<sftp::FileHandle>,
}

struct DirHandle {
    entries: Arc<Vec<DirEntry>>,
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
    next_ino: u64,
}

struct INode {
    ino: u64,
    path: PathBuf,
    refcount: u64,
}

impl PathTable {
    fn new() -> Self {
        let mut inodes = HashMap::new();
        inodes.insert(
            1,
            INode {
                ino: 1,
                path: PathBuf::new(),
                refcount: u64::MAX / 2,
            },
        );

        let mut path_to_ino = HashMap::new();
        path_to_ino.insert(PathBuf::new(), 1);

        Self {
            inodes,
            path_to_ino,
            next_ino: 2,
        }
    }

    fn get(&self, ino: u64) -> Option<&Path> {
        self.inodes.get(&ino).map(|inode| &*inode.path)
    }

    fn recognize(&mut self, path: &Path) -> &mut INode {
        match self.path_to_ino.get(path) {
            Some(&ino) => self.inodes.get_mut(&ino).expect("inode is missing"),

            None => {
                let ino = self.next_ino;
                debug_assert!(!self.inodes.contains_key(&ino));

                let inode = self.inodes.entry(ino).or_insert_with(|| INode {
                    ino,
                    path: path.to_owned(),
                    refcount: 0,
                });

                self.path_to_ino.insert(path.to_owned(), ino);
                self.next_ino = self.next_ino.wrapping_add(1);

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
                drop(entry.remove());
            }
        }
    }
}
