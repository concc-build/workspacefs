use crate::sftp::Session;
use crate::sftp;
use crate::Opt;

use anyhow::{Context as _, Result};
use futures::{
    future::poll_fn,
    ready,
    task::Poll,
};
use polyfuse::{
    op,
    reply::{AttrOut, EntryOut, FileAttr, OpenOut, ReaddirOut, WriteOut},
    Data, KernelConfig, Operation, Request,
};
use slab::Slab;
use std::{
    collections::HashMap,
    ffi::OsString,
    io::{self, prelude::*},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::io::{unix::AsyncFd, Interest};

pub(crate) async fn mount(opt: Opt,  sftp: Session) -> Result<()> {
    let sftp_path = opt.remote.path();

    let fuse = AsyncSession::mount(opt.mountpoint, {
        let mut config = KernelConfig::default();
        config.mount_option("fsname=sshfs");
        config.mount_option("default_permissions");
        for mount_option in opt.options.iter() {
            config.mount_option(mount_option);
        }
        if let Some(ref fusermount_path) = opt.fusermount_path {
            config.fusermount_path(fusermount_path);
        }
        config
    })
    .await
    .context("failed to start FUSE session")?;

    let mut sshfs = SSHFS {
        sftp,
        base_dir: PathBuf::from(sftp_path),
        path_table: PathTable::new(),
        dir_handles: Slab::new(),
        file_handles: Slab::new(),
    };

    while let Some(req) = fuse
        .next_request()
        .await
        .context("failed to receive FUSE request")?
    {
        sshfs
            .handle_request(req)
            .await
            .context("failed to send FUSE reply")?;
    }

    Ok(())
}

// ==== PathTable ====

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

// ==== SSHFS ====

struct SSHFS {
    sftp: sftp::Session,
    base_dir: PathBuf,
    path_table: PathTable,
    dir_handles: Slab<DirHandle>,
    file_handles: Slab<FileState>,
}

#[derive(Clone)]
struct FileState {
    open_flags: sftp::OpenFlag,
    handle: Option<sftp::FileHandle>,
}

impl SSHFS {
    async fn handle_request(&mut self, req: Request) -> Result<()> {
        let span = tracing::debug_span!("handle_request", unique = req.unique());
        let _enter = span.enter();

        match req.operation()? {
            Operation::Lookup(op) => self.do_lookup(&req, op).await?,
            Operation::Forget(forgets) => self.do_forget(forgets.as_ref()),

            Operation::Getattr(op) => self.do_getattr(&req, op).await?,
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

        let stat = match self.sftp.lstat(&full_path).await {
            Ok(stat) => stat,
            Err(err) => return req.reply_error(sftp_error_to_errno(&err)),
        };

        tracing::debug!(?stat);

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

    async fn do_getattr(&mut self, req: &Request, op: op::Getattr<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("getattr", ino = op.ino());
        let _enter = span.enter();

        let path = match self.path_table.get(op.ino()) {
            Some(path) => path,
            None => return req.reply_error(libc::EINVAL),
        };

        let full_path = self.base_dir.join(path);
        tracing::debug!(?full_path);

        let stat = match self.sftp.lstat(&full_path).await {
            Ok(stat) => stat,
            Err(err) => return req.reply_error(sftp_error_to_errno(&err)),
        };

        let mut out = AttrOut::default();
        fill_attr(out.attr(), &stat);
        out.attr().ino(op.ino());
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

    async fn do_opendir(&mut self, req: &Request, op: op::Opendir<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("opendir", ino = op.ino());
        let _enter = span.enter();

        let dirname = match self.path_table.get(op.ino()) {
            Some(path) => path.to_owned(),
            None => return req.reply_error(libc::EINVAL),
        };

        let full_dirname = self.base_dir.join(&dirname);
        tracing::debug!(?full_dirname);

        let dir = match self.sftp.opendir(&full_dirname).await {
            Ok(dir) => dir,
            Err(err) => return req.reply_error(sftp_error_to_errno(&err)),
        };

        let entries: Vec<DirEntry> = match self.sftp.readdir(&dir).await {
            Ok(entries) => {
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

                    dst.push(DirEntry {
                        name: entry.filename,
                        ino,
                        typ,
                    });
                }
                dst
            }

            Err(sftp::Error::Remote(err)) if err.code() == sftp::SSH_FX_EOF => {
                vec![]
            }

            Err(err) => return req.reply_error(sftp_error_to_errno(&err)),
        };
        tracing::debug!(?entries);

        match self.sftp.close(&dir).await {
            Ok(()) => (),
            Err(err) => return req.reply_error(sftp_error_to_errno(&err)),
        }

        let fh = self.dir_handles.insert(DirHandle { entries, offset: 0 }) as u64;

        let mut out = OpenOut::default();
        out.fh(fh);
        out.direct_io(true);

        req.reply(out)
    }

    fn do_readdir(&mut self, req: &Request, op: op::Readdir<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("readdir", ino = op.ino());
        let _enter = span.enter();

        if op.mode() == op::ReaddirMode::Plus {
            return req.reply_error(libc::ENOSYS);
        }

        let handle = match self.dir_handles.get_mut(op.fh() as usize) {
            Some(handle) => handle,
            None => return req.reply_error(libc::EINVAL),
        };

        let mut out = ReaddirOut::new(op.size() as usize);
        for entry in handle.entries.iter().skip(op.offset() as usize) {
            if out.entry(&entry.name, entry.ino, entry.typ, handle.offset + 1) {
                break;
            }
            handle.offset += 1;
        }
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

        req.reply(out)
    }

    async fn do_read(&mut self, req: &Request, op: op::Read<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("read", ino = op.ino(), fh = op.fh());
        let _enter = span.enter();

        let handle = match self.ensure_open(op.ino(), op.fh()).await {
            Ok(handle) => handle,
            Err(err) => return req.reply_error(err),
        };

        match self.sftp.read(&handle, op.offset(), op.size()).await {
            Ok(data) => req.reply(data),
            Err(err) => req.reply_error(sftp_error_to_errno(&err)),
        }
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

        match self.sftp.write(&handle, op.offset(), &content[..]).await {
            Ok(()) => {
                let mut out = WriteOut::default();
                out.size(op.size());
                req.reply(out)
            }
            Err(err) => req.reply_error(sftp_error_to_errno(&err)),
        }
    }

    async fn do_release(&mut self, req: &Request, op: op::Release<'_>) -> io::Result<()> {
        let span = tracing::debug_span!("release", ino = op.ino());
        let _enter = span.enter();

        let state = self.file_handles.remove(op.fh() as usize);

        if let Some(handle) = state.handle {
            if let Err(err) = self.sftp.close(&handle).await {
                tracing::error!(?err);
                return req.reply_error(sftp_error_to_errno(&err));
            }
        }

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

struct DirHandle {
    entries: Vec<DirEntry>,
    offset: u64,
}

#[derive(Debug)]
struct DirEntry {
    name: OsString,
    typ: u32,
    ino: u64,
}

fn fill_attr(attr: &mut FileAttr, st: &sftp::FileAttr) {
    attr.size(st.size.unwrap_or(0));
    attr.mode(st.permissions.unwrap_or(0));
    attr.uid(st.uid().unwrap_or(0));
    attr.gid(st.gid().unwrap_or(0));
    attr.atime(Duration::from_secs(st.atime().unwrap_or(0).into()));
    attr.mtime(Duration::from_secs(st.mtime().unwrap_or(0).into()));

    attr.nlink(1);
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

// ==== AsyncSession ====

struct AsyncSession {
    inner: AsyncFd<polyfuse::Session>,
}

impl AsyncSession {
    async fn mount(mountpoint: PathBuf, config: KernelConfig) -> io::Result<Self> {
        tokio::task::spawn_blocking(move || {
            let session = polyfuse::Session::mount(mountpoint, config)?;
            Ok(Self {
                inner: AsyncFd::with_interest(session, Interest::READABLE)?,
            })
        })
        .await
        .expect("join error")
    }

    async fn next_request(&self) -> io::Result<Option<Request>> {
        poll_fn(|cx| {
            let mut guard = ready!(self.inner.poll_read_ready(cx))?;
            match guard.try_io(|inner| inner.get_ref().next_request()) {
                Err(_would_block) => Poll::Pending,
                Ok(res) => Poll::Ready(res),
            }
        })
        .await
    }
}
