//! A pure-Rust implementation of SFTP client independent to transport layer.

// Refs:
// * https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02
// * https://tools.ietf.org/html/rfc4251
// * https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/sftp-server.c?rev=1.120&content-type=text/x-cvsweb-markup

// Assumed that the text encoding in the remote server is UTF-8.

#![allow(dead_code)]

use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use dashmap::DashMap;
use std::borrow::Cow;
use std::fmt;
use std::io;
use std::io::IoSlice;
use std::mem;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Weak;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio::process::Child;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::process::ChildStdin;
use tokio::process::ChildStdout;
use tokio::task::JoinHandle;
use tracing::instrument;
use crate::ssh;
use crate::config::SftpConfig;

const SFTP_PROTOCOL_VERSION: u32 = 3;

// defined in https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-3
const SSH_FXP_INIT: u8 = 1;
const SSH_FXP_VERSION: u8 = 2;
const SSH_FXP_OPEN: u8 = 3;
const SSH_FXP_CLOSE: u8 = 4;
const SSH_FXP_READ: u8 = 5;
const SSH_FXP_WRITE: u8 = 6;
const SSH_FXP_LSTAT: u8 = 7;
const SSH_FXP_FSTAT: u8 = 8;
const SSH_FXP_SETSTAT: u8 = 9;
const SSH_FXP_FSETSTAT: u8 = 10;
const SSH_FXP_OPENDIR: u8 = 11;
const SSH_FXP_READDIR: u8 = 12;
const SSH_FXP_REMOVE: u8 = 13;
const SSH_FXP_MKDIR: u8 = 14;
const SSH_FXP_RMDIR: u8 = 15;
const SSH_FXP_REALPATH: u8 = 16;
const SSH_FXP_STAT: u8 = 17;
const SSH_FXP_RENAME: u8 = 18;
const SSH_FXP_READLINK: u8 = 19;
const SSH_FXP_SYMLINK: u8 = 20;
const SSH_FXP_STATUS: u8 = 101;
const SSH_FXP_HANDLE: u8 = 102;
const SSH_FXP_DATA: u8 = 103;
const SSH_FXP_NAME: u8 = 104;
const SSH_FXP_ATTRS: u8 = 105;
const SSH_FXP_EXTENDED: u8 = 200;
const SSH_FXP_EXTENDED_REPLY: u8 = 201;

// defined in https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-5
const SSH_FILEXFER_ATTR_SIZE: u32 = 0x00000001;
const SSH_FILEXFER_ATTR_UIDGID: u32 = 0x00000002;
const SSH_FILEXFER_ATTR_PERMISSIONS: u32 = 0x00000004;
const SSH_FILEXFER_ATTR_ACMODTIME: u32 = 0x00000008;
const SSH_FILEXFER_ATTR_EXTENDED: u32 = 0x80000000;

// defined in https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-6.3
const SSH_FXF_READ: u32 = 0x00000001;
const SSH_FXF_WRITE: u32 = 0x00000002;
const SSH_FXF_APPEND: u32 = 0x00000004;
const SSH_FXF_CREAT: u32 = 0x00000008;
const SSH_FXF_TRUNC: u32 = 0x00000010;
const SSH_FXF_EXCL: u32 = 0x00000020;

// defined in https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-7
pub const SSH_FX_OK: u32 = 0;
pub const SSH_FX_EOF: u32 = 1;
pub const SSH_FX_NO_SUCH_FILE: u32 = 2;
pub const SSH_FX_PERMISSION_DENIED: u32 = 3;
pub const SSH_FX_FAILURE: u32 = 4;
pub const SSH_FX_BAD_MESSAGE: u32 = 5;
pub const SSH_FX_NO_CONNECTION: u32 = 6;
pub const SSH_FX_CONNECTION_LOST: u32 = 7;
pub const SSH_FX_OP_UNSUPPORTED: u32 = 8;

const MAX_READ: usize = 65536;
const MAX_WRITE: usize = 65536;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("errored in underlying transport I/O")]
    Transport(
        #[from]
        #[source]
        io::Error,
    ),

    #[error("protocol error")]
    Protocol { msg: Cow<'static, str> },

    #[error("session has already been closed")]
    SessionClosed,

    #[error("locale error")]
    Locale(
        #[from]
        #[source]
        std::string::FromUtf8Error,
    ),
}

// described in https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-5
#[derive(Default)]
#[non_exhaustive]
pub struct FileAttr {
    pub size: Option<u64>,
    pub uid_gid: Option<(u32, u32)>,
    pub permissions: Option<u32>,
    pub ac_mod_time: Option<(u32, u32)>,
    pub extended: Vec<(String, String)>,
}

impl FileAttr {
    pub fn uid(&self) -> Option<u32> {
        self.uid_gid.map(|(uid, _)| uid)
    }

    pub fn gid(&self) -> Option<u32> {
        self.uid_gid.map(|(_, gid)| gid)
    }

    pub fn atime(&self) -> Option<u32> {
        self.ac_mod_time.map(|(atime, _)| atime)
    }

    pub fn mtime(&self) -> Option<u32> {
        self.ac_mod_time.map(|(_, mtime)| mtime)
    }

    fn count_bytes(&self) -> usize {
        let mut n = 4;
        if self.size.is_some() {
            n += 8
        }
        if self.uid_gid.is_some() {
            n += 8;
        }
        if self.permissions.is_some() {
            n += 4;
        }
        if self.ac_mod_time.is_some() {
            n += 8;
        }
        if !self.extended.is_empty() {
            n += 4;
            for (typ, data) in &self.extended {
                n += 4 + typ.as_bytes().len();
                n += 4 + data.as_bytes().len();
            }
        }
        n
    }

    fn put_bytes(&self, b: &mut BytesMut) {
        #[inline(always)]
        fn flag(b: bool, flag: u32) -> u32 {
            if b {
                flag
            } else {
                0
            }
        }

        let flags = flag(self.size.is_some(), SSH_FILEXFER_ATTR_SIZE)
            | flag(self.uid_gid.is_some(), SSH_FILEXFER_ATTR_UIDGID)
            | flag(self.permissions.is_some(), SSH_FILEXFER_ATTR_PERMISSIONS)
            | flag(self.ac_mod_time.is_some(), SSH_FILEXFER_ATTR_ACMODTIME);

        b.put_u32(flags);
        if let Some(size) = self.size {
            b.put_u64(size);
        }
        if let Some((uid, gid)) = self.uid_gid {
            b.put_u32(uid);
            b.put_u32(gid);
        }
        if let Some(perm) = self.permissions {
            b.put_u32(perm);
        }
        if let Some((atime, mtime)) = self.ac_mod_time {
            b.put_u32(atime);
            b.put_u32(mtime);
        }
        if !self.extended.is_empty() {
            b.put_u32(self.extended.len() as u32);
            for (typ, data) in &self.extended {
                b.put_u32(typ.as_bytes().len() as u32);
                b.put(typ.as_bytes());
                b.put_u32(data.as_bytes().len() as u32);
                b.put(data.as_bytes());
            }
        }
    }
}

impl fmt::Debug for FileAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "(")?;
        if let Some(size) = self.size {
            write!(f, " size={}", size)?;
        }
        if let Some((uid, gid)) = self.uid_gid {
            write!(f, " uid={} gid={}", uid, gid)?;
        }
        if let Some(permissions) = self.permissions {
            write!(f, " mode={:#o}", permissions)?;
        }
        if let Some((atime, mtime)) = self.ac_mod_time {
            write!(f, " atime={} mtime={}", atime, mtime)?;
        }
        for ext in self.extended.iter() {
            write!(f, " {:?}={:?}", ext.0, ext.1)?;
        }
        write!(f, " )")
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub struct DirEntry {
    pub filename: String,
    pub longname: String,
    pub attrs: FileAttr,
}

#[derive(Debug, Clone)]
pub struct FileHandle(Vec<u8>);

/// The handle for communicating with associated SFTP session.
#[derive(Debug, Clone)]
pub struct Session {
    base_path: PathBuf,
    inner: Weak<Inner>,
}

impl Session {
    async fn request(
        &self,
        packet_type: u8,
        payload: Vec<Bytes>,
    ) -> Result<Response, i32> {
        let inner = self.inner.upgrade().ok_or(libc::EIO)?;
        inner.send_request(packet_type, payload).await
    }

    /// Request to open a file.
    pub async fn open<P>(
        &self,
        filename: P,
        pflags: OpenFlag,
        attrs: &FileAttr,
    ) -> Result<FileHandle, i32>
    where
        P: AsRef<Path>,
    {
        let path = self.base_path.join(filename.as_ref());
        let path = path.to_str().expect("must be a UTF-8 string").as_bytes();

        let len = 8 + path.len() + attrs.count_bytes();

        let mut payload = BytesMut::with_capacity(len);
        payload.put_u32(path.len() as u32);
        payload.put(path);
        payload.put_u32(pflags.bits());
        attrs.put_bytes(&mut payload);

        match self.request(SSH_FXP_OPEN, vec![payload.freeze()]).await? {
            Response::Handle(handle) => Ok(handle),
            Response::Status { code, msg, .. } => {
                tracing::debug!(code, ?msg);
                Err(status_code_to_errno(code))
            }
            _ => {
                tracing::error!("Incorrect response type");
                Err(libc::EIO)
            }
        }
    }

    /// Request to close a file corresponding to the specified handle.
    pub async fn close(&self, handle: &FileHandle) -> Result<(), i32> {
        let len = 4 + handle.0.len();

        let mut payload = BytesMut::with_capacity(len);
        payload.put_u32(handle.0.len() as u32);
        payload.put(&handle.0[..]);

        match self.request(SSH_FXP_CLOSE, vec![payload.freeze()]).await? {
            Response::Status { code, ..} if code == SSH_FX_OK => Ok(()),
            Response::Status { code, msg, .. } => {
                tracing::debug!(code, ?msg);
                Err(status_code_to_errno(code))
            }
            _ => {
                tracing::error!("Incorrect response type");
                Err(libc::EIO)
            }
        }
    }

    /// Request to read a range of data from an opened file corresponding to the specified handle.
    #[instrument(name = "sftp.read", level = "debug", skip_all,
                 fields(handle = ?handle.0, offset, len))]
    pub async fn read(
        &self,
        handle: &FileHandle,
        offset: u64,
        len: u32,
    ) -> Result<(usize, Vec<Vec<u8>>), i32> {
        let offset = offset as usize;
        let len = len as usize;

        // Read chunks in parallel.
        let futs = (0..len).step_by(MAX_READ).map(|pos| {
            let chunk_len = if pos + MAX_READ > len {
                len - pos
            } else {
                MAX_WRITE
            };
            self.read_chunk(handle, offset + pos, chunk_len)
        });

        let mut nread = 0;
        let mut chunks = Vec::with_capacity(futs.len());
        for result in futures::future::join_all(futs).await.into_iter() {
            match result {
                Ok(chunk) => {
                    nread += chunk.len();
                    chunks.push(chunk);
                }
                Err(0) => break,  // EOF
                Err(err) => return Err(err),
            }
        }

        Ok((nread, chunks))
    }

    pub async fn read_chunk(
        &self,
        handle: &FileHandle,
        offset: usize,
        len: usize,
    ) -> Result<Vec<u8>, i32> {
        assert!(offset <= u64::MAX as usize);
        assert!(len <= u32::MAX as usize);

        tracing::debug!(offset, len, "reading a chunk...");

        let payload_len = 16 + handle.0.len();

        let mut payload = BytesMut::with_capacity(payload_len);
        payload.put_u32(handle.0.len() as u32);
        payload.put(&handle.0[..]);
        payload.put_u64(offset as u64);
        payload.put_u32(len as u32);

        match self.request(SSH_FXP_READ, vec![payload.freeze()]).await? {
            Response::Data(data) => {
                tracing::debug!(nread = data.len());
                Ok(data)
            }
            Response::Status { code, .. } if code == SSH_FX_EOF => Err(0),
            Response::Status { code, msg, .. } => {
                tracing::debug!(code, ?msg);
                Err(status_code_to_errno(code))
            }
            _ => {
                tracing::error!("Incorrect response type");
                Err(libc::EIO)
            }
        }
    }

    /// Request to write a range of data to an opened file corresponding to the specified handle.
    #[instrument(name = "sftp.write", level = "debug", skip_all,
                 fields(handle = ?handle.0, offset, len = data.len()))]
    pub async fn write(
        &self,
        handle: &FileHandle,
        offset: u64,
        data: Bytes
    ) -> Result<(), i32> {
        let size = data.len();

        // Write chunks in parallel.
        let futs = (0..data.len())
            .step_by(MAX_WRITE)
            .map(|pos| {
                let range = if pos + MAX_WRITE > size {
                    pos..size
                } else {
                    pos..(pos + MAX_WRITE)
                };
                self.write_chunk(handle, offset + pos as u64, data.slice(range))
            });

        for result in futures::future::join_all(futs).await.into_iter() {
            if result.is_err() {
                return result;
            }
        }

        Ok(())
    }

    async fn write_chunk(
        &self,
        handle: &FileHandle,
        offset: u64,
        data: Bytes
    ) -> Result<(), i32> {
        tracing::debug!(offset, len = data.len(), "writing a chunk...");

        let params_len = 16 + handle.0.len();

        let mut params = BytesMut::with_capacity(params_len);
        params.put_u32(handle.0.len() as u32);
        params.put(&handle.0[..]);
        params.put_u64(offset as u64);
        params.put_u32(data.len() as u32);

        match self.request(SSH_FXP_WRITE, vec![params.freeze(), data]).await? {
            Response::Status { code, .. } if code == SSH_FX_OK => {
                tracing::debug!("written");
                Ok(())
            }
            Response::Status { code, msg, .. } => {
                tracing::debug!(code, ?msg);
                Err(status_code_to_errno(code))
            }
            _ => {
                tracing::error!("incorrect response type");
                Err(libc::EIO)
            }
        }
    }

    /// Request to retrieve attribute values for a named file, without following symbolic links.
    #[instrument(name = "sftp.lstat", level = "debug", skip_all)]
    pub async fn lstat<P>(&self, path: P) -> Result<FileAttr, i32>
    where
        P: AsRef<Path>,
    {
        let path = self.base_path.join(path.as_ref());
        tracing::debug!(?path);
        let path = path.to_str().expect("must be a UTF-8 string").as_bytes();

        let payload_len = 4 + path.len();

        let mut payload = BytesMut::with_capacity(payload_len);
        payload.put_u32(path.len() as u32);
        payload.put(path);

        match self.request(SSH_FXP_LSTAT, vec![payload.freeze()]).await? {
            Response::Attrs(attrs) => {
                tracing::debug!("done");
                Ok(attrs)
            }
            Response::Status { code, msg, .. } => {
                tracing::debug!(code, ?msg);
                Err(status_code_to_errno(code))
            }
            _ => {
                tracing::error!("incorrect response type");
                Err(libc::EIO)
            }
        }
    }

    /// Request to retrieve attribute values for a named file.
    #[instrument(name = "sftp.fstat", level = "debug", skip_all)]
    pub async fn fstat(&self, handle: &FileHandle) -> Result<FileAttr, i32> {
        let payload_len = 4 + handle.0.len();

        let mut payload = BytesMut::with_capacity(payload_len);
        payload.put_u32(handle.0.len() as u32);
        payload.put(&handle.0[..]);

        match self.request(SSH_FXP_FSTAT, vec![payload.freeze()]).await? {
            Response::Attrs(attrs) => Ok(attrs),
            Response::Status { code, msg, .. } => {
                tracing::debug!(code, ?msg);
                Err(status_code_to_errno(code))
            }
            _ => {
                tracing::error!("incorrect response type");
                Err(libc::EIO)
            }
        }
    }

    #[instrument(name = "sftp.setstat", level = "debug", skip_all)]
    pub async fn setstat<P>(&self, path: P, attrs: &FileAttr) -> Result<(), i32>
    where
        P: AsRef<Path>,
    {
        let path = self.base_path.join(path.as_ref());
        tracing::debug!(?path);
        let path = path.to_str().expect("must be a valid Unicode").as_bytes();

        let payload_len = 4 + path.len() + attrs.count_bytes();

        let mut payload = BytesMut::with_capacity(payload_len);
        payload.put_u32(path.len() as u32);
        payload.put(path);
        attrs.put_bytes(&mut payload);

        match self.request(SSH_FXP_SETSTAT, vec![payload.freeze()]).await? {
            Response::Status { code, .. } if code == SSH_FX_OK => Ok(()),
            Response::Status { code, msg, .. } => {
                tracing::debug!(code, ?msg);
                Err(status_code_to_errno(code))
            }
            _ => {
                tracing::error!("incorrect response type");
                Err(libc::EIO)
            }
        }
    }

    #[instrument(name = "sftp.fsetstat", level = "debug", skip_all)]
    pub async fn fsetstat(&self, handle: &FileHandle, attrs: &FileAttr) -> Result<(), i32> {
        let payload_len = 4 + handle.0.len() + attrs.count_bytes();

        let mut payload = BytesMut::with_capacity(payload_len);
        payload.put_u32(handle.0.len() as u32);
        payload.put(&handle.0[..]);
        attrs.put_bytes(&mut payload);

        match self.request(SSH_FXP_FSETSTAT, vec![payload.freeze()]).await? {
            Response::Status { code, .. } if code == SSH_FX_OK => Ok(()),
            Response::Status { code, msg, .. } => {
                tracing::debug!(code, ?msg);
                Err(status_code_to_errno(code))
            }
            _ => {
                tracing::error!("incorrect response type");
                Err(libc::EIO)
            }
        }
    }

    /// Request to open a directory for reading.
    #[instrument(name = "sftp.opendir", level = "debug", skip_all)]
    pub async fn opendir<P>(&self, path: P) -> Result<FileHandle, i32>
    where
        P: AsRef<Path>,
    {
        let path = self.base_path.join(path.as_ref());
        tracing::debug!(?path);
        let path = path.to_str().expect("must be a valid Unicode").as_bytes();

        let payload_len = 4 + path.len();

        let mut payload = BytesMut::with_capacity(payload_len);
        payload.put_u32(path.len() as u32);
        payload.put(path);

        match self.request(SSH_FXP_OPENDIR, vec![payload.freeze()]).await? {
            Response::Handle(handle) => Ok(handle),
            Response::Status { code, msg, .. } => {
                tracing::debug!(code, ?msg);
                Err(status_code_to_errno(code))
            }
            _ => {
                tracing::error!("incorrect response type");
                Err(libc::EIO)
            }
        }
    }

    /// Request to list files and directories contained in an opened directory.
    #[instrument(name = "sftp.readdir", level = "debug", skip_all)]
    pub async fn readdir(&self, handle: &FileHandle) -> Result<Vec<DirEntry>, i32> {
        let payload_len = 4 + handle.0.len();

        let mut payload = BytesMut::with_capacity(payload_len);
        payload.put_u32(handle.0.len() as u32);
        payload.put(&handle.0[..]);

        match self.request(SSH_FXP_READDIR, vec![payload.freeze()]).await? {
            Response::Name(entries) => Ok(entries),
            Response::Status { code, .. } if code == SSH_FX_EOF => Err(0),
            Response::Status { code, msg, .. } => {
                tracing::debug!(code, ?msg);
                Err(status_code_to_errno(code))
            }
            _ => {
                tracing::error!("incorrect response type");
                Err(libc::EIO)
            }
        }
    }

    #[instrument(name = "sftp.remove", level = "debug", skip_all)]
    pub async fn remove<P>(&self, path: P) -> Result<(), i32>
    where
        P: AsRef<Path>,
    {
        let path = self.base_path.join(path.as_ref());
        tracing::debug!(?path);
        let path = path.to_str().expect("must be a valid Unicode").as_bytes();

        let payload_len = 4 + path.len();

        let mut payload = BytesMut::with_capacity(payload_len);
        payload.put_u32(path.len() as u32);
        payload.put(path);

        match self.request(SSH_FXP_REMOVE, vec![payload.freeze()]).await? {
            Response::Status { code, .. } if code == SSH_FX_OK => Ok(()),
            Response::Status { code, msg, .. } => {
                tracing::debug!(code, ?msg);
                Err(status_code_to_errno(code))
            }
            _ => {
                tracing::error!("incorrect response type");
                Err(libc::EIO)
            }
        }
    }

    #[instrument(name = "sftp.mkdir", level = "debug", skip_all)]
    pub async fn mkdir<P>(&self, path: P, attrs: &FileAttr) -> Result<(), i32>
    where
        P: AsRef<Path>,
    {
        let path = self.base_path.join(path.as_ref());
        tracing::debug!(?path);
        let path = path.to_str().expect("must be a valid Unicode").as_bytes();

        let payload_len = 4 + path.len() + attrs.count_bytes();

        let mut payload = BytesMut::with_capacity(payload_len);
        payload.put_u32(path.len() as u32);
        payload.put(path);
        attrs.put_bytes(&mut payload);

        match self.request(SSH_FXP_MKDIR, vec![payload.freeze()]).await? {
            Response::Status { code, .. } if code == SSH_FX_OK => Ok(()),
            Response::Status { code, msg, .. } => {
                tracing::debug!(code, ?msg);
                Err(status_code_to_errno(code))
            }
            _ => {
                tracing::error!("incorrect response type");
                Err(libc::EIO)
            }
        }
    }

    #[instrument(name = "sftp.rmdir", level = "debug", skip_all)]
    pub async fn rmdir<P>(&self, path: P) -> Result<(), i32>
    where
        P: AsRef<Path>,
    {
        let remote_path = self.make_remote_path(path.as_ref());
        tracing::debug!(?remote_path);
        let path = remote_path.to_str().expect("must be a valid Unicode").as_bytes();

        let payload_len = 4 + path.len();

        let mut payload = BytesMut::with_capacity(payload_len);
        payload.put_u32(path.len() as u32);
        payload.put(path);

        match self.request(SSH_FXP_RMDIR, vec![payload.freeze()]).await? {
            Response::Status { code, .. } if code == SSH_FX_OK => Ok(()),
            Response::Status { code, msg, .. } => {
                tracing::debug!(code, ?msg);
                Err(status_code_to_errno(code))
            }
            _ => {
                tracing::error!("incorrect response type");
                Err(libc::EIO)
            }
        }
    }

    #[instrument(name = "sftp.realpath", level = "debug", skip_all)]
    pub async fn realpath<P>(&self, path: P) -> Result<String, i32>
    where
        P: AsRef<Path>,
    {
        let remote_path = self.make_remote_path(path.as_ref());
        tracing::debug!(?remote_path);
        let path = remote_path.to_str().expect("must be a valid Unicode").as_bytes();

        let payload_len = 4 + path.len();

        let mut payload = BytesMut::with_capacity(payload_len);
        payload.put_u32(path.len() as u32);
        payload.put(path);

        match self.request(SSH_FXP_REALPATH, vec![payload.freeze()]).await? {
            Response::Name(mut entries) =>
                Ok(mem::replace(&mut entries[0].filename, "".to_string())),
            Response::Status { code, msg, .. } => {
                tracing::debug!(code, ?msg);
                Err(status_code_to_errno(code))
            }
            _ => {
                tracing::error!("incorrect response type");
                Err(libc::EIO)
            }
        }
    }

    /// Request to retrieve attribute values for a named file.
    #[instrument(name = "sftp.stat", level = "debug", skip_all)]
    pub async fn stat<P>(&self, path: P) -> Result<FileAttr, i32>
    where
        P: AsRef<Path>,
    {
        let remote_path = self.make_remote_path(path.as_ref());
        tracing::debug!(?remote_path);
        let path = remote_path.to_str().expect("must be a valid Unicode").as_bytes();

        let payload_len = 4 + path.len();

        let mut payload = BytesMut::with_capacity(payload_len);
        payload.put_u32(path.len() as u32);
        payload.put(path);

        match self.request(SSH_FXP_STAT, vec![payload.freeze()]).await? {
            Response::Attrs(attrs) => Ok(attrs),
            Response::Status { code, msg, .. } => {
                tracing::debug!(code, ?msg);
                Err(status_code_to_errno(code))
            }
            _ => {
                tracing::error!("incorrect response type");
                Err(libc::EIO)
            }
        }
    }

    #[instrument(name = "sftp.rename", level = "debug", skip_all)]
    pub async fn rename<P>(&self, old_path: P, new_path: P,) -> Result<(), i32>
    where
        P: AsRef<Path>,
    {
        const POSIX_EXTENSION_RENAME: (&'static str, &'static str) =
            ("posix-rename@openssh.com", "1");

        let (type_, additioal_len) = if self.has_extension(&POSIX_EXTENSION_RENAME) {
            (SSH_FXP_EXTENDED, 4 + POSIX_EXTENSION_RENAME.0.as_bytes().len())
        } else {
            (SSH_FXP_RENAME, 0)
        };

        let old_remote_path = self.make_remote_path(old_path.as_ref());
        let new_remote_path = self.make_remote_path(new_path.as_ref());
        tracing::debug!(?old_remote_path, ?new_remote_path);
        let old_path = old_remote_path.to_str().expect("must be a valid Unicode").as_bytes();
        let new_path = new_remote_path.to_str().expect("must be a valid Unicdoe").as_bytes();

        let payload_len = 8 + old_path.len() + new_path.len() + additioal_len;

        let mut payload = BytesMut::with_capacity(payload_len);
        if type_ == SSH_FXP_EXTENDED {
            payload.put_u32(POSIX_EXTENSION_RENAME.0.as_bytes().len() as u32);
            payload.put(POSIX_EXTENSION_RENAME.0.as_bytes());
        }
        payload.put_u32(old_path.len() as u32);
        payload.put(old_path);
        payload.put_u32(new_path.len() as u32);
        payload.put(new_path);

        match self.request(type_, vec![payload.freeze()]).await? {
            Response::Status { code, .. } if code == SSH_FX_OK => Ok(()),
            Response::Status { code, msg, .. } => {
                tracing::debug!(code, ?msg);
                Err(status_code_to_errno(code))
            }
            _ => {
                tracing::error!("incorrect response type");
                Err(libc::EIO)
            }
        }
    }

    #[instrument(name = "sftp.readlink", level = "debug", skip_all)]
    pub async fn readlink<P>(&self, path: P) -> Result<String, i32>
    where
        P: AsRef<Path>,
    {
        let remote_path = self.make_remote_path(path.as_ref());
        tracing::debug!(?remote_path);
        let path = remote_path.to_str().expect("must be a valid Unicode").as_bytes();

        let payload_len = 4 + path.len();

        let mut payload = BytesMut::with_capacity(payload_len);
        payload.put_u32(path.len() as u32);
        payload.put(path);

        match self.request(SSH_FXP_READLINK, vec![payload.freeze()]).await? {
            Response::Name(mut entries) => Ok(entries.remove(0).filename),
            Response::Status { code, msg, .. } => {
                tracing::debug!(code, ?msg);
                Err(status_code_to_errno(code))
            }
            _ => {
                tracing::error!("incorrect response type");
                Err(libc::EIO)
            }
        }
    }

    #[instrument(name = "sftp.symlink", level = "debug", skip_all)]
    pub async fn symlink<P, Q>(&self, path: P, target_path: Q) -> Result<(), i32>
    where
        P: AsRef<Path>,
        Q: AsRef<Path> + fmt::Debug,
    {
        let remote_path = self.make_remote_path(path.as_ref());
        tracing::debug!(?remote_path, ?target_path);
        let path = remote_path.to_str().expect("must be a valid Unicode").as_bytes();
        let target_path = target_path.as_ref().to_str().expect("must be a valid Unicode").as_bytes();

        let payload_len = 8 + path.len() + target_path.len();

        let reverse_symlink_arguments = self.inner
            .upgrade().ok_or(libc::EIO)?.reverse_symlink_arguments;

        let mut payload = BytesMut::with_capacity(payload_len);
        if reverse_symlink_arguments {
            payload.put_u32(target_path.len() as u32);
            payload.put(target_path);
            payload.put_u32(path.len() as u32);
            payload.put(path);
        } else {
            payload.put_u32(path.len() as u32);
            payload.put(path);
            payload.put_u32(target_path.len() as u32);
            payload.put(target_path);
        }

        match self.request(SSH_FXP_SYMLINK, vec![payload.freeze()]).await? {
            Response::Status { code, .. } if code == SSH_FX_OK => Ok(()),
            Response::Status { code, msg, .. } => {
                tracing::debug!(code, ?msg);
                Err(status_code_to_errno(code))
            }
            _ => {
                tracing::error!("incorrect response type");
                Err(libc::EIO)
            }
        }
    }

    #[instrument(name = "sftp.extended", level = "debug", skip_all)]
    pub async fn extended<R>(&self, request: &str, data: Bytes) -> Result<Vec<u8>, i32> {
        let request = request.as_bytes();

        let payload_len = 4 + request.len();

        let mut payload = BytesMut::with_capacity(payload_len);
        payload.put_u32(request.len() as u32);
        payload.put(request);

        match self.request(SSH_FXP_EXTENDED, vec![payload.freeze(), data]).await? {
            Response::Extended(data) => Ok(data.to_vec()),
            Response::Status { code, msg, .. } => {
                tracing::debug!(code, ?msg);
                Err(status_code_to_errno(code))
            }
            _ => {
                tracing::error!("incorrect response type");
                Err(libc::EIO)
            }
        }
    }

    #[inline]
    fn has_extension(&self, extension: &(&str, &str)) -> bool {
        self.inner.upgrade().unwrap().has_extension(extension)
    }

    #[inline]
    fn make_remote_path<P>(&self, path: P) -> PathBuf
    where
        P: AsRef<Path>,
    {
        self.base_path.join(path.as_ref())
    }
}

bitflags::bitflags! {
    /// Open file flags.
    #[repr(transparent)]
    pub struct OpenFlag: u32 {
        /// Open the file for reading.
        const READ = SSH_FXF_READ;

        /// Open the file for writing.
        const WRITE = SSH_FXF_WRITE;

        /// Force all writes to append data at the end of the file.
        const APPEND = SSH_FXF_APPEND;

        /// A new file will be created if one does not already exist.
        ///
        /// When [`TRUNC`](Self::TRUNC) is specified at the same time
        /// as this flag, the new file will be truncated to zero length
        /// if it previously exists.
        const CREAT = SSH_FXF_CREAT;

        /// Forces an existing file with the same name to be truncated
        /// to zero length when creating a file.
        ///
        /// This flag MUST be specified with [`CREAT`](Self::CREAT) if
        /// it is used.
        const TRUNC = SSH_FXF_TRUNC;

        /// Causes the request to fail if the named file already exists.
        ///
        /// This flag MUST be specified with [`CREAT`](Self::CREAT) if
        /// it is used.
        const EXCL = SSH_FXF_EXCL;
    }
}

// ==== session drivers ====

#[derive(Debug)]
struct Inner {
    extensions: Vec<(String, String)>,
    reverse_symlink_arguments: bool,
    incoming_requests: mpsc::UnboundedSender<Vec<Bytes>>,
    pending_requests: DashMap<u32, oneshot::Sender<Response>>,
    next_request_id: AtomicU32,
}

impl Inner {
    async fn send_request(
        &self,
        packet_type: u8,
        mut payload: Vec<Bytes>,
    ) -> Result<Response, i32> {
        // FIXME: choose appropriate atomic ordering.
        let id = self.next_request_id.fetch_add(1, Ordering::SeqCst);

        let data_len = payload.iter().fold(5, |a, v| a + v.len());
        tracing::debug!(?packet_type, ?data_len);

        let mut header = BytesMut::with_capacity(9);
        header.put_u32(data_len as u32);
        header.put_u8(packet_type);
        header.put_u32(id);

        let mut iovec = Vec::with_capacity(1 + payload.len());
        iovec.push(header.freeze());
        iovec.append(&mut payload);

        let (tx, rx) = oneshot::channel();
        // The pending request MUST be registered before sending the buffer.
        self.pending_requests.insert(id, tx);

        self.incoming_requests.send(iovec).map_err(|_| {
            tracing::error!("session is not available");
            libc::EIO
        })?;

        rx.await.map_err(|_| libc::EIO)
    }

    fn has_extension(&self, extension: &(&str, &str)) -> bool {
        self.extensions.iter().any(|ext| ext.0 == extension.0 && ext.1 == extension.1)
    }
}

#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct Connection {
    child: Child,
    inner: Arc<Inner>,
    send_task: JoinHandle<()>,
    recv_task: JoinHandle<()>,
}

/// The kind of response values received from the server.
#[derive(Debug)]
enum Response {
    /// The operation is failed.
    Status { code: u32, msg: String, lang: String },

    /// An opened file handle.
    Handle(FileHandle),

    /// Received data.
    Data(Vec<u8>),

    /// Retrieved attribute values.
    Attrs(FileAttr),

    /// Directory entries.
    Name(Vec<DirEntry>),

    /// Reply from an vendor-specific extended request.
    Extended(Vec<u8>),

    /// The response type is unknown or currently not supported.
    Unknown { typ: u8, data: Vec<u8> },
}

/// Start a SFTP session on the provided transport I/O.
///
/// This is a shortcut to `InitSession::default().init(r, w)`.
pub(crate) async fn init(config: &SftpConfig) -> Result<Session, Error> {
    let child = ssh::connect(
        &config.ssh_command, &config.user, &config.host, config.port)
        .expect("failed to establish SSH connection");
    let conn = InitSession::default().init(child).await?;
    let se = Session {
        base_path: config.path.clone(),
        inner: Arc::downgrade(&conn.inner),
    };
    Ok(se)
}

#[derive(Debug)]
struct InitSession {
    reverse_symlink_arguments: bool,
    extensions: Vec<(String, String)>,
}

impl Default for InitSession {
    fn default() -> Self {
        Self {
            reverse_symlink_arguments: true,
            extensions: vec![],
        }
    }
}

impl InitSession {
    /// Reverse the order of arguments in symlink request.
    ///
    /// For historical reason, the SFTP server implementation provied by OpenSSH
    /// (`sftp-server`) requiers that the order of arguments in the `SSH_FXP_SYMLINK`
    /// requests be the opposite of what is defined in RFC draft.
    ///
    /// This flag is enabled by default, as most SFTP servers are expected to
    /// use OpenSSH's implementation.
    pub fn reverse_symlink_arguments(&mut self, enabled: bool) -> &mut Self {
        self.reverse_symlink_arguments = enabled;
        self
    }

    pub fn extension(&mut self, name: String, data: String) -> &mut Self {
        self.extensions.push((name, data));
        self
    }

    /// Start a SFTP session on the provided transport I/O.
    ///
    /// This function first exchanges some packets with the server and negotiates
    /// the settings of SFTP protocol to use.  When the initialization process is
    /// successed, it returns a handle to send subsequent SFTP requests from the
    /// client and objects to drive the underlying communication with the server.
    async fn init(
        &self,
        mut child: Child,
    ) -> Result<Connection, Error> {
        let mut reader = child.stdout.take().expect("missing stdout pipe");
        let mut writer = child.stdin.take().expect("missing stdin pipe");

        // send SSH_FXP_INIT packet.
        {
            let packet = {
                let mut buf = BytesMut::new();
                buf.put_u8(SSH_FXP_INIT);
                buf.put_u32(SFTP_PROTOCOL_VERSION);
                for (name, data) in &self.extensions {
                    put_string(&mut buf, name.as_bytes());
                    put_string(&mut buf, data.as_bytes());
                }
                buf
            };
            let length = packet.len() as u32;
            writer.write_u32(length as u32).await?;
            writer.write_all(&packet[..]).await?;
            writer.flush().await?;
        }

        // receive SSH_FXP_VERSION packet.
        let (version, extensions) = {
            let length = reader.read_u32().await? as usize;

            let mut packet = PacketReader::new(&mut reader, length);

            let typ = packet.read_u8().await?;
            if typ != SSH_FXP_VERSION {
                return Err(Error::Protocol {
                    msg: "incorrect message type during initialization".into(),
                });
            }

            let version = packet.read_u32().await?;
            if version < SFTP_PROTOCOL_VERSION {
                return Err(Error::Protocol {
                    msg: "server supports older SFTP protocol".into(),
                });
            }

            let mut extensions = vec![];
            while packet.remaining > 0 {
                let name = packet.read_string().await?;
                let data = packet.read_string().await?;
                extensions.push((name, data));
            }

            (version, extensions)
        };
        tracing::debug!(version);
        tracing::debug!(?extensions);

        let (tx, rx) = mpsc::unbounded_channel::<Vec<Bytes>>();

        let inner = Arc::new(Inner {
            extensions,
            reverse_symlink_arguments: self.reverse_symlink_arguments,
            incoming_requests: tx,
            pending_requests: DashMap::new(),
            next_request_id: AtomicU32::new(0),
        });

        let send_task = tokio::spawn(async move {
            let _ = send_loop(writer, rx).await;
        });

        let x = inner.clone();
        let recv_task = tokio::spawn(async move {
            let _ = recv_loop(reader, x).await;
        });

        let conn = Connection {
            child,
            inner,
            send_task,
            recv_task,
        };

        Ok(conn)
    }
}

#[instrument(name = "sftp.send", level = "debug", skip_all)]
async fn send_loop(
    mut writer: ChildStdin,
    mut rx: mpsc::UnboundedReceiver<Vec<Bytes>>
) -> Result<(), Error> {
    while let Some(iovec) = rx.recv().await {
        let nwritten = if writer.is_write_vectored() {
            tracing::trace!("Sending with write_vectored...");
            let mut slices: Vec<IoSlice<'_>> = iovec
                .iter()
                .map(|buf| IoSlice::new(buf.as_ref()))
                .collect();
            writer.write_vectored(&mut slices).await?
        } else {
            tracing::trace!("Sending with write_all...");
            let mut nwritten = 0;
            for buf in iovec.into_iter() {
                nwritten += buf.len();
                writer.write_all(&buf[..]).await?;
            }
            nwritten
        };
        writer.flush().await?;
        tracing::trace!("Sent {} bytes", nwritten);
    }

    Ok(())
}

#[instrument(name = "sftp.recv", level = "debug", skip_all)]
async fn recv_loop(
    mut reader: ChildStdout,
    inner: Arc<Inner>
) -> Result<(), Error> {
    loop {
        let length = reader.read_u32().await? as usize;
        tracing::trace!(packet.length = length);
        assert!(length >= 5);

        let mut packet = PacketReader::new(&mut reader, length);
        let type_ = packet.read_u8().await?;
        let id = packet.read_u32().await?;

        let response = match type_ {
            SSH_FXP_STATUS => {
                let code = packet.read_u32().await?;
                let msg = packet.read_string().await?;
                let lang = packet.read_string().await?;
                tracing::trace!(id, r#type = "STATUS", code, ?msg, ?lang);
                Response::Status { code, msg, lang }
            }
            SSH_FXP_HANDLE => {
                let handle = packet.read_bytes().await?;
                tracing::trace!(id, r#type = "HANDLE", ?handle);
                Response::Handle(FileHandle(handle))
            }
            SSH_FXP_DATA => {
                let data = packet.read_bytes().await?;
                tracing::trace!(id, r#type = "DATA", len = data.len());
                Response::Data(data)
            }
            SSH_FXP_ATTRS => {
                let attrs = packet.read_attr().await?;
                tracing::trace!(id, r#type = "ATTRS", ?attrs);
                Response::Attrs(attrs)
            }
            SSH_FXP_NAME => {
                let count = packet.read_u32().await? as usize;
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    let filename = packet.read_string().await?;
                    let longname = packet.read_string().await?;
                    let attrs = packet.read_attr().await?;
                    entries.push(DirEntry {
                        filename,
                        longname,
                        attrs,
                    });
                }
                tracing::trace!(id, r#type = "NAME", count);
                Response::Name(entries)
            }
            SSH_FXP_EXTENDED_REPLY => {
                let data = packet.read_to_end().await?;
                tracing::trace!(id, r#type = "EXTENDED_REPLY", len = data.len());
                Response::Extended(data)
            }
            typ => {
                let data = packet.read_to_end().await?;
                tracing::trace!(id, r#type = "UNKNOWN", len = data.len());
                Response::Unknown { typ, data }
            }
        };
        if packet.remaining > 0 {
            tracing::warn!(id, r#type = type_, packet.remaining = packet.remaining);
            let _ = packet.read_to_end().await?;
        }

        if let Some((_id, tx)) = inner.pending_requests.remove(&id) {
            let _ = tx.send(response);
        }
    }
}

struct PacketReader<'a, R> {
    inner: &'a mut R,
    remaining: usize,
}

impl<'a, R> PacketReader<'a, R>
where
    R: AsyncReadExt + Unpin,
{
    #[inline]
    fn new(inner: &'a mut R, remaining: usize) -> Self {
        Self {
            inner,
            remaining,
        }
    }

    async fn read_attr(&mut self) -> Result<FileAttr, Error> {
        let flags = self.read_u32().await?;

        let size = if flags & SSH_FILEXFER_ATTR_SIZE != 0 {
            let size = self.read_u64().await?;
            Some(size)
        } else {
            None
        };

        let uid_gid = if flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
            let uid = self.read_u32().await?;
            let gid = self.read_u32().await?;
            Some((uid, gid))
        } else {
            None
        };

        let permissions = if flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
            let perm = self.read_u32().await?;
            Some(perm)
        } else {
            None
        };

        let ac_mod_time = if flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 {
            let atime = self.read_u32().await?;
            let mtime = self.read_u32().await?;
            Some((atime, mtime))
        } else {
            None
        };

        let mut extended = vec![];

        if flags & SSH_FILEXFER_ATTR_EXTENDED != 0 {
            let count = self.read_u32().await? as usize;
            for _ in 0..count {
                let ex_type = self.read_string().await?;
                let ex_data = self.read_string().await?;
                extended.push((ex_type, ex_data));
            }
        }

        Ok(FileAttr {
            size,
            uid_gid,
            permissions,
            ac_mod_time,
            extended,
        })
    }

    #[inline]
    async fn read_to_end(&mut self) -> Result<Vec<u8>, Error> {
        self.read_exact(self.remaining).await
    }

    #[inline]
    async fn read_bytes(&mut self) -> Result<Vec<u8>, Error> {
        let len = self.read_u32().await? as usize;
        self.read_exact(len).await
    }

    #[inline]
    async fn read_string(&mut self) -> Result<String, Error> {
        let v = self.read_bytes().await?;
        Ok(String::from_utf8(v)?)
    }

    #[inline]
    async fn read_u8(&mut self) -> Result<u8, Error> {
        const N: usize = mem::size_of::<u8>();
        self.ensure(N)?;
        let v = self.inner.read_u8().await?;
        self.remaining -= N;
        Ok(v)
    }

    #[inline]
    async fn read_u32(&mut self) -> Result<u32, Error> {
        const N: usize = mem::size_of::<u32>();
        self.ensure(N)?;
        let v = self.inner.read_u32().await?;
        self.remaining -= N;
        Ok(v)
    }

    #[inline]
    async fn read_u64(&mut self) -> Result<u64, Error> {
        const N: usize = mem::size_of::<u64>();
        self.ensure(N)?;
        let v = self.inner.read_u64().await?;
        self.remaining -= N;
        Ok(v)
    }

    #[inline]
    async fn read_exact(&mut self, n: usize) -> Result<Vec<u8>, Error> {
        self.ensure(n)?;
        let mut v = Vec::with_capacity(n);
        unsafe {
            v.set_len(n);
        }
        self.inner.read_exact(&mut v[..]).await?;
        self.remaining -= n;
        Ok(v)
    }

    #[inline]
    fn ensure(&self, n: usize) -> Result<(), Error> {
        if self.remaining >= n {
            Ok(())
        } else {
            Err(Error::Protocol {
                msg: "too short data".into(),
            })
        }
    }
}

// ==== misc ====

#[inline]
fn put_string(b: &mut BytesMut, s: &[u8]) {
    b.put_u32(s.len() as u32);
    b.put(s);
}

fn status_code_to_errno(code: u32) -> i32 {
    match code {
        SSH_FX_OK => 0,
        SSH_FX_NO_SUCH_FILE => libc::ENOENT,
        SSH_FX_PERMISSION_DENIED => libc::EPERM,
        SSH_FX_OP_UNSUPPORTED => libc::ENOTSUP,
        _ => libc::EIO,
    }
}
