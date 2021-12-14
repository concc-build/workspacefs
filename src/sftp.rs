//! A pure-Rust implementation of SFTP client independent to transport layer.

// Refs:
// * https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02
// * https://tools.ietf.org/html/rfc4251
// * https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/sftp-server.c?rev=1.120&content-type=text/x-cvsweb-markup

// Assumed that the text encoding in the remote server is UTF-8.

#![allow(dead_code)]

use bytes::Buf;
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

    #[error("from remote: {}", _0)]
    Remote(#[source] RemoteError),

    #[error("session has already been closed")]
    SessionClosed,

    #[error("locale error")]
    Locale(
        #[from]
        #[source]
        std::string::FromUtf8Error,
    ),
}

#[derive(Debug, thiserror::Error)]
#[error("from remote server")]
pub struct RemoteError(RemoteStatus);

impl RemoteError {
    pub fn code(&self) -> u32 {
        self.0.code
    }

    pub fn message(&self) -> &str {
        &self.0.message
    }

    pub fn language_tag(&self) -> &str {
        &self.0.language_tag
    }
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
pub struct FileHandle(Bytes);

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
    ) -> Result<Response, Error> {
        let inner = self.inner.upgrade().ok_or(Error::SessionClosed)?;
        inner.send_request(packet_type, payload).await
    }

    /// Request to open a file.
    pub async fn open<P>(
        &self,
        filename: P,
        pflags: OpenFlag,
        attrs: &FileAttr,
    ) -> Result<FileHandle, Error>
    where
        P: AsRef<Path>,
    {
        let path = self.base_path.join(filename.as_ref());
        let path = path.to_str().expect("").as_bytes();

        let len = 8 + path.len() + attrs.count_bytes();

        let mut payload = BytesMut::with_capacity(len);
        payload.put_u32(path.len() as u32);
        payload.put(path);
        payload.put_u32(pflags.bits());
        attrs.put_bytes(&mut payload);

        match self.request(SSH_FXP_OPEN, vec![payload.freeze()]).await? {
            Response::Handle(handle) => Ok(handle),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to close a file corresponding to the specified handle.
    pub async fn close(&self, handle: &FileHandle) -> Result<(), Error> {
        let len = 4 + handle.0.len();

        let mut payload = BytesMut::with_capacity(len);
        payload.put_u32(handle.0.len() as u32);
        payload.put(&handle.0[..]);

        match self.request(SSH_FXP_CLOSE, vec![payload.freeze()]).await? {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
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
    ) -> Result<(usize, Vec<Bytes>), Error> {
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
                Err(Error::Remote(err)) if err.code() == SSH_FX_EOF => {
                    break
                }
                Err(err) => {
                    return Err(err);
                }
            }
        }

        Ok((nread, chunks))
    }

    pub async fn read_chunk(
        &self,
        handle: &FileHandle,
        offset: usize,
        len: usize,
    ) -> Result<Bytes, Error> {
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
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
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
    ) -> Result<(), Error> {
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
    ) -> Result<(), Error> {
        tracing::debug!(offset, len = data.len(), "writing a chunk...");

        let params_len = 16 + handle.0.len();

        let mut params = BytesMut::with_capacity(params_len);
        params.put_u32(handle.0.len() as u32);
        params.put(&handle.0[..]);
        params.put_u64(offset as u64);
        params.put_u32(data.len() as u32);

        match self.request(SSH_FXP_WRITE, vec![params.freeze(), data]).await? {
            Response::Status(st) if st.code == SSH_FX_OK => {
                tracing::debug!("written");
                Ok(())
            }
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to retrieve attribute values for a named file, without following symbolic links.
    #[instrument(name = "sftp.lstat", level = "debug", skip_all)]
    pub async fn lstat<P>(&self, path: P) -> Result<FileAttr, Error>
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
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to retrieve attribute values for a named file.
    #[instrument(name = "sftp.fstat", level = "debug", skip_all)]
    pub async fn fstat(&self, handle: &FileHandle) -> Result<FileAttr, Error> {
        let payload_len = 4 + handle.0.len();

        let mut payload = BytesMut::with_capacity(payload_len);
        payload.put_u32(handle.0.len() as u32);
        payload.put(&handle.0[..]);

        match self.request(SSH_FXP_FSTAT, vec![payload.freeze()]).await? {
            Response::Attrs(attrs) => Ok(attrs),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    #[instrument(name = "sftp.setstat", level = "debug", skip_all)]
    pub async fn setstat<P>(&self, path: P, attrs: &FileAttr) -> Result<(), Error>
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
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    #[instrument(name = "sftp.fsetstat", level = "debug", skip_all)]
    pub async fn fsetstat(&self, handle: &FileHandle, attrs: &FileAttr) -> Result<(), Error> {
        let payload_len = 4 + handle.0.len() + attrs.count_bytes();

        let mut payload = BytesMut::with_capacity(payload_len);
        payload.put_u32(handle.0.len() as u32);
        payload.put(&handle.0[..]);
        attrs.put_bytes(&mut payload);

        match self.request(SSH_FXP_FSETSTAT, vec![payload.freeze()]).await? {
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to open a directory for reading.
    #[instrument(name = "sftp.opendir", level = "debug", skip_all)]
    pub async fn opendir<P>(&self, path: P) -> Result<FileHandle, Error>
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
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to list files and directories contained in an opened directory.
    #[instrument(name = "sftp.readdir", level = "debug", skip_all)]
    pub async fn readdir(&self, handle: &FileHandle) -> Result<Vec<DirEntry>, Error> {
        let payload_len = 4 + handle.0.len();

        let mut payload = BytesMut::with_capacity(payload_len);
        payload.put_u32(handle.0.len() as u32);
        payload.put(&handle.0[..]);

        match self.request(SSH_FXP_READDIR, vec![payload.freeze()]).await? {
            Response::Name(entries) => Ok(entries),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    #[instrument(name = "sftp.remove", level = "debug", skip_all)]
    pub async fn remove<P>(&self, path: P) -> Result<(), Error>
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
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    #[instrument(name = "sftp.mkdir", level = "debug", skip_all)]
    pub async fn mkdir<P>(&self, path: P, attrs: &FileAttr) -> Result<(), Error>
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
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    #[instrument(name = "sftp.rmdir", level = "debug", skip_all)]
    pub async fn rmdir<P>(&self, path: P) -> Result<(), Error>
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
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    #[instrument(name = "sftp.realpath", level = "debug", skip_all)]
    pub async fn realpath<P>(&self, path: P) -> Result<String, Error>
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
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    /// Request to retrieve attribute values for a named file.
    #[instrument(name = "sftp.stat", level = "debug", skip_all)]
    pub async fn stat<P>(&self, path: P) -> Result<FileAttr, Error>
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
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    #[instrument(name = "sftp.rename", level = "debug", skip_all)]
    pub async fn rename<P>(&self, old_path: P, new_path: P,) -> Result<(), Error>
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
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    #[instrument(name = "sftp.readlink", level = "debug", skip_all)]
    pub async fn readlink<P>(&self, path: P) -> Result<String, Error>
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
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    #[instrument(name = "sftp.symlink", level = "debug", skip_all)]
    pub async fn symlink<P, Q>(&self, path: P, target_path: Q) -> Result<(), Error>
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
            .upgrade().ok_or(Error::SessionClosed)?.reverse_symlink_arguments;

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
            Response::Status(st) if st.code == SSH_FX_OK => Ok(()),
            Response::Status(st) => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
        }
    }

    #[instrument(name = "sftp.extended", level = "debug", skip_all)]
    pub async fn extended<R>(&self, request: &str, data: Bytes) -> Result<Vec<u8>, Error> {
        let request = request.as_bytes();

        let payload_len = 4 + request.len();

        let mut payload = BytesMut::with_capacity(payload_len);
        payload.put_u32(request.len() as u32);
        payload.put(request);

        match self.request(SSH_FXP_EXTENDED, vec![payload.freeze(), data]).await? {
            Response::Extended(data) => Ok(data.to_vec()),
            Response::Status(st) if st.code != SSH_FX_OK => Err(Error::Remote(RemoteError(st))),
            _ => Err(Error::Protocol {
                msg: "incorrect response type".into(),
            }),
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
    ) -> Result<Response, Error> {
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
            io::Error::new(io::ErrorKind::ConnectionAborted, "session is not available")
        })?;

        rx.await.map_err(|_| Error::SessionClosed)
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
    Status(RemoteStatus),

    /// An opened file handle.
    Handle(FileHandle),

    /// Received data.
    Data(Bytes),

    /// Retrieved attribute values.
    Attrs(FileAttr),

    /// Directory entries.
    Name(Vec<DirEntry>),

    /// Reply from an vendor-specific extended request.
    Extended(Bytes),

    /// The response type is unknown or currently not supported.
    Unknown { typ: u8, data: Bytes },
}

#[derive(Debug)]
struct RemoteStatus {
    code: u32,
    message: String,
    language_tag: String,
}

/// Start a SFTP session on the provided transport I/O.
///
/// This is a shortcut to `InitSession::default().init(r, w)`.
pub async fn init<P>(
    ssh_command: &str,
    user: &str,
    host: &str,
    port: u16,
    path: P,
) -> Result<Session, Error>
where
    P: AsRef<Path>,
{
    let child = ssh::connect(ssh_command, user, host, port)
        .expect("failed to establish SSH connection");
    let conn = InitSession::default().init(child).await?;
    let se = Session {
        base_path: path.as_ref().to_owned(),
        inner: Arc::downgrade(&conn.inner),
    };
    Ok(se)
}

#[derive(Debug)]
pub struct InitSession {
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
        writer.write_all(&length.to_be_bytes()).await?;
        writer.write_all(&packet[..]).await?;
        writer.flush().await?;

        // receive SSH_FXP_VERSION packet.
        let length = {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf[..]).await?;
            u32::from_be_bytes(buf)
        };

        let mut packet = {
            let mut buf = BytesMut::with_capacity(length as usize);
            reader.read_buf(&mut buf).await?;
            buf.freeze()
        };

        let typ = read_u8(&mut packet)?;
        if typ != SSH_FXP_VERSION {
            return Err(Error::Protocol {
                msg: "incorrect message type during initialization".into(),
            });
        }

        let version = read_u32(&mut packet)?;
        if version < SFTP_PROTOCOL_VERSION {
            return Err(Error::Protocol {
                msg: "server supports older SFTP protocol".into(),
            });
        }

        let mut extensions = vec![];
        while !packet.is_empty() {
            let name = read_string(&mut packet)?;
            let data = read_string(&mut packet)?;
            extensions.push((name, data));
        }

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
            tracing::debug!("Sending with write_vectored...");
            let mut slices: Vec<IoSlice<'_>> = iovec
                .iter()
                .map(|buf| IoSlice::new(buf.as_ref()))
                .collect();
            writer.write_vectored(&mut slices).await?
        } else {
            tracing::debug!("Sending with write_all...");
            let mut nwritten = 0;
            for buf in iovec.into_iter() {
                nwritten += buf.len();
                writer.write_all(&buf[..]).await?;
            }
            nwritten
        };
        writer.flush().await?;
        tracing::debug!("Sent {} bytes", nwritten);
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
        tracing::trace!(length);

        let mut buf = BytesMut::with_capacity(length);
        unsafe {
            buf.set_len(length);
        }

        reader.read_exact(&mut buf[..]).await?;

        let mut packet = buf.freeze();
        let type_ = read_u8(&mut packet)?;
        let id = read_u32(&mut packet)?;
        let response = match type_ {
            SSH_FXP_STATUS => {
                let code = read_u32(&mut packet)?;
                let message = read_string(&mut packet)?;
                let language_tag = read_string(&mut packet)?;
                tracing::trace!(id, r#type = "STATUS", code, ?message, ?language_tag);
                Response::Status(RemoteStatus {
                    code,
                    message,
                    language_tag,
                })
            }
            SSH_FXP_HANDLE => {
                let handle = read_bytes(&mut packet)?;
                tracing::trace!(id, r#type = "HANDLE", ?handle);
                Response::Handle(FileHandle(handle))
            }
            SSH_FXP_DATA => {
                let data = read_bytes(&mut packet)?;
                tracing::trace!(id, r#type = "DATA", len = data.len());
                Response::Data(data)
            }
            SSH_FXP_ATTRS => {
                let attrs = read_file_attr(&mut packet)?;
                tracing::trace!(id, r#type = "ATTRS", ?attrs);
                Response::Attrs(attrs)
            }
            SSH_FXP_NAME => {
                let count = read_u32(&mut packet)?;
                let mut entries = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    let filename = read_string(&mut packet)?;
                    let longname = read_string(&mut packet)?;
                    let attrs = read_file_attr(&mut packet)?;
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
                let data = packet.split_to(packet.len());
                tracing::trace!(id, r#type = "EXTENDED_REPLY", len = data.len());
                Response::Extended(data)
            }
            typ => {
                let data = packet.split_to(packet.len());
                tracing::trace!(id, r#type = "UNKNOWN", len = data.len());
                Response::Unknown { typ, data }
            }
        };
        if !packet.is_empty() {
            tracing::warn!(id, r#type = type_, packet.remaining = packet.remaining());
        }

        if let Some((_id, tx)) = inner.pending_requests.remove(&id) {
            let _ = tx.send(response);
        }
    }
}

// ==== misc ====

#[inline]
fn put_string(b: &mut BytesMut, s: &[u8]) {
    b.put_u32(s.len() as u32);
    b.put(s);
}

#[inline]
fn ensure_buf_remaining(b: &Bytes, n: usize) -> Result<(), Error> {
    if b.remaining() >= n {
        Ok(())
    } else {
        Err(Error::Protocol {
            msg: "too short data".into(),
        })
    }
}

#[inline]
fn read_u8(b: &mut Bytes) -> Result<u8, Error> {
    ensure_buf_remaining(b, mem::size_of::<u8>())?;
    Ok(b.get_u8())
}

#[inline]
fn read_u32(b: &mut Bytes) -> Result<u32, Error> {
    ensure_buf_remaining(b, mem::size_of::<u32>())?;
    Ok(b.get_u32())
}

#[inline]
fn read_u64(b: &mut Bytes) -> Result<u64, Error> {
    ensure_buf_remaining(b, mem::size_of::<u64>())?;
    Ok(b.get_u64())
}

#[inline]
fn read_bytes(b: &mut Bytes) -> Result<Bytes, Error> {
    let len = read_u32(b)? as usize;
    ensure_buf_remaining(b, len)?;
    Ok(b.split_to(len))
}

#[inline]
fn read_string(b: &mut Bytes) -> Result<String, Error> {
    let bytes = read_bytes(b)?;
    Ok(String::from_utf8(bytes.as_ref().to_vec())?)
}

fn read_file_attr(b: &mut Bytes) -> Result<FileAttr, Error> {
    let flags = read_u32(b)?;

    let size = if flags & SSH_FILEXFER_ATTR_SIZE != 0 {
        let size = read_u64(b)?;
        Some(size)
    } else {
        None
    };

    let uid_gid = if flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
        let uid = read_u32(b)?;
        let gid = read_u32(b)?;
        Some((uid, gid))
    } else {
        None
    };

    let permissions = if flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
        let perm = read_u32(b)?;
        Some(perm)
    } else {
        None
    };

    let ac_mod_time = if flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 {
        let atime = read_u32(b)?;
        let mtime = read_u32(b)?;
        Some((atime, mtime))
    } else {
        None
    };

    let mut extended = vec![];

    if flags & SSH_FILEXFER_ATTR_EXTENDED != 0 {
        let count = read_u32(b)?;
        for _ in 0..count {
            let ex_type = read_string(b)?;
            let ex_data = read_string(b)?;
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
