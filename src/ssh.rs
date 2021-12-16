use anyhow::Result;
use anyhow::Context as _;
use std::io;
use std::io::IoSlice;
use std::pin::Pin;
use std::process::Stdio;
use std::task::Poll;
use std::task::Context;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;
use tokio::process::Command;
use tokio::process::Child;
use tokio::process::ChildStdin;
use tokio::process::ChildStdout;
use tracing;

pub(crate) struct Stream {
    reader: ChildStdout,
    writer: ChildStdin,
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write_vectored(cx, bufs)
    }
}

pub(crate) fn connect(
    command: &str,
    user: &str,
    host: &str,
    port: u16,
) -> Result<Child> {
    let words = shell_words::split(command)?;
    let (prog, args) = words.split_first().unwrap();
    let extra = format!("-sx -p {} -- {}@{} sftp", port, user, host);
    let extra_args = shell_words::split(&extra)?;
    let mut cmd = Command::new(&prog);
    cmd.args(args).args(extra_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());

    tracing::debug!("spawn `<ssh-command> {}`", extra);
    Ok(cmd.spawn().context("failed to spawn ssh")?)
}
