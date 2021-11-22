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
    user: &str,
    host: &str,
    port: u16,
) -> Result<(Child, Stream)> {
    let mut cmd = Command::new("ssh");
    cmd.arg("-sx")
        .arg("-p")
        .arg(port.to_string())
        .arg("--")
        .arg(format!("{}@{}", user, host))
        .arg("sftp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());

    tracing::debug!("spawn {:?}", cmd);
    let mut child = cmd.spawn().context("failed to spawn ssh")?;

    let stream = Stream {
        reader: child.stdout.take().expect("missing stdout pipe"),
        writer: child.stdin.take().expect("missing stdin pipe"),
    };

    Ok((child, stream))
}
