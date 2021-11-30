use anyhow::Context as _;
use anyhow::Result;
use futures::future::poll_fn;
use futures::ready;
use polyfuse::KernelConfig;
use polyfuse::Request;
use polyfuse::Session;
use std::io;
use std::path::PathBuf;
use std::task::Poll;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::Sender;
use crate::Opt;
use crate::daemon::Message;

pub(crate) async fn mount(opt: &Opt, sender: Sender<Message>) -> Result<()> {
    let fuse = AsyncSession::mount(opt.mountpoint.clone(), {
        let mut config = KernelConfig::default();
        config.mount_option("fsname=sshfs");
        config.mount_option("default_permissions");
        for mount_option in opt.options.iter() {
            config.mount_option(mount_option);
        }
        if let Some(ref fusermount_path) = opt.fusermount_path {
            config.fusermount_path(fusermount_path);
        }
        // SFTP only supports 1-second time resolution.
        config.time_gran(1000000000);
        config
    })
    .await
    .context("failed to start FUSE session")?;

    while let Some(req) = fuse
        .next_request()
        .await
        .context("failed to receive FUSE request")?
    {
        sender.send(Message::Request(req)).await?;
    }

    Ok(())
}

struct AsyncSession {
    inner: AsyncFd<Session>,
}

impl AsyncSession {
    async fn mount(mountpoint: PathBuf, config: KernelConfig) -> io::Result<Self> {
        tokio::task::spawn_blocking(move || {
            let session = Session::mount(mountpoint, config)?;
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
