use anyhow::Context as _;
use anyhow::Result;
use futures::future::poll_fn;
use futures::ready;
use polyfuse::KernelConfig;
use polyfuse::Request;
use polyfuse::Session;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::task::Poll;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::Sender;
use crate::config::MountConfig;
use crate::daemon::Message;

pub(crate) async fn mount<P>(
    mountpoint: P,
    config: &MountConfig,
    sender: Sender<Message>
) -> Result<()>
where
    P: AsRef<Path>,
{
    let fuse = AsyncSession::mount(mountpoint.as_ref().to_owned(), {
        let mut kconfig = KernelConfig::default();
        kconfig.mount_option("fsname=sshfs");
        for mount_option in config.options.iter() {
            kconfig.mount_option(mount_option);
        }
        if let Some(ref fusermount) = config.fusermount {
            kconfig.fusermount_path(fusermount);
        }
        // SFTP only supports 1-second time resolution.
        kconfig.time_gran(1000000000);
        kconfig
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
