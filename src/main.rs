mod config;
mod daemon;
mod fs;
mod sftp;
mod ssh;

use anyhow::Context as _;
use anyhow::Result;
use std::path::PathBuf;
use structopt::StructOpt;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[derive(Debug, StructOpt)]
struct Opt {
    /// Mount point.
    #[structopt(parse(from_os_str))]
    mountpoint: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(atty::is(atty::Stream::Stderr))
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let opt = Opt::from_args();
    let config = config::load(&opt.mountpoint)?;

    let remote = match config.remote {
        config::RemoteConfig::Sftp(ref config) => {
            sftp::init(config).await.context("failed to initialize SFTP session")?
        }
    };

    // let stat = sftp
    //     .lstat(&args.base_dir)
    //     .await
    //     .context("failed to get target attribute")?;
    // ensure!(stat.is_dir(), "the target path is not directory");

    let (sender, daemon) = daemon::init(&config, remote)?;
    tokio::spawn(async move {
        let _ = daemon.run().await;
    });

    fs::mount(&opt.mountpoint, &config.mount, sender).await?;

    Ok(())
}
