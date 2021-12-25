mod config;
mod daemon;
mod fs;
mod remote;
mod sftp;
mod ssh;
mod logging;

use anyhow::Context as _;
use anyhow::Result;
use std::path::PathBuf;
use structopt::StructOpt;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[derive(Debug, StructOpt)]
struct Opt {
    /// Logging in a JSON format.
    #[structopt(long, possible_values = &["text", "json"], default_value = "text")]
    log_format: String,

    /// Mount point.
    #[structopt(parse(from_os_str))]
    mountpoint: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::from_args();

    logging::init(&opt.log_format);

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

    fs::mount(&opt.mountpoint, &config.fuse, sender).await?;

    Ok(())
}
