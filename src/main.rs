mod daemon;
mod fs;
mod sftp;
mod ssh;

use anyhow::{ensure, Context as _, Result};
use std::path::PathBuf;
use structopt::StructOpt;
use tracing::Instrument as _;
use url::Url;

#[derive(Debug, StructOpt)]
struct Opt {
    /// FUSE options.
    #[structopt(short, number_of_values = 1)]
    options: Vec<String>,

    /// SSH command to be executed for establishing a connection.
    ///
    /// Additional SSH options will be added after the command string.
    #[structopt(long, default_value = "ssh")]
    ssh_command: String,

    /// Absolute path to fusermount or fusermount3.
    #[structopt(long, parse(from_os_str))]
    fusermount_path: Option<PathBuf>,

    /// URL of the target directory on the remote host like sftp://user@remote/path/to/dir.
    #[structopt(parse(try_from_str = Url::parse))]
    remote: Url,

    /// Mount point.
    #[structopt(parse(from_os_str))]
    mountpoint: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let opt = Opt::from_args();

    ensure!(opt.remote.scheme() == "sftp", "remote url must be a sftp URL");
    ensure!(!opt.remote.username().is_empty(), "remote url must has an username part");
    ensure!(opt.remote.has_host(), "remote url must has a host part");
    ensure!(opt.mountpoint.is_dir(), "mountpoint must be a directory");

    let sftp_user = opt.remote.username();
    let sftp_host = opt.remote.host_str().unwrap();
    let sftp_port = opt.remote.port().unwrap_or(22);

    let (mut child, stream) = ssh::connect(
        &opt.ssh_command, sftp_user, sftp_host, sftp_port)
        .context("failed to establish SSH connection")?;

    let (sftp, conn) = sftp::init(stream)
        .await
        .context("failed to initialize SFTP session")?;
    tokio::spawn(conn.instrument(tracing::debug_span!("sftp_connection")));

    // let stat = sftp
    //     .lstat(&args.base_dir)
    //     .await
    //     .context("failed to get target attribute")?;
    // ensure!(stat.is_dir(), "the target path is not directory");

    let (sender, daemon) = daemon::init(&opt, sftp);
    tokio::spawn(async move {
        let _ = daemon.run().await;
    });

    fs::mount(&opt, sender).await?;

    child.kill().await.context("failed to send kill")?;
    child.wait().await?;

    Ok(())
}
