mod daemon;
mod fs;
mod sftp;
mod ssh;

use anyhow::{ensure, Context as _, Result};
use humantime::parse_duration;
use std::path::PathBuf;
use std::time::Duration;
use structopt::StructOpt;
use url::Url;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[derive(Debug, StructOpt)]
struct Opt {
    /// FUSE mount options.
    #[structopt(short, number_of_values = 1)]
    options: Vec<String>,

    /// Cache timeout for directory entries.
    ///
    /// A value is represented with a concatenation of time spans.  Where each
    /// time span is an integer number and a suffix.  Supported suffixes:
    ///
    ///   * nsec, ns -- nanoseconds
    ///   * usec, us -- microseconds
    ///   * msec, ms -- milliseconds
    ///   * seconds, second, sec, s
    ///   * minutes, minute, min, m
    ///   * hours, hour, hr, h
    ///   * days, day, d
    ///   * weeks, week, w
    ///   * months, month, M -- defined as 30.44 days
    ///   * years, year, y -- defined as 365.25 days
    ///
    /// "0<suffix>" means that caching is disabled.
    #[structopt(
        short = "E",
        long,
        default_value = "0s",
        parse(try_from_str = parse_duration),
        verbatim_doc_comment)]
    entry_timeout: Duration,

    /// Cache timeout for file attributes.
    #[structopt(
        short = "A",
        long,
        default_value = "0s",
        parse(try_from_str = parse_duration),
        verbatim_doc_comment)]
    attr_timeout: Duration,

    /// Cache timeout for negative lookups.
    #[structopt(
        short = "N",
        long,
        default_value = "0s",
        parse(try_from_str = parse_duration),
        verbatim_doc_comment)]
    negative_timeout: Duration,

    /// Glob patterns of paths excluded from negative lookup caching.
    #[structopt(short = "X", long, number_of_values = 1)]
    negative_xglobs: Vec<String>,

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
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(atty::is(atty::Stream::Stderr))
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let opt = Opt::from_args();

    ensure!(opt.remote.scheme() == "sftp", "remote url must be a sftp URL");
    ensure!(!opt.remote.username().is_empty(), "remote url must has an username part");
    ensure!(opt.remote.has_host(), "remote url must has a host part");
    ensure!(opt.mountpoint.is_dir(), "mountpoint must be a directory");

    let sftp_user = opt.remote.username();
    let sftp_host = opt.remote.host_str().unwrap();
    let sftp_port = opt.remote.port().unwrap_or(22);

    let sftp = sftp::init(
        &opt.ssh_command, sftp_user, sftp_host, sftp_port)
        .await
        .context("failed to initialize SFTP session")?;

    // let stat = sftp
    //     .lstat(&args.base_dir)
    //     .await
    //     .context("failed to get target attribute")?;
    // ensure!(stat.is_dir(), "the target path is not directory");

    let (sender, daemon) = daemon::init(&opt, sftp)?;
    tokio::spawn(async move {
        let _ = daemon.run().await;
    });

    fs::mount(&opt, sender).await?;

    Ok(())
}
