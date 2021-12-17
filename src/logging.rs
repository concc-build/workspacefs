use atty;
use tracing_subscriber;
use tracing_subscriber::filter::EnvFilter;

pub(crate) fn init(format: &str) {
    match format {
        "text" => init_text(),
        "json" => init_json(),
        _ => unreachable!(),
    }
}

fn init_text() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(atty::is(atty::Stream::Stderr))
        .with_env_filter(EnvFilter::from_default_env())
        .init();
}

fn init_json() {
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_ansi(atty::is(atty::Stream::Stderr))
        .with_env_filter(EnvFilter::from_default_env())
        .init();
}
