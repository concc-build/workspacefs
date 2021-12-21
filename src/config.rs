use anyhow::Result;
use humantime::Duration;
use serde::Deserialize;
use serde_with::serde_as;
use serde_with::DisplayFromStr;
use serde_yaml;
use std::fs::File;
use std::path::Path;
use std::path::PathBuf;

pub(crate) fn load<P: AsRef<Path>>(dir: P) -> Result<Config> {
    let path = dir.as_ref().join("netfs.yml");
    let file = File::open(&path)?;
    let config: Config = serde_yaml::from_reader(file)?;
    Ok(config)
}

#[derive(Clone, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    #[serde(default)]
    pub fuse: FuseConfig,
    pub cache: CacheConfigSet,
    pub remote: RemoteConfig,
}

#[derive(Clone, Default, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub(crate) struct FuseConfig {
    #[serde(default)]
    pub mount_options: Vec<String>,
    #[serde(default)]
    pub fusermount: Option<String>,
    #[serde(default = "FuseConfig::default_time_gran")]
    pub time_gran: u32,
}

impl FuseConfig {
    fn default_time_gran() -> u32 {
        1
    }
}

#[derive(Clone, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub(crate) struct CacheConfigSet {
    #[serde(default)]
    pub page_cache: KernelCacheConfig,
    #[serde(default)]
    pub dentry_cache: KernelCacheConfig,
    pub attr: CacheConfig,
    pub entry: CacheConfig,
    pub negative: CacheConfig,
}

#[serde_as]
#[derive(Clone, Default, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub(crate) struct KernelCacheConfig {
    #[serde(default)]
    pub excludes: Vec<String>,
}

#[serde_as]
#[derive(Clone, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub(crate) struct CacheConfig {
    #[serde_as(as = "DisplayFromStr")]
    #[serde(default = "CacheConfig::default_timeout")]
    pub timeout: Duration,
    #[serde(default)]
    pub excludes: Vec<String>,
}

impl CacheConfig {
    fn default_timeout() -> Duration {
        "0s".parse().unwrap()
    }
}

#[derive(Clone, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub(crate) enum RemoteConfig {
    Sftp(SftpConfig),
}

#[derive(Clone, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub(crate) struct SftpConfig {
    pub user: String,
    pub host: String,
    #[serde(default = "SftpConfig::default_port")]
    pub port: u16,
    #[serde(default = "SftpConfig::default_path")]
    pub path: PathBuf,
    #[serde(default = "SftpConfig::default_ssh_command")]
    pub ssh_command: String,
}

impl SftpConfig {
    fn default_port() -> u16 {
        22
    }

    fn default_path() -> PathBuf {
        PathBuf::from("/")
    }

    fn default_ssh_command() -> String {
        "ssh".to_string()
    }
}
