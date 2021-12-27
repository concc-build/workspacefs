#[derive(Debug, Default)]
pub(crate) struct Stat {
    pub size: Option<u64>,
    pub atime: Option<u32>,
    pub mtime: Option<u32>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

#[derive(Debug, Default)]
pub(crate) struct Statfs {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
    pub frsize: u32,
}

#[derive(Debug, Default)]
pub(crate) struct DirEntry {
    pub kind: u32,
    pub name: String,
}
