#[derive(Debug)]
pub(crate) struct Statfs {
    pub bsize: u32,
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub namelen: u32,
    pub frsize: u32,
}
