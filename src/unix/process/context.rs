use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ProcessContext {
    pub exe: PathBuf,
    pub pid: u32,
    pub original_uid: u32,
    pub original_gid: u32,
    pub sid: u32,
    pub ttyno: u32,
}
