use std::io;

use super::stat::Stat;
use crate::unix::ProcessContext;

impl ProcessContext {
    pub fn current() -> io::Result<Self> {
        let exe = std::env::current_exe()?;
        let proc_stat = Stat::current()?;
        let pid: u32 = proc_stat.pid;
        let sid: u32 = proc_stat.session;
        let ttyno: u32 = proc_stat.tty_nr;
        let original_uid: u32 = unsafe { libc::getuid() };
        let original_gid: u32 = unsafe { libc::getgid() };

        Ok(Self {
            exe,
            pid,
            original_uid,
            original_gid,
            sid,
            ttyno,
        })
    }
}
