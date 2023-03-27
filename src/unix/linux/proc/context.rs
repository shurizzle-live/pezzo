use std::io;

use super::super::super::{
    process::{Group, User},
    IAMContext, ProcessContext,
};
use super::stat::Stat;

impl ProcessContext {
    pub fn current(iam: &IAMContext) -> io::Result<Self> {
        let exe = std::env::current_exe()?;
        let proc_stat = Stat::current()?;
        let pid: u32 = proc_stat.pid;
        let sid: u32 = proc_stat.session;
        let ttyno: u32 = proc_stat.tty_nr;
        let uid: u32 = unsafe { libc::getuid() };
        let gid: u32 = unsafe { libc::getgid() };

        let user_name = if let Some(user_name) = iam.user_name_by_id(uid)? {
            user_name
        } else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "invalid user"));
        };

        let group_name = if let Some(group_name) = iam.group_name_by_id(uid)? {
            group_name
        } else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "invalid group"));
        };

        let original_user = User {
            name: user_name,
            id: uid,
        };

        let original_group = Group {
            name: group_name,
            id: gid,
        };

        Ok(Self {
            exe,
            pid,
            original_user,
            original_group,
            sid,
            ttyno,
        })
    }
}
