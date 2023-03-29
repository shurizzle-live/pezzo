use std::{ffi::CStr, io, ptr};

use super::super::super::{
    process::{Group, User},
    IAMContext, ProcessContext,
};
use super::stat::Stat;

pub fn get_groups() -> io::Result<Vec<u32>> {
    unsafe {
        let len = libc::getgroups(0, ptr::null_mut());
        if len == -1 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = Vec::with_capacity(len as usize);
        let len = libc::getgroups(len, buf.as_mut_ptr());
        if len == -1 {
            return Err(io::Error::last_os_error());
        }
        buf.set_len(len as usize);
        println!("{:?}", buf);

        Ok(buf)
    }
}

impl ProcessContext {
    pub fn current(iam: &IAMContext) -> io::Result<Self> {
        let uid: u32 = unsafe { libc::getuid() };
        let gid: u32 = unsafe { libc::getgid() };

        iam.set_effective_identity(uid, gid)?;

        let exe = std::env::current_exe()?;
        let proc_stat = Stat::current()?;
        let pid: u32 = proc_stat.pid;
        let sid: u32 = proc_stat.session;
        let ttyno: u32 = proc_stat.tty_nr;

        let user_name = if let Some(user_name) = iam.user_name_by_id(uid)? {
            user_name
        } else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "invalid user"));
        };

        let group_name = if let Some(group_name) = iam.group_name_by_id(gid)? {
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

        let original_groups = iam.get_groups(original_user.name().to_bytes())?;

        Ok(Self {
            exe,
            pid,
            original_user,
            original_group,
            original_groups,
            sid,
            ttyno,
        })
    }
}
