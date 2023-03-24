use std::ffi::CStr;
use std::io;

use super::super::super::process::{Group, User};
use super::stat::Stat;
use crate::unix::ProcessContext;

impl ProcessContext {
    pub fn current() -> io::Result<Self> {
        let exe = std::env::current_exe()?;
        let proc_stat = Stat::current()?;
        let pid: u32 = proc_stat.pid;
        let sid: u32 = proc_stat.session;
        let ttyno: u32 = proc_stat.tty_nr;
        let uid: u32 = unsafe { libc::getuid() };
        let gid: u32 = unsafe { libc::getgid() };

        let user_name = unsafe {
            *libc::__errno_location() = 0;
            let pwd = libc::getpwuid(uid);
            if pwd.is_null() {
                if *libc::__errno_location() == 0 {
                    return Err(io::Error::new(io::ErrorKind::NotFound, "invalid user"));
                } else {
                    return Err(io::Error::last_os_error());
                }
            } else {
                CStr::from_ptr((*pwd).pw_name).to_owned()
            }
        };

        let group_name = unsafe {
            *libc::__errno_location() = 0;
            let grd = libc::getgrgid(gid);
            if grd.is_null() {
                if *libc::__errno_location() == 0 {
                    return Err(io::Error::new(io::ErrorKind::NotFound, "invalid group"));
                } else {
                    return Err(io::Error::last_os_error());
                }
            } else {
                CStr::from_ptr((*grd).gr_name).to_owned()
            }
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
