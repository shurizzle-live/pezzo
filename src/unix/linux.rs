#[macro_export]
macro_rules! prefix {
    ($p:literal) => {
        $p
    };
}

use std::{io, ptr, sync::Arc};

use tty_info::ProcessInfo;

use super::{
    process::{Group, User},
    IAMContext, ProcessContext,
};

pub(crate) const BOOTTIME_CLOCKID: unix_clock::raw::ClockId = unix_clock::raw::ClockId::Bootime;

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
        let ProcessInfo { pid, session, tty } = ProcessInfo::current()?;

        let tty = if let Some(tty) = tty {
            tty
        } else {
            return Err(io::ErrorKind::NotFound.into());
        };

        let uid: u32 = unsafe { libc::getuid() };
        let gid: u32 = unsafe { libc::getgid() };

        iam.set_effective_identity(uid, gid)?;

        let exe = std::fs::canonicalize(std::env::current_exe()?)?;

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

        let original_groups = iam.get_groups(original_user.name())?;

        Ok(Self {
            exe,
            pid,
            original_user,
            original_group,
            original_groups,
            sid: session,
            tty: Arc::new(tty),
        })
    }
}
