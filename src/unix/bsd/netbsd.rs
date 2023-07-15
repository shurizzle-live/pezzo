use std::{io, rc::Rc};

use super::{Group, IAMContext, User};

pub(crate) const BOOTTIME_CLOCKID: unix_clock::raw::ClockId = unix_clock::raw::ClockId::Monotonic;

impl super::ProcessContext {
    pub fn current(iam: &IAMContext) -> io::Result<Self> {
        let tty_info::ProcessInfo {
            pid,
            uid,
            gid,
            session,
            tty,
        } = tty_info::ProcessInfo::current()?;

        let tty = if let Some(tty) = tty {
            tty
        } else {
            return Err(io::ErrorKind::NotFound.into());
        };

        let exe = std::env::current_exe()?;

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
            tty: Rc::new(tty),
        })
    }
}
