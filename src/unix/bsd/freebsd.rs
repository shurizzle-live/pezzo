use std::{io, rc::Rc};

use super::{Group, IAMContext, User};

pub(crate) const BOOTTIME_CLOCKID: unix_clock::raw::ClockId = unix_clock::raw::ClockId::Boottime;

#[inline(always)]
pub(crate) fn process_infos() -> io::Result<(u32, u32, u32, u32, Option<TtyInfo>)> {
    let tty_info::ProcessInfo {
        pid,
        uid,
        session,
        tty,
    } = tty_info::ProcessInfo::current()?;
    let gid = unsafe { libc::getgid() };

    Ok((pid, uid, gid, session, tty))
}
