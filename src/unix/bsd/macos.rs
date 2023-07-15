use std::{io, rc::Rc};

use super::{Group, IAMContext, User};

pub(crate) const BOOTTIME_CLOCKID: unix_clock::raw::ClockId =
    unix_clock::raw::ClockId::MonotonicRaw;

#[inline(always)]
pub(crate) fn process_infos() -> io::Result<(u32, u32, u32, u32, Option<TtyInfo>)> {
    let tty_info::ProcessInfo { pid, uid, gid, tty } = tty_info::ProcessInfo::current()?;
    let session = unsafe { libc::getsid(pid as _) as _ };

    Ok((pid, uid, gid, session, tty))
}
