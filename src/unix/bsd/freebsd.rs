use std::io;

use tty_info::TtyInfo;

pub(crate) const BOOTTIME_CLOCKID: unix_clock::raw::ClockId = unix_clock::raw::ClockId::Boottime;

#[inline(always)]
pub(crate) fn process_infos() -> io::Result<(u32, u32, u32, u32, Option<TtyInfo>)> {
    let tty_info::ProcessInfo { pid, session, tty } = tty_info::ProcessInfo::current()?;
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    Ok((pid, uid, gid, session, tty))
}
