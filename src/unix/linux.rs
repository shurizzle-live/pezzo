use sstd::io;

use linux_syscalls::{syscall, Sysno};
use tty_info::{ProcessInfo, TtyInfo};

pub(crate) const BOOTTIME_CLOCKID: unix_clock::raw::ClockId = unix_clock::raw::ClockId::Boottime;

#[inline(always)]
pub(crate) fn process_infos() -> io::Result<(u32, u32, u32, u32, Option<TtyInfo>)> {
    let ProcessInfo { pid, session, tty } = ProcessInfo::current()?;
    let uid = unsafe { syscall!([ro] Sysno::getuid).unwrap_unchecked() as u32 };
    let gid = unsafe { syscall!([ro] Sysno::getgid).unwrap_unchecked() as u32 };

    Ok((pid, uid, gid, session, tty))
}
