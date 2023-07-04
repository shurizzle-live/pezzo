#![allow(non_camel_case_types)]

use crate::io;
use core::mem::MaybeUninit;

use linux_syscalls::{syscall, Sysno};

pub const NCCS: usize = 32;
pub const TCGETS: core::ffi::c_int = 0x5401;
pub const TCSETS: core::ffi::c_int = 0x5402;
pub const TCSANOW: core::ffi::c_int = 0;

pub const IGNBRK: tcflag_t = 1;
pub const BRKINT: tcflag_t = 2;
pub const INLCR: tcflag_t = 0x40;
pub const ICRNL: tcflag_t = 0x100;

pub const ISIG: tcflag_t = 1;
pub const ICANON: tcflag_t = 2;
pub const ECHOE: tcflag_t = 0x10;
pub const ECHOK: tcflag_t = 0x20;
pub const ECHONL: tcflag_t = 0x40;
pub const IEXTEN: tcflag_t = 0x8000;

pub type tcflag_t = core::ffi::c_uint;
pub type cc_t = core::ffi::c_uchar;
pub type speed_t = core::ffi::c_uint;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct termios {
    pub c_iflag: tcflag_t,
    pub c_oflag: tcflag_t,
    pub c_cflag: tcflag_t,
    pub c_lflag: tcflag_t,
    pub c_line: cc_t,
    pub c_cc: [cc_t; NCCS],
    #[cfg(not(any(
        target_arch = "sparc",
        target_arch = "sparc64",
        target_arch = "mips",
        target_arch = "mips64"
    )))]
    pub c_ispeed: speed_t,
    #[cfg(not(any(
        target_arch = "sparc",
        target_arch = "sparc64",
        target_arch = "mips",
        target_arch = "mips64"
    )))]
    pub c_ospeed: speed_t,
}

pub struct NoEchoHolder(io::RawFd, termios);

impl Drop for NoEchoHolder {
    fn drop(&mut self) {
        unsafe {
            _ = syscall!(
                [ro] Sysno::ioctl,
                self.0,
                TCSETS.wrapping_add(TCSANOW),
                &self.1 as *const _
            );
        };
    }
}

pub fn noecho<R: io::BufRead + io::AsRawFd>(reader: &mut R) -> io::Result<NoEchoHolder> {
    let mut stat = unsafe {
        let mut stat = MaybeUninit::<termios>::uninit();
        syscall!(Sysno::ioctl, reader.as_raw_fd(), TCGETS, stat.as_mut_ptr())?;
        stat.assume_init()
    };

    let holder = NoEchoHolder(reader.as_raw_fd(), stat);

    stat.c_iflag = IGNBRK | BRKINT | INLCR | ICRNL;
    stat.c_lflag = ISIG | ICANON | ECHOE | ECHOK | ECHONL | IEXTEN;

    unsafe {
        syscall!(
            [ro] Sysno::ioctl,
            reader.as_raw_fd(),
            TCSETS.wrapping_add(TCSANOW),
            &stat as *const _
        )?;
    };

    Ok(holder)
}
