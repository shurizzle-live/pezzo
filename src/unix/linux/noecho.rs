use std::{
    io::{self, BufRead},
    mem::MaybeUninit,
    os::fd::{AsRawFd, RawFd},
};

use syscalls::{syscall, Sysno};

const NCCS: usize = 32;

#[allow(non_camel_case_types)]
type tcflag_t = core::ffi::c_uint;
#[allow(non_camel_case_types)]
type cc_t = core::ffi::c_uchar;
#[allow(non_camel_case_types)]
type speed_t = core::ffi::c_uint;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
struct termios {
    c_iflag: tcflag_t,
    c_oflag: tcflag_t,
    c_cflag: tcflag_t,
    c_lflag: tcflag_t,
    c_line: cc_t,
    c_cc: [cc_t; NCCS],
    c_ispeed: speed_t,
    c_ospeed: speed_t,
}

const TCGETS: usize = 21505;
const TCSETS: usize = 21506;

const IGNBRK: tcflag_t = 1;
const BRKINT: tcflag_t = 2;
const INLCR: tcflag_t = 64;
const ICRNL: tcflag_t = 256;
const ISIG: tcflag_t = 1;
const ICANON: tcflag_t = 2;
const ECHOE: tcflag_t = 16;
const ECHOK: tcflag_t = 32;
const ECHONL: tcflag_t = 64;
const IEXTEN: tcflag_t = 32768;

pub struct NoEchoHolder(RawFd, termios);

impl Drop for NoEchoHolder {
    fn drop(&mut self) {
        unsafe {
            _ = syscall!(Sysno::ioctl, self.0, TCSETS, &self.1 as *const _);
        };
    }
}

pub fn noecho<R: BufRead + AsRawFd>(reader: &mut R) -> io::Result<NoEchoHolder> {
    let mut stat = unsafe {
        let mut stat = MaybeUninit::<termios>::uninit();
        syscall!(Sysno::ioctl, reader.as_raw_fd(), TCGETS, stat.as_mut_ptr()).unwrap();
        stat.assume_init()
    };

    let holder = NoEchoHolder(reader.as_raw_fd(), stat);

    stat.c_iflag = IGNBRK | BRKINT | INLCR | ICRNL;
    stat.c_lflag = ISIG | ICANON | ECHOE | ECHOK | ECHONL | IEXTEN;

    unsafe {
        syscall!(Sysno::ioctl, reader.as_raw_fd(), TCSETS, &stat as *const _).unwrap();
    };

    Ok(holder)
}
