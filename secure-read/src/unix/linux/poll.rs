#![allow(clippy::useless_conversion)]

use cfg_if::cfg_if;
use unix_clock::raw::Timespec;

use crate::io;

use linux_syscalls::{syscall, Errno, Sysno};

// const MAX_TIMEOUT: u32 = core::ffi::c_int::MAX as u32 / 2;
const POLLIN: core::ffi::c_short = 1;

cfg_if! {
    if #[cfg(any(target_arch = "mips", target_arch = "mips64"))] {
        const _NSIG: usize = 128;
    } else {
        const _NSIG: usize = 65;
    }
}

cfg_if! {
    if #[cfg(any(
        target_arch = "x86_64",
        all(target_arch = "mips", target_pointer_width = "64"),
        target_arch = "powerpc64",
        target_arch = "s390x",
        target_arch = "sparc64"
    ))] {
        #[allow(non_upper_case_globals)]
        const SYS_ppoll: Sysno = Sysno::ppoll;
    } else {
        #[allow(non_upper_case_globals)]
        const SYS_ppoll: Sysno = Sysno::ppoll_time64;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct pollfd_t {
    pub fd: io::RawFd,
    pub events: core::ffi::c_short,
    pub revents: core::ffi::c_short,
}

#[inline(always)]
fn poll_read_inf(fd: io::RawFd) -> Result<(), Errno> {
    let mut pfd = pollfd_t {
        fd,
        events: POLLIN,
        revents: 0,
    };

    loop {
        match unsafe { syscall!(SYS_ppoll, &mut pfd as *mut pollfd_t, 1, 0, 0, _NSIG / 8) } {
            Ok(0) => return Err(Errno::ETIMEDOUT),
            Ok(_) => return Ok(()),
            Err(Errno::EAGAIN) | Err(Errno::EINTR) => (),
            Err(err) => return Err(err),
        }
    }
}

pub fn poll_read(fd: io::RawFd, timeout: i32) -> io::Result<()> {
    let mut timeout = if timeout > 0 {
        Timespec::new(timeout as i64, 0)
    } else {
        return Ok(poll_read_inf(fd)?);
    };

    let mut pfd = pollfd_t {
        fd,
        events: POLLIN,
        revents: 0,
    };

    loop {
        match unsafe {
            syscall!(
                SYS_ppoll,
                &mut pfd as *mut pollfd_t,
                1,
                (&mut timeout) as *mut Timespec,
                0,
                _NSIG / 8
            )
        } {
            Ok(0) => return Err(Errno::ETIMEDOUT.into()),
            Ok(_) => return Ok(()),
            Err(Errno::EAGAIN) | Err(Errno::EINTR) => {
                println!("{:?}", timeout);
            }
            Err(err) => return Err(err.into()),
        }
    }
}
