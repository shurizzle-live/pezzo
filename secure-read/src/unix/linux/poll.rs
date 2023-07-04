#![allow(clippy::useless_conversion)]

use unix_clock::Instant;

use crate::io;

use linux_syscalls::{syscall, Errno, Sysno};

// const MAX_TIMEOUT: u32 = core::ffi::c_int::MAX as u32 / 2;
const POLLIN: core::ffi::c_short = 1;

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
    const TIMEOUT: core::ffi::c_int = -1;

    loop {
        match unsafe { syscall!(Sysno::poll, &mut pfd as *mut pollfd_t, 1, TIMEOUT) } {
            Ok(0) => return Err(Errno::ETIMEDOUT),
            Ok(_) => return Ok(()),
            Err(Errno::EAGAIN) | Err(Errno::EINTR) => (),
            Err(err) => return Err(err),
        }
    }
}

pub fn poll_read(fd: io::RawFd, timeout: i32) -> io::Result<()> {
    let mut timeout = if timeout > 0 {
        timeout as u32 * 1000
    } else {
        return Ok(poll_read_inf(fd)?);
    };

    let mut pfd = pollfd_t {
        fd,
        events: POLLIN,
        revents: 0,
    };

    loop {
        let pre = Instant::now();
        match unsafe { syscall!(Sysno::poll, &mut pfd as *mut pollfd_t, 1, timeout as i32) } {
            Ok(0) => return Err(Errno::ETIMEDOUT.into()),
            Ok(_) => return Ok(()),
            Err(Errno::EAGAIN) | Err(Errno::EINTR) => {
                timeout = pre
                    .elapsed()
                    .as_millis()
                    .try_into()
                    .ok()
                    .and_then(|elapsed| timeout.checked_sub(elapsed))
                    .and_then(|t| if t == 0 { None } else { Some(t) })
                    .map_or(Err(Errno::ETIMEDOUT), Ok)?;
            }
            Err(err) => return Err(err.into()),
        }
    }
}
