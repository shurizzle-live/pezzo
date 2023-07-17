#![allow(clippy::useless_conversion)]

use cfg_if::cfg_if;
use unix_clock::raw::Timespec;

use crate::io;

use linux_syscalls::{syscall, Errno, Sysno};

const POLLIN: core::ffi::c_short = 1;

cfg_if! {
    if #[cfg(any(target_arch = "mips", target_arch = "mips64"))] {
        const _NSIG: usize = 128;
    } else {
        const _NSIG: usize = 65;
    }
}

cfg_if! {
    if #[cfg(any(target_pointer_width = "64", target_arch = "x86_64"))] {
        #[allow(non_upper_case_globals)]
        const SYS_ppoll64: Sysno = Sysno::ppoll;

        #[inline(always)]
        fn poll(pfds: &mut [pollfd_t], timeout: i32) -> Result<usize, Errno> {
            poll64(pfds, timeout)
        }
    } else {
        #[allow(non_upper_case_globals)]
        const SYS_ppoll64: Sysno = Sysno::ppoll_time64;
        #[allow(non_upper_case_globals)]
        const SYS_ppoll32: Sysno = Sysno::ppoll;

        use core::sync::atomic::{AtomicU8, Ordering};

        #[repr(C)]
        pub struct Timespec32 {
            secs: i32,
            nsecs: u32,
        }

        impl Timespec32 {
            #[inline]
            pub fn new(secs: i32, nsecs: u32) -> Self {
                Self { secs, nsecs }
            }
        }

        static mut STATE: AtomicU8 = AtomicU8::new(2);

        #[inline(always)]
        fn poll32(pfds: &mut [pollfd_t], timeout: i32) -> Result<usize, Errno> {
            let mut timeout = if timeout > 0 {
                Some(Timespec32::new(timeout, 0))
            } else {
                None
            };

            loop {
                match unsafe {
                    syscall!(
                        SYS_ppoll64,
                        pfds.as_mut_ptr(),
                        pfds.len(),
                        timeout
                            .as_mut()
                            .map(|x| x as *mut Timespec32)
                            .unwrap_or(core::ptr::null_mut()),
                        0,
                        _NSIG / 8
                    )
                } {
                    Ok(0) => return Err(Errno::ETIMEDOUT),
                    Ok(v) => return Ok(v),
                    Err(Errno::EINTR) => (),
                    Err(err) => return Err(err),
                }
            }
        }

        fn poll(pfds: &mut [pollfd_t], timeout: i32) -> Result<usize, Errno> {
            match unsafe { STATE.load(Ordering::Relaxed) } {
                0 => poll32(pfds, timeout),
                1 => poll64(pfds, timeout),
                _ => match poll64(pfds, timeout) {
                    Err(Errno::ENOSYS) => {
                        unsafe { STATE.store(0, Ordering::Relaxed) };
                        poll32(pfds, timeout)
                    }
                    other => {
                        unsafe { STATE.store(1, Ordering::Relaxed) };
                        other
                    }
                },
            }
        }
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
fn poll64(pfds: &mut [pollfd_t], timeout: i32) -> Result<usize, Errno> {
    let mut timeout = if timeout > 0 {
        Some(Timespec::new(timeout as i64, 0))
    } else {
        None
    };

    loop {
        match unsafe {
            syscall!(
                SYS_ppoll64,
                pfds.as_mut_ptr(),
                pfds.len(),
                timeout
                    .as_mut()
                    .map(|x| x as *mut Timespec)
                    .unwrap_or(core::ptr::null_mut()),
                0,
                _NSIG / 8
            )
        } {
            Ok(0) => return Err(Errno::ETIMEDOUT),
            Ok(v) => return Ok(v),
            Err(Errno::EINTR) => (),
            Err(err) => return Err(err),
        }
    }
}

pub fn poll_read(fd: io::RawFd, timeout: i32) -> io::Result<()> {
    let mut pfds = [pollfd_t {
        fd,
        events: POLLIN,
        revents: 0,
    }];

    _ = poll(&mut pfds[..], timeout)?;
    Ok(())
}
