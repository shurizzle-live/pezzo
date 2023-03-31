use std::{io, mem::MaybeUninit};

pub fn now() -> io::Result<i64> {
    unsafe {
        let mut time = MaybeUninit::<libc::timespec>::uninit();
        let rc = libc::clock_gettime(libc::CLOCK_BOOTTIME, time.as_mut_ptr());
        if rc == -1 {
            return Err(io::Error::last_os_error());
        }

        let time = time.assume_init();
        Ok(time.tv_sec)
    }
}
