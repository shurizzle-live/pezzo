use std::mem::{self, MaybeUninit};

pub fn now() -> u64 {
    unsafe {
        let mut time = MaybeUninit::<libc::timespec>::uninit();
        libc::clock_gettime(
            if crate::version!(>= 2, 6, 39) {
                libc::CLOCK_BOOTTIME
            } else {
                libc::CLOCK_MONOTONIC
            },
            time.as_mut_ptr(),
        );
        let time = time.assume_init();
        mem::transmute(time.tv_sec)
    }
}
