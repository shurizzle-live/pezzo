use std::mem::{self, MaybeUninit};

pub fn now() -> u64 {
    unsafe {
        let mut time = MaybeUninit::<libc::timespec>::uninit();
        libc::clock_gettime(libc::CLOCK_BOOTTIME, time.as_mut_ptr());
        let time = time.assume_init();
        mem::transmute(time.tv_sec)
    }
}
