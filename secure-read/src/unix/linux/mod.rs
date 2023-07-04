mod noecho;
mod nonblock;
mod poll;

pub use linux_syscalls::Errno;

use core::mem::MaybeUninit;

use linux_syscalls::{syscall, Sysno};

pub(crate) fn is_terminal(fd: crate::io::RawFd) -> bool {
    const TIOCGWINSZ: core::ffi::c_int = 0x5413;
    #[repr(C)]
    struct winsize {
        pub ws_row: core::ffi::c_ushort,
        pub ws_col: core::ffi::c_ushort,
        pub ws_xpixel: core::ffi::c_ushort,
        pub ws_ypixel: core::ffi::c_ushort,
    }

    let mut wsz = MaybeUninit::<winsize>::uninit();
    unsafe { syscall!(Sysno::ioctl, fd, TIOCGWINSZ, wsz.as_mut_ptr()) }.map_or(false, |_| true)
}

pub use noecho::{noecho, NoEchoHolder};
pub use nonblock::{nonblock, NonBlockHolder};
pub use poll::poll_read;
