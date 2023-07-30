mod noecho;
mod nonblock;
mod poll;

use core::mem::MaybeUninit;

pub(crate) fn is_terminal(fd: crate::io::RawFd) -> bool {
    let mut wsz = MaybeUninit::<libc::winsize>::uninit();
    unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, wsz.as_mut_ptr()) != -1 }
}

pub use noecho::{noecho, NoEchoHolder};
pub use nonblock::{nonblock, NonBlockHolder};
pub use poll::poll_read;
