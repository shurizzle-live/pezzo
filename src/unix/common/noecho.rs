use std::{
    io::{self, BufRead},
    mem::MaybeUninit,
    os::fd::{AsRawFd, RawFd},
};

pub struct NoEchoHolder(RawFd, libc::termios);

impl Drop for NoEchoHolder {
    fn drop(&mut self) {
        unsafe {
            _ = libc::tcsetattr(self.0, libc::TCSANOW, &self.1 as *const _);
        };
    }
}

pub fn noecho<R: BufRead + AsRawFd>(reader: &mut R) -> io::Result<NoEchoHolder> {
    let mut stat = unsafe {
        let mut stat = MaybeUninit::<libc::termios>::uninit();
        if libc::tcgetattr(reader.as_raw_fd(), stat.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        stat.assume_init()
    };

    let holder = NoEchoHolder(reader.as_raw_fd(), stat);

    stat.c_iflag = libc::IGNBRK | libc::BRKINT | libc::INLCR | libc::ICRNL;
    stat.c_lflag =
        libc::ISIG | libc::ICANON | libc::ECHOE | libc::ECHOK | libc::ECHONL | libc::IEXTEN;

    unsafe {
        if libc::tcsetattr(reader.as_raw_fd(), libc::TCSANOW, &stat as *const _) != 0 {
            return Err(io::Error::last_os_error());
        }
    };

    Ok(holder)
}
