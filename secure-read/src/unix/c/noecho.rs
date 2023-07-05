use core::mem::MaybeUninit;

use crate::io;

pub struct NoEchoHolder(io::RawFd, libc::termios);

impl Drop for NoEchoHolder {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.0, libc::TCSANOW, &self.1) };
    }
}

pub fn noecho<R: io::BufRead + io::AsRawFd>(reader: &mut R) -> io::Result<NoEchoHolder> {
    let mut stat = unsafe {
        let mut stat = MaybeUninit::<libc::termios>::uninit();
        if libc::tcgetattr(reader.as_raw_fd(), stat.as_mut_ptr()) == -1 {
            return Err(io::Error::last_os_error());
        }
        stat.assume_init()
    };

    let holder = NoEchoHolder(reader.as_raw_fd(), stat);

    stat.c_iflag = libc::IGNBRK | libc::BRKINT | libc::INLCR | libc::ICRNL;
    stat.c_lflag =
        libc::ISIG | libc::ICANON | libc::ECHOE | libc::ECHOK | libc::ECHONL | libc::IEXTEN;

    if unsafe { libc::tcsetattr(reader.as_raw_fd(), libc::TCSANOW, &stat) } == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(holder)
}
