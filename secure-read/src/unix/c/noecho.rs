use core::mem::MaybeUninit;

use crate::io;

pub struct NoEchoHolder(io::RawFd, libc::termios);

impl Drop for NoEchoHolder {
    fn drop(&mut self) {
        unsafe {
            libc::ioctl(
                self.0,
                libc::TCSETS | libc::TCSANOW as libc::Ioctl,
                &self.1 as *const _,
            )
        };
    }
}

pub fn noecho<R: io::BufRead + io::AsRawFd>(reader: &mut R) -> io::Result<NoEchoHolder> {
    let mut stat = unsafe {
        let mut stat = MaybeUninit::<libc::termios>::uninit();
        if libc::ioctl(reader.as_raw_fd(), libc::TCGETS, stat.as_mut_ptr()) == -1 {
            return Err(io::Error::last_os_error());
        }
        stat.assume_init()
    };

    let holder = NoEchoHolder(reader.as_raw_fd(), stat);

    stat.c_iflag = libc::IGNBRK | libc::BRKINT | libc::INLCR | libc::ICRNL;
    stat.c_lflag =
        libc::ISIG | libc::ICANON | libc::ECHOE | libc::ECHOK | libc::ECHONL | libc::IEXTEN;

    if unsafe {
        libc::ioctl(
            reader.as_raw_fd(),
            libc::TCSETS | libc::TCSANOW as libc::Ioctl,
            &stat as *const _,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }

    Ok(holder)
}
