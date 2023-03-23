use std::{
    io::{self, BufRead},
    os::fd::{AsRawFd, RawFd},
};

pub struct NonBlockHolder(RawFd, libc::c_int);

impl Drop for NonBlockHolder {
    fn drop(&mut self) {
        if self.1 != 0 {
            unsafe { libc::fcntl(self.0, libc::F_SETFL, self.1) };
        }
    }
}

pub fn nonblock<R: BufRead + AsRawFd>(reader: &mut R) -> io::Result<NonBlockHolder> {
    let flags = unsafe {
        let flags = libc::fcntl(reader.as_raw_fd(), libc::F_GETFL);
        if flags == -1 {
            return Err(io::Error::last_os_error());
        }

        if flags & libc::O_NONBLOCK == 0 {
            if libc::fcntl(reader.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) == -1 {
                return Err(io::Error::last_os_error());
            }
            flags
        } else {
            0
        }
    };

    Ok(NonBlockHolder(reader.as_raw_fd(), flags))
}
