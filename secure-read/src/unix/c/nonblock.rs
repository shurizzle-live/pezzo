use crate::io;

pub struct NonBlockHolder(io::RawFd, core::ffi::c_int);

impl Drop for NonBlockHolder {
    fn drop(&mut self) {
        if self.1 != 0 {
            unsafe { libc::fcntl(self.0, libc::F_SETFL, self.1) };
        }
    }
}

pub fn nonblock<R: io::BufRead + io::AsRawFd>(reader: &mut R) -> io::Result<NonBlockHolder> {
    let flags = unsafe {
        let flags = libc::fcntl(reader.as_raw_fd(), libc::F_GETFL);
        if flags == -1 {
            return Err(io::Error::last_os_error());
        }
        #[cfg(target_os = "linux")]
        let flags = flags | libc::O_LARGEFILE;

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
