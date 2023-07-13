use crate::io;
use linux_raw_sys::general::{F_GETFL, F_SETFL, O_LARGEFILE, O_NONBLOCK};
use linux_syscalls::{syscall, Errno, Sysno};

pub struct NonBlockHolder(io::RawFd, u32);

impl Drop for NonBlockHolder {
    fn drop(&mut self) {
        if self.1 == 0 {
            unsafe {
                _ = syscall!([ro] Sysno::fcntl, self.0, F_SETFL, self.1);
            };
        }
    }
}

pub fn nonblock<R: io::BufRead + io::AsRawFd>(reader: &mut R) -> io::Result<NonBlockHolder> {
    let flags = unsafe {
        let flags = loop {
            match syscall!(Sysno::fcntl, reader.as_raw_fd(), F_GETFL) {
                Err(Errno::EINTR) => (),
                Err(err) => break Err(err),
                Ok(f) => break Ok(f as u32 | O_LARGEFILE),
            }
        }?;
        if flags & O_NONBLOCK != O_NONBLOCK {
            loop {
                match syscall!(
                    [ro] Sysno::fcntl,
                    reader.as_raw_fd(),
                    F_SETFL,
                    flags | O_NONBLOCK
                ) {
                    Err(Errno::EINTR) => (),
                    Err(err) => break Err(err),
                    Ok(_) => break Ok(()),
                }
            }?;

            flags
        } else {
            0
        }
    };

    Ok(NonBlockHolder(reader.as_raw_fd(), flags))
}
