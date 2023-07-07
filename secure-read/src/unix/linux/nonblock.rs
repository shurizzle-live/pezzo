use crate::io;
use linux_defs::{FcntlCommand as F, O};
use linux_syscalls::{syscall, Errno, Sysno};

pub struct NonBlockHolder(io::RawFd, O);

impl Drop for NonBlockHolder {
    fn drop(&mut self) {
        if self.1.bits() == 0 {
            unsafe {
                _ = syscall!([ro] Sysno::fcntl, self.0, F::SETFL, self.1.bits());
            };
        }
    }
}

pub fn nonblock<R: io::BufRead + io::AsRawFd>(reader: &mut R) -> io::Result<NonBlockHolder> {
    let flags = unsafe {
        let flags = loop {
            match syscall!(Sysno::fcntl, reader.as_raw_fd(), F::GETFL) {
                Err(Errno::EINTR) => (),
                Err(err) => break Err(err),
                Ok(f) => break Ok(O::from_bits(f) | O::LARGEFILE),
            }
        }?;
        if !flags.contains(O::NONBLOCK) {
            loop {
                match syscall!(
                    [ro] Sysno::fcntl,
                    reader.as_raw_fd(),
                    F::SETFL,
                    (flags | O::NONBLOCK).bits()
                ) {
                    Err(Errno::EINTR) => (),
                    Err(err) => break Err(err),
                    Ok(_) => break Ok(()),
                }
            }?;

            flags
        } else {
            O::empty()
        }
    };

    Ok(NonBlockHolder(reader.as_raw_fd(), flags))
}
