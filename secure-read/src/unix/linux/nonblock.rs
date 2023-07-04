use crate::io;
use linux_syscalls::{syscall, Sysno};

pub const F_GETFL: core::ffi::c_int = 3;
pub const F_SETFL: core::ffi::c_int = 4;
pub const O_NONBLOCK: core::ffi::c_int = 0x800;
pub const O_LARGEFILE: core::ffi::c_int = 0o100000;

pub struct NonBlockHolder(io::RawFd, core::ffi::c_int);

impl Drop for NonBlockHolder {
    fn drop(&mut self) {
        if self.1 != 0 {
            unsafe {
                _ = syscall!([ro] Sysno::fcntl, self.0, F_SETFL, self.1);
            };
        }
    }
}

pub fn nonblock<R: io::BufRead + io::AsRawFd>(reader: &mut R) -> io::Result<NonBlockHolder> {
    let flags = unsafe {
        let flags = syscall!(Sysno::fcntl, reader.as_raw_fd(), F_GETFL)?;
        let flags = core::mem::transmute::<u32, i32>(flags as u32) | O_LARGEFILE;

        if flags & O_NONBLOCK == 0 {
            syscall!(
                [ro] Sysno::fcntl,
                reader.as_raw_fd(),
                F_SETFL,
                flags | O_NONBLOCK
            )?;
            flags
        } else {
            0
        }
    };

    Ok(NonBlockHolder(reader.as_raw_fd(), flags))
}
