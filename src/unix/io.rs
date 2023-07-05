pub use secure_read::io::AsRawFd;
pub use std::io::Result;
use tty_info::CStr;
pub use tty_info::RawFd;

use std::{
    io::{Read, Write},
    os::fd::{AsFd, FromRawFd},
};

cfg_if::cfg_if! {
    if #[cfg(target_os = "linux")] {
        use linux_syscalls::{syscall, Sysno};

        const O_RDONLY: usize = 0o0000000;
        const O_WRONLY: usize = 0o0000001;
        const O_RDWR: usize = 0o0000002;
        const O_APPEND: usize = 0o0002000;
        const O_CREAT: usize = 0o00000100;
        const O_TRUNC: usize = 0o00001000;
        const O_EXCL: usize = 0o00000200;
        const O_CLOEXEC: usize = 0o2000000;

        pub struct File {
            fd: RawFd,
        }

        impl AsRawFd for File {
            #[inline(always)]
            fn as_raw_fd(&self) -> RawFd {
                self.fd
            }
        }

        impl Read for File {
            #[inline]
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                Ok(unsafe { syscall!(Sysno::read, self.fd, buf.as_mut_ptr(), buf.len()) }?)
            }
        }

        impl Write for File {
            #[inline]
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                Ok(unsafe { syscall!([ro] Sysno::write, self.fd, buf.as_ptr(), buf.len()) }?)
            }

            #[inline(always)]
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl AsFd for File {
            #[inline]
            fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
                unsafe { std::os::fd::BorrowedFd::borrow_raw(self.as_raw_fd()) }
            }
        }

        impl FromRawFd for File {
            #[inline]
            unsafe fn from_raw_fd(fd: RawFd) -> Self {
                Self { fd }
            }
        }
    } else {
        pub use std::fs::File;

        const O_RDONLY: usize = libc::O_RDONLY as usize;
        const O_WRONLY: usize = libc::O_WRONLY as usize;
        const O_RDWR: usize = libc::O_RDWR as usize;
        const O_APPEND: usize = libc::O_APPEND as usize;
        const O_CREAT: usize = libc::O_CREAT as usize;
        const O_TRUNC: usize = libc::O_TRUNC as usize;
        const O_EXCL: usize = libc::O_EXCL as usize;
        const O_CLOEXEC: usize = libc::O_CLOEXEC as usize;
    }
}

pub struct OpenOptions {
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
}

#[allow(dead_code)]
impl OpenOptions {
    pub fn new() -> Self {
        Self {
            read: false,
            write: false,
            append: false,
            truncate: false,
            create: false,
            create_new: false,
        }
    }

    pub fn read(&mut self, read: bool) -> &mut Self {
        self.read = read;
        self
    }

    pub fn write(&mut self, write: bool) -> &mut Self {
        self.write = write;
        self
    }

    pub fn append(&mut self, append: bool) -> &mut Self {
        self.append = append;
        self
    }

    pub fn truncate(&mut self, truncate: bool) -> &mut Self {
        self.truncate = truncate;
        self
    }

    pub fn create(&mut self, create: bool) -> &mut Self {
        self.create = create;
        self
    }

    pub fn create_new(&mut self, create_new: bool) -> &mut Self {
        self.create_new = create_new;
        self
    }

    fn get_access_mode(&self) -> std::io::Result<usize> {
        match (self.read, self.write, self.append) {
            (true, false, false) => Ok(O_RDONLY),
            (false, true, false) => Ok(O_WRONLY),
            (true, true, false) => Ok(O_RDWR),
            (false, _, true) => Ok(O_WRONLY | O_APPEND),
            (true, _, true) => Ok(O_RDWR | O_APPEND),
            (false, false, false) => Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
        }
    }

    fn get_creation_mode(&self) -> std::io::Result<usize> {
        match (self.write, self.append) {
            (true, false) => (),
            (false, false) => {
                if self.truncate || self.create || self.create_new {
                    return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
                }
            }
            (_, true) => {
                if self.truncate && !self.create_new {
                    return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
                }
            }
        }

        Ok(match (self.create, self.truncate, self.create_new) {
            (false, false, false) => 0,
            (true, false, false) => O_CREAT,
            (false, true, false) => O_TRUNC,
            (true, true, false) => O_CREAT | O_TRUNC,
            (_, _, true) => O_CREAT | O_EXCL,
        })
    }

    pub fn open_cstr(&self, path: &CStr) -> std::io::Result<File> {
        let flags = O_CLOEXEC | self.get_access_mode()? | self.get_creation_mode()?;
        #[cfg(not(target_os = "linux"))]
        {
            let fd = unsafe { libc::open(path.as_ptr(), flags as _) };
            if fd == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(unsafe { File::from_raw_fd(fd as RawFd) })
            }
        }
        #[cfg(target_os = "linux")]
        {
            Ok(unsafe { File::from_raw_fd(syscall!(Sysno::open, path.as_ptr(), flags)? as RawFd) })
        }
    }
}
