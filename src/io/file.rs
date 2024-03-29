use tty_info::CStr;

use super::{FromRawFd, RawFd};

pub trait FileExt {
    fn lock_shared(&mut self) -> std::io::Result<()>;

    fn lock_exclusive(&mut self) -> std::io::Result<()>;
}

cfg_if::cfg_if! {
    if #[cfg(target_os = "linux")] {
        use std::{
            io::{Read, Write, Seek, SeekFrom},
            os::fd::AsFd,
        };
        use linux_syscalls::{syscall, Sysno, Errno};
        use linux_stat::CURRENT_DIRECTORY;
        use super::AsRawFd;
        use linux_raw_sys::general::{
            LOCK_EX, LOCK_SH, O_APPEND, O_CLOEXEC, O_CREAT, O_EXCL, O_RDONLY, O_RDWR, O_TRUNC,
            O_WRONLY, SEEK_SET, SEEK_CUR, SEEK_END
        };

        pub struct File {
            fd: RawFd,
        }

        impl File {
            pub fn set_len(&mut self, size: u64) -> std::io::Result<()> {
                _ = unsafe { syscall!([ro] Sysno::ftruncate, self.fd, size)? };
                Ok(())
            }
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
                loop {
                    match unsafe { syscall!(Sysno::read, self.fd, buf.as_mut_ptr(), buf.len()) } {
                        Err(Errno::EINTR) => (),
                        Err(err) => return Err(err.into()),
                        Ok(len) => return Ok(len),
                    }
                }
            }
        }

        impl Write for File {
            #[inline]
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                loop {
                    match unsafe { syscall!([ro] Sysno::write, self.fd, buf.as_ptr(), buf.len()) } {
                        Err(Errno::EINTR) => (),
                        Err(err) => return Err(err.into()),
                        Ok(len) => return Ok(len),
                    }
                }
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

        impl FileExt for File {
            fn lock_shared(&mut self) -> std::io::Result<()> {
                loop {
                    match unsafe { syscall!([ro] Sysno::flock, self.as_raw_fd(), LOCK_SH) } {
                        Err(Errno::EINTR) => println!("EINTR"),
                        Err(err) => return Err(err.into()),
                        Ok(_) => return Ok(()),
                    }
                }
            }

            fn lock_exclusive(&mut self) -> std::io::Result<()> {
                loop {
                    match unsafe { syscall!([ro] Sysno::flock, self.as_raw_fd(), LOCK_EX) } {
                        Err(Errno::EINTR) => println!("EINTR"),
                        Err(err) => return Err(err.into()),
                        Ok(_) => return Ok(()),
                    }
                }
            }
        }

        impl Seek for File {
            fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
                let fd = self.as_raw_fd();
                let (pos, whence) = match pos {
                    SeekFrom::Start(pos) => (pos as usize, SEEK_SET as usize),
                    SeekFrom::Current(pos) => (pos as usize, SEEK_CUR as usize),
                    SeekFrom::End(pos) => (pos as usize, SEEK_END as usize),
                };

                loop {
                    match unsafe { syscall!([ro] Sysno::lseek, fd, pos, whence) } {
                        Err(Errno::EINTR) => (),
                        Err(err) => return Err(err.into()),
                        Ok(prev) => return Ok(prev as u64),
                    }
                }
            }
        }

        impl Drop for File {
            fn drop(&mut self) {
                unsafe { _ = syscall!([ro] Sysno::close, self.as_raw_fd()) };
            }
        }

        pub fn remove_file<P: AsRef<CStr>>(path: P) -> std::io::Result<()> {
            loop {
                match unsafe { syscall!([ro] Sysno::unlinkat, CURRENT_DIRECTORY, path.as_ref().as_ptr(), 0) } {
                    Err(Errno::EINTR) => (),
                    Err(err) => return Err(err.into()),
                    Ok(_) => return Ok(()),
                }
            }
        }
    } else {
        pub use std::fs::File;
    }
}

cfg_if::cfg_if! {
    if #[cfg(all(unix, not(target_os = "linux")))] {
        use super::AsRawFd;

        const O_RDONLY: u32 = libc::O_RDONLY as u32;
        const O_WRONLY: u32 = libc::O_WRONLY as u32;
        const O_RDWR: u32 = libc::O_RDWR as u32;
        const O_APPEND: u32 = libc::O_APPEND as u32;
        const O_CREAT: u32 = libc::O_CREAT as u32;
        const O_TRUNC: u32 = libc::O_TRUNC as u32;
        const O_EXCL: u32 = libc::O_EXCL as u32;
        const O_CLOEXEC: u32 = libc::O_CLOEXEC as u32;

        pub fn remove_file<P: AsRef<CStr>>(path: P) -> std::io::Result<()> {
            loop {
                if unsafe { libc::unlink(path.as_ref().as_ptr()) } == -1 {
                    match std::io::Error::last_os_error() {
                        err if err.kind() == std::io::ErrorKind::Interrupted => (),
                        err => return Err(err),
                    }
                } else {
                    return Ok(());
                }
            }
        }

        impl FileExt for File {
            fn lock_shared(&mut self) -> std::io::Result<()> {
                if unsafe { libc::flock(self.as_raw_fd(), libc::LOCK_SH) } == -1 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            }

            fn lock_exclusive(&mut self) -> std::io::Result<()> {
                if unsafe { libc::flock(self.as_raw_fd(), libc::LOCK_EX) } == -1 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            }
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub struct OpenOptions {
            read: bool,
            write: bool,
            append: bool,
            truncate: bool,
            create: bool,
            create_new: bool,
            mode: u16,
        }

        impl Default for OpenOptions {
            #[inline]
            fn default() -> Self {
                Self::new()
            }
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
                    mode: 0o666,
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

            pub fn mode(&mut self, mode: u16) -> &mut Self {
                self.mode = mode;
                self
            }

            fn get_access_mode(&self) -> std::io::Result<u32> {
                match (self.read, self.write, self.append) {
                    (true, false, false) => Ok(O_RDONLY),
                    (false, true, false) => Ok(O_WRONLY),
                    (true, true, false) => Ok(O_RDWR),
                    (false, _, true) => Ok(O_WRONLY | O_APPEND),
                    (true, _, true) => Ok(O_RDWR | O_APPEND),
                    (false, false, false) => Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
                }
            }

            fn get_creation_mode(&self) -> std::io::Result<u32> {
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

            pub fn open_cstr<P: AsRef<CStr>>(&self, path: P) -> std::io::Result<File> {
                let path = path.as_ref();

                let flags = O_CLOEXEC | self.get_access_mode()? | self.get_creation_mode()?;
                #[cfg(not(target_os = "linux"))]
                {
                    loop {
                        let fd = unsafe { libc::open(path.as_ptr(), flags as _, self.mode as libc::c_uint) };
                        if fd == -1 {
                            match std::io::Error::last_os_error() {
                                err if err.kind() == std::io::ErrorKind::Interrupted => (),
                                err => return Err(err),
                            }
                        } else {
                            return Ok(unsafe { File::from_raw_fd(fd as RawFd) });
                        }
                    }
                }
                #[cfg(target_os = "linux")]
                {
                    loop {
                        match unsafe {
                            syscall!([ro] Sysno::openat, CURRENT_DIRECTORY, path.as_ptr(), flags, self.mode).map(|fd| fd as RawFd)
                        } {
                            Err(Errno::EINTR) => (),
                            Err(err) => return Err(err.into()),
                            Ok(fd) => return Ok(unsafe { File::from_raw_fd(fd) }),
                        }
                    }
                }
            }
        }
    }
}
