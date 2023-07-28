use core::{
    cell::OnceCell,
    fmt,
    ops::{Deref, DerefMut},
};

use crate::io::{AsRawFd, BufRead, BufReader, LineWriter, RawFd, Read, Result, Write};

const DEFAULT_BUF_SIZE: usize = if cfg!(target_os = "espidf") {
    512
} else {
    8 * 1024
};

mod raw {
    use linux_syscalls::{syscall, Sysno};

    use crate::io::{AsRawFd, Errno, RawFd, Read, Result, Write};

    #[cfg(target_os = "macos")]
    const BUF_LIMIT: usize = libc::c_int::MAX as usize - 1;
    #[cfg(target_os = "linux")]
    const BUF_LIMIT: usize = isize::MAX as usize;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    const BUF_LIMIT: usize = libc::ssize_t::MAX as usize;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[inline(always)]
    fn _read(fd: RawFd, buf: &mut [u8]) -> Result<usize> {
        unsafe {
            Ok(handle_ebadf(
                syscall!(
                    Sysno::read,
                    fd,
                    buf.as_mut_ptr(),
                    core::cmp::min(buf.len(), BUF_LIMIT)
                ),
                0,
            )?)
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    #[inline(always)]
    fn _read(fd: RawFd, buf: &mut [u8]) -> Result<usize> {
        unsafe {
            Ok(handle_ebadf(
                match libc::read(
                    fd,
                    buf.as_mut_ptr().cast(),
                    core::cmp::min(buf.len(), BUF_LIMIT),
                ) {
                    -1 => Err(Errno::last_os_error()),
                    len => Ok(len as usize),
                },
                0,
            )?)
        }
    }

    fn read(fd: RawFd, buf: &mut [u8]) -> Result<usize> {
        loop {
            match _read(fd, buf) {
                Err(err) if err.kind() == crate::io::ErrorKind::Interrupted => (),
                other => return other,
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[inline(always)]
    fn _write(fd: RawFd, buf: &[u8]) -> Result<usize> {
        unsafe {
            Ok(handle_ebadf(
                syscall!([ro] Sysno::write, fd, buf.as_ptr(), core::cmp::min(buf.len(), BUF_LIMIT)),
                buf.len(),
            )?)
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    #[inline(always)]
    fn _write(fd: RawFd, buf: &[u8]) -> Result<usize> {
        unsafe {
            Ok(handle_ebadf(
                match libc::write(
                    fd,
                    buf.as_ptr().cast(),
                    core::cmp::min(buf.len(), BUF_LIMIT),
                ) {
                    -1 => Err(Errno::last_os_error()),
                    len => Ok(len as usize),
                },
                buf.len(),
            )?)
        }
    }

    fn write(fd: RawFd, buf: &[u8]) -> Result<usize> {
        loop {
            match _write(fd, buf) {
                Err(err) if err.kind() == crate::io::ErrorKind::Interrupted => (),
                other => return other,
            }
        }
    }

    pub struct Stdin;

    impl Read for Stdin {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            read(self.as_raw_fd(), buf)
        }
    }

    impl AsRawFd for Stdin {
        #[inline(always)]
        fn as_raw_fd(&self) -> RawFd {
            0
        }
    }

    pub struct Stdout;

    impl Write for Stdout {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            write(self.as_raw_fd(), buf)
        }

        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    impl AsRawFd for Stdout {
        #[inline]
        fn as_raw_fd(&self) -> RawFd {
            1
        }
    }

    pub struct Stderr;

    impl Write for Stderr {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            write(self.as_raw_fd(), buf)
        }

        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    impl AsRawFd for Stderr {
        #[inline]
        fn as_raw_fd(&self) -> RawFd {
            2
        }
    }

    fn handle_ebadf<T>(
        r: core::result::Result<T, Errno>,
        default: T,
    ) -> core::result::Result<T, Errno> {
        match r {
            Err(ref e) if *e == Errno::EBADF => Ok(default),
            r => r,
        }
    }
}

pub struct Stdin {
    inner: &'static FakeSyncCell<BufReader<raw::Stdin>>,
}

impl Read for Stdin {
    #[inline(always)]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.inner.get_mut().read(buf)
    }
}

impl BufRead for Stdin {
    #[inline(always)]
    fn fill_buf(&mut self) -> Result<&[u8]> {
        self.inner.get_mut().fill_buf()
    }

    #[inline(always)]
    fn consume(&mut self, amt: usize) {
        self.inner.get_mut().consume(amt)
    }
}

impl AsRawFd for Stdin {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.inner.get_ref().as_raw_fd()
    }
}

impl fmt::Debug for Stdin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stdin").finish_non_exhaustive()
    }
}

pub struct Stdout {
    inner: &'static FakeSyncCell<LineWriter<raw::Stdout>>,
}

impl Write for Stdout {
    #[inline(always)]
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.inner.get_mut().write(buf)
    }

    #[inline(always)]
    fn flush(&mut self) -> Result<()> {
        self.inner.get_mut().flush()
    }
}

impl AsRawFd for Stdout {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.inner.get_ref().as_raw_fd()
    }
}

impl fmt::Debug for Stdout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stdout").finish_non_exhaustive()
    }
}

pub struct Stderr {
    inner: &'static FakeSyncCell<raw::Stderr>,
}

impl Write for Stderr {
    #[inline(always)]
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.inner.get_mut().write(buf)
    }

    #[inline(always)]
    fn flush(&mut self) -> Result<()> {
        self.inner.get_mut().flush()
    }
}

impl AsRawFd for Stderr {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl fmt::Debug for Stderr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stderr").finish_non_exhaustive()
    }
}

struct FakeSyncCell<T: ?Sized>(T);

impl<T> FakeSyncCell<T> {
    #[inline]
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    #[inline(always)]
    #[allow(clippy::mut_from_ref, clippy::cast_ref_to_mut)]
    pub fn get_mut(&self) -> &mut T {
        unsafe { &mut *(&self.0 as *const T as *mut T) }
    }
}

impl<T> Deref for FakeSyncCell<T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for FakeSyncCell<T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

unsafe impl<T> Send for FakeSyncCell<T> {}
unsafe impl<T> Sync for FakeSyncCell<T> {}

static STDIN_INSTANCE: FakeSyncCell<OnceCell<FakeSyncCell<BufReader<raw::Stdin>>>> =
    FakeSyncCell::new(OnceCell::new());
static STDOUT_INSTANCE: FakeSyncCell<OnceCell<FakeSyncCell<LineWriter<raw::Stdout>>>> =
    FakeSyncCell::new(OnceCell::new());
static mut DTOR_REGISTERED: bool = false;

extern "C" fn dtor() {
    if let Some(inner) = STDOUT_INSTANCE.get() {
        let _ = inner.get_mut().flush();
    }
}

fn register_dtor() {
    if unsafe { !DTOR_REGISTERED } {
        unsafe { DTOR_REGISTERED = true };
        let _ = crate::process::atexit(dtor);
    }
}

#[must_use]
pub fn stdin() -> Stdin {
    Stdin {
        inner: STDIN_INSTANCE.get_or_init(|| {
            FakeSyncCell::new(BufReader::with_capacity(DEFAULT_BUF_SIZE, raw::Stdin))
        }),
    }
}

#[must_use]
pub fn stdout() -> Stdout {
    Stdout {
        inner: STDOUT_INSTANCE.get_or_init(|| {
            register_dtor();
            FakeSyncCell::new(LineWriter::new(raw::Stdout))
        }),
    }
}

#[must_use]
pub fn stderr() -> Stderr {
    static INSTANCE: FakeSyncCell<OnceCell<FakeSyncCell<raw::Stderr>>> =
        FakeSyncCell::new(OnceCell::new());

    Stderr {
        inner: INSTANCE.get_or_init(|| FakeSyncCell::new(raw::Stderr)),
    }
}

fn print_to<T>(args: fmt::Arguments<'_>, global_s: fn() -> T, label: &str)
where
    T: Write,
{
    if let Err(e) = global_s().write_fmt(args) {
        panic!("failed printing to {}: {}", label, e);
    }
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments<'_>) {
    print_to(args, stdout, "stdout")
}

#[doc(hidden)]
pub fn _eprint(args: fmt::Arguments<'_>) {
    print_to(args, stderr, "stderr")
}
