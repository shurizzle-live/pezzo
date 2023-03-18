use std::{
    fmt,
    fs::File,
    io::{self, BufRead, BufReader, BufWriter, Read, Write},
    os::fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd, RawFd},
    path::{Path, PathBuf},
    sync::Arc,
};

use zeroize::Zeroizing;

pub struct TtyInfo {
    pub(crate) path: Arc<PathBuf>,
    pub(crate) name: Arc<Box<str>>,
}

pub struct TtyIn {
    path: Arc<PathBuf>,
    name: Arc<Box<str>>,
    inner: BufReader<File>,
}

pub struct TtyOut {
    path: Arc<PathBuf>,
    name: Arc<Box<str>>,
    inner: BufWriter<File>,
}

impl fmt::Debug for TtyInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TtyInfo")
            .field("path", &self.path())
            .field("name", &self.name())
            .finish()
    }
}

impl fmt::Debug for TtyIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        pub struct B(usize, usize);
        impl fmt::Debug for B {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}/{}", self.0, self.1)
            }
        }

        f.debug_struct("TtyIn")
            .field("path", &self.path())
            .field("name", &self.name())
            .field("fd", &self.as_raw_fd())
            .field("read", &true)
            .field("write", &false)
            .field(
                "buffer",
                &B(self.inner.buffer().len(), self.inner.capacity()),
            )
            .finish()
    }
}

impl fmt::Debug for TtyOut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        pub struct B(usize, usize);
        impl fmt::Debug for B {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}/{}", self.0, self.1)
            }
        }

        f.debug_struct("TtyOut")
            .field("path", &self.path())
            .field("name", &self.name())
            .field("fd", &self.as_raw_fd())
            .field("read", &false)
            .field("write", &true)
            .field(
                "buffer",
                &B(self.inner.buffer().len(), self.inner.capacity()),
            )
            .finish()
    }
}

impl TtyInfo {
    #[inline]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn input(&self) -> io::Result<TtyIn> {
        let fd = File::options()
            .read(true)
            .write(false)
            .append(false)
            .create(false)
            .truncate(false)
            .create_new(false)
            .open(self.path())?
            .into_raw_fd();
        let f = unsafe { File::from_raw_fd(fd) };

        Ok(TtyIn {
            path: Arc::clone(&self.path),
            name: Arc::clone(&self.name),
            inner: BufReader::new(f),
        })
    }

    pub fn output(&self) -> io::Result<TtyOut> {
        let fd = File::options()
            .read(false)
            .write(true)
            .append(false)
            .create(false)
            .truncate(false)
            .create_new(false)
            .open(self.path())?
            .into_raw_fd();
        let f = unsafe { File::from_raw_fd(fd) };

        Ok(TtyOut {
            path: Arc::clone(&self.path),
            name: Arc::clone(&self.name),
            inner: BufWriter::new(f),
        })
    }
}

impl TtyIn {
    #[inline]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn read_password(&mut self) -> io::Result<Zeroizing<Box<[u8]>>> {
        fn normalize_line(buf: &mut Vec<u8>) {
            if buf.ends_with(b"\n") {
                buf.pop();
            }
            if buf.ends_with(b"\r") {
                buf.pop();
            }

            if let Some(i) = memchr::memrchr(b'\x15', buf.as_slice()) {
                unsafe {
                    let dst = buf.as_mut_ptr() as *mut u8;
                    let src = buf.as_ptr().add(i + 1) as *const u8;
                    let len = buf.len() - i - 1;
                    std::ptr::copy(src, dst, len);
                    std::slice::from_raw_parts_mut(buf.as_mut_ptr().add(len), buf.len() - len)
                        .fill(0);
                    buf.set_len(len);
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        let _holder = crate::unix::common::noecho::noecho(self)?;
        #[cfg(target_os = "linux")]
        let _holder = crate::unix::linux::noecho::noecho(self)?;

        let mut buf = Vec::<u8>::new();
        self.read_until(b'\n', &mut buf)?;
        normalize_line(&mut buf);

        Ok(Zeroizing::new(buf.into_boxed_slice()))
    }
}

impl AsRawFd for TtyIn {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.inner.get_ref().as_raw_fd()
    }
}

impl AsFd for TtyIn {
    #[inline]
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.get_ref().as_fd()
    }
}

impl Read for TtyIn {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }

    #[inline]
    fn read_vectored(&mut self, bufs: &mut [std::io::IoSliceMut<'_>]) -> std::io::Result<usize> {
        self.inner.read_vectored(bufs)
    }

    #[inline]
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> std::io::Result<usize> {
        self.inner.read_to_end(buf)
    }

    #[inline]
    fn read_to_string(&mut self, buf: &mut String) -> std::io::Result<usize> {
        self.inner.read_to_string(buf)
    }

    #[inline]
    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        self.inner.read_exact(buf)
    }

    #[inline]
    fn by_ref(&mut self) -> &mut Self
    where
        Self: Sized,
    {
        self
    }
}

impl BufRead for TtyIn {
    #[inline]
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        self.inner.fill_buf()
    }

    #[inline]
    fn consume(&mut self, amt: usize) {
        self.inner.consume(amt)
    }

    #[inline]
    fn read_until(&mut self, byte: u8, buf: &mut Vec<u8>) -> std::io::Result<usize> {
        self.inner.read_until(byte, buf)
    }

    #[inline]
    fn read_line(&mut self, buf: &mut String) -> std::io::Result<usize> {
        self.inner.read_line(buf)
    }
}

impl TtyOut {
    #[inline]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl AsRawFd for TtyOut {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.inner.get_ref().as_raw_fd()
    }
}

impl AsFd for TtyOut {
    #[inline]
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.get_ref().as_fd()
    }
}

impl Write for TtyOut {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    #[inline]
    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.inner.write_vectored(bufs)
    }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.inner.write_all(buf)
    }

    #[inline]
    fn write_fmt(&mut self, fmt: std::fmt::Arguments<'_>) -> io::Result<()> {
        self.inner.write_fmt(fmt)
    }

    #[inline]
    fn by_ref(&mut self) -> &mut Self
    where
        Self: Sized,
    {
        self
    }
}
