use crate::{
    ffi::CStr,
    io::{AsRawFd, BufRead, BufReader, BufWriter, RawFd, Read, Write},
};

use alloc_crate::{rc::Rc, vec::Vec};
use core::fmt;

use super::{
    fs::{File, OpenOptions},
    io,
};

use tty_info::TtyInfo;

pub struct TtyIn {
    pub(crate) info: Rc<TtyInfo>,
    pub(crate) inner: BufReader<File>,
}

pub struct TtyOut {
    pub(crate) info: Rc<TtyInfo>,
    pub(crate) inner: BufWriter<File>,
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

impl TtyIn {
    pub fn open(info: Rc<TtyInfo>) -> io::Result<Self> {
        let inner = BufReader::new(OpenOptions::new().read(true).open_cstr(info.path())?);
        Ok(Self { info, inner })
    }

    #[inline]
    pub fn path(&self) -> &CStr {
        self.info.path()
    }

    #[inline]
    pub fn name(&self) -> &CStr {
        self.info.name()
    }

    #[inline]
    pub fn c_readline(&mut self, timeout: u32) -> io::Result<secure_read::CBuffer> {
        secure_read::secure_read(self, secure_read::CBuffer::new(), timeout)
    }

    #[inline]
    pub fn c_readline_noecho(&mut self, timeout: u32) -> io::Result<secure_read::CBuffer> {
        secure_read::secure_read_noecho(self, secure_read::CBuffer::new(), timeout)
    }
}

impl AsRawFd for TtyIn {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.inner.get_ref().as_raw_fd()
    }
}

impl Read for TtyIn {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> crate::io::Result<usize> {
        self.inner.read(buf)
    }

    #[inline]
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> crate::io::Result<usize> {
        self.inner.read_to_end(buf)
    }

    #[inline]
    fn read_exact(&mut self, buf: &mut [u8]) -> crate::io::Result<()> {
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
    fn fill_buf(&mut self) -> crate::io::Result<&[u8]> {
        self.inner.fill_buf()
    }

    #[inline]
    fn consume(&mut self, amt: usize) {
        self.inner.consume(amt)
    }
}

impl TtyOut {
    pub fn open(info: Rc<TtyInfo>) -> io::Result<Self> {
        let inner = BufWriter::new(OpenOptions::new().write(true).open_cstr(info.path())?);
        Ok(Self { info, inner })
    }

    #[inline]
    pub fn path(&self) -> &CStr {
        self.info.path()
    }

    #[inline]
    pub fn name(&self) -> &CStr {
        self.info.name()
    }
}

impl AsRawFd for TtyOut {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.inner.get_ref().as_raw_fd()
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
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.inner.write_all(buf)
    }

    #[inline]
    fn write_fmt(&mut self, fmt: core::fmt::Arguments<'_>) -> io::Result<()> {
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

impl Drop for TtyIn {
    /// Consume input and zeroize the buffer
    fn drop(&mut self) {
        let _holder = secure_read::nonblock(self);

        let mut max_len = self.inner.buffer().len();
        self.inner.consume(max_len);
        while {
            match self.inner.fill_buf() {
                Err(err) if err.kind() == io::ErrorKind::Interrupted => true,
                Err(_) => false,
                Ok(_) => {
                    let l = self.inner.buffer().len();
                    self.inner.consume(l);
                    max_len = max_len.max(l);
                    true
                }
            }
        } {}

        unsafe {
            core::slice::from_raw_parts_mut(self.inner.buffer().as_ptr() as *mut u8, max_len)
        }
        .fill(0);
    }
}
