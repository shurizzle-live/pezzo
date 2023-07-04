pub(crate) trait ErrorExt {
    fn is_interrupted(&self) -> bool;
    fn would_block(&self) -> bool;
}

#[cfg(not(feature = "std"))]
mod imp {
    #[cfg(target_os = "linux")]
    pub use core::ffi::c_int as RawFd;
    use core::mem::MaybeUninit;
    #[cfg(not(target_os = "linux"))]
    pub use libc::c_int as RawFd;

    pub use crate::Errno as Error;

    pub type Result<T> = core::result::Result<T, Error>;

    /// A trait to extract the raw file descriptor from an underlying object.
    pub trait AsRawFd {
        /// Extracts the raw file descriptor.
        fn as_raw_fd(&self) -> RawFd;
    }

    impl AsRawFd for RawFd {
        #[inline]
        fn as_raw_fd(&self) -> RawFd {
            *self
        }
    }

    /// The Read trait allows for reading bytes from a source.
    pub trait Read {
        /// Pull some bytes from this source into the specified buffer, returning how many bytes were read.
        fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
    }

    /// A BufRead is a type of Reader which has an internal buffer, allowing it to perform extra ways of reading.
    pub trait BufRead: Read {
        /// Returns the contents of the internal buffer, filling it with more data
        /// from the inner reader if it is empty.
        fn fill_buf(&mut self) -> Result<&[u8]>;

        /// Tells this buffer that `amt` bytes have been consumed from the buffer,
        /// so they should no longer be returned in calls to `read`.
        fn consume(&mut self, amt: usize);
    }

    impl super::ErrorExt for Error {
        #[inline]
        fn is_interrupted(&self) -> bool {
            *self == Error::EINTR
        }

        #[inline]
        fn would_block(&self) -> bool {
            *self == Error::EAGAIN
        }
    }

    impl Read for &[u8] {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            let nread = core::cmp::min(self.len(), buf.len());
            unsafe { core::ptr::copy_nonoverlapping(self.as_ptr(), buf.as_mut_ptr(), nread) };
            Ok(nread)
        }
    }

    impl Read for &str {
        #[inline]
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            self.as_bytes().read(buf)
        }
    }

    const DEFAULT_BUF_SIZE: usize = 8 * 1024;

    pub struct BufReader<R, const N: usize = DEFAULT_BUF_SIZE> {
        inner: R,
        buf: MaybeUninit<[u8; N]>,
        pos: usize,
        len: usize,
    }

    impl<R: Read, const N: usize> BufReader<R, N> {
        #[inline]
        pub const fn new(inner: R) -> Self {
            Self {
                inner,
                buf: MaybeUninit::uninit(),
                pos: 0,
                len: 0,
            }
        }
    }

    impl<R, const N: usize> BufReader<R, N> {
        #[inline]
        pub fn get_ref(&self) -> &R {
            &self.inner
        }

        #[inline]
        pub fn get_mut(&mut self) -> &mut R {
            &mut self.inner
        }

        #[inline]
        pub fn buffer(&self) -> &[u8] {
            unsafe { core::slice::from_raw_parts(self.buf.as_ptr() as *const u8, self.len) }
        }

        #[inline]
        pub const fn capacity(&self) -> usize {
            N
        }

        #[inline]
        pub fn into_inner(self) -> R {
            self.inner
        }

        #[inline]
        fn discard_buffer(&mut self) {
            self.len = 0;
            self.pos = 0;
        }
    }

    impl<R: Read, const N: usize> Read for BufReader<R, N> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            if self.pos == self.len && buf.len() > self.capacity() {
                self.discard_buffer();
                return self.inner.read(buf);
            }

            let nread = {
                let mut rem = self.fill_buf()?;
                rem.read(buf)?
            };
            self.consume(nread);
            Ok(nread)
        }
    }

    impl<R: Read, const N: usize> BufRead for BufReader<R, N> {
        fn fill_buf(&mut self) -> Result<&[u8]> {
            if self.pos >= self.len {
                let buf =
                    unsafe { core::slice::from_raw_parts_mut(self.buf.as_mut_ptr() as *mut u8, N) };
                let nread = self.inner.read(buf)?;
                self.pos = 0;
                self.len = nread;
            }

            Ok(self.buffer())
        }

        #[inline]
        fn consume(&mut self, amt: usize) {
            self.pos = core::cmp::min(self.pos + amt, self.len);
        }
    }
}

#[cfg(feature = "std")]
mod imp {
    pub use std::io::{BufRead, BufReader, Error, Read, Result};
    pub use std::os::fd::{AsRawFd, RawFd};

    impl super::ErrorExt for Error {
        #[inline]
        fn is_interrupted(&self) -> bool {
            self.kind() == std::io::ErrorKind::Interrupted
        }

        #[inline]
        fn would_block(&self) -> bool {
            self.kind() == std::io::ErrorKind::WouldBlock
        }
    }
}

pub use imp::*;
