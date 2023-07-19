use core::{cmp, fmt, mem, ptr};

pub use no_std_io::io::{BufRead, Error, ErrorKind, Read, Result, Seek, SeekFrom, Write};
pub use secure_read::io::AsRawFd;
pub use secure_read::io::RawFd;

use alloc_crate::vec::Vec;

pub trait FromRawFd {
    /// # Safety
    unsafe fn from_raw_fd(fd: RawFd) -> Self;
}

#[cfg(target_os = "linux")]
pub fn from_raw_os_error(no: i32) -> Error {
    linux_syscalls::Errno::new(no).into()
}

#[cfg(not(target_os = "linux"))]
pub fn from_raw_os_error(no: i32) -> Error {
    use ErrorKind::*;
    match no {
        // libc::E2BIG => ArgumentListTooLong.into(),
        libc::EADDRINUSE => AddrInUse.into(),
        libc::EADDRNOTAVAIL => AddrNotAvailable.into(),
        // libc::EBUSY => ResourceBusy.into(),
        libc::ECONNABORTED => ConnectionAborted.into(),
        libc::ECONNREFUSED => ConnectionRefused.into(),
        libc::ECONNRESET => ConnectionReset.into(),
        // libc::EDEADLK => Deadlock.into(),
        // libc::EDQUOT => FilesystemQuotaExceeded.into(),
        libc::EEXIST => AlreadyExists.into(),
        // libc::EFBIG => FileTooLarge.into(),
        // libc::EHOSTUNREACH => HostUnreachable.into(),
        libc::EINTR => Interrupted.into(),
        libc::EINVAL => InvalidInput.into(),
        // libc::EISDIR => IsADirectory.into(),
        // libc::ELOOP => FilesystemLoop.into(),
        libc::ENOENT => NotFound.into(),
        // libc::ENOMEM => OutOfMemory.into(),
        // libc::ENOSPC => StorageFull.into(),
        // libc::ENOSYS => Unsupported.into(),
        // libc::EMLINK => TooManyLinks.into(),
        // libc::ENAMETOOLONG => InvalidFilename.into(),
        // libc::ENETDOWN => NetworkDown.into(),
        // libc::ENETUNREACH => NetworkUnreachable.into(),
        libc::ENOTCONN => NotConnected.into(),
        // libc::ENOTDIR => NotADirectory.into(),
        // libc::ENOTEMPTY => DirectoryNotEmpty.into(),
        libc::EPIPE => BrokenPipe.into(),
        // libc::EROFS => ReadOnlyFilesystem.into(),
        // libc::ESPIPE => NotSeekable.into(),
        // libc::ESTALE => StaleNetworkFileHandle.into(),
        libc::ETIMEDOUT => TimedOut.into(),
        // libc::ETXTBSY => ExecutableFileBusy.into(),
        // libc::EXDEV => CrossesDevices.into(),
        libc::EACCES | libc::EPERM => PermissionDenied.into(),

        // These two constants can have the same value on some systems,
        // but different values on others, so we can't use a match
        // clause
        x if x == libc::EAGAIN || x == libc::EWOULDBLOCK => WouldBlock.into(),

        x => ::no_std_io::io::Error::new(Uncategorized, x.description().unwrap_or("Unknown error")),
    }
}

#[inline]
pub fn last_os_error() -> Error {
    from_raw_os_error(unsafe { *crate::__errno() })
}

const DEFAULT_BUF_SIZE: usize = 8 * 1024;

pub struct BufReader<R: ?Sized> {
    buf: Vec<u8>,
    offset: usize,
    inner: R,
}

impl<R: Read> BufReader<R> {
    pub fn new(inner: R) -> Self {
        Self::with_capacity(DEFAULT_BUF_SIZE, inner)
    }

    pub fn with_capacity(capacity: usize, inner: R) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(capacity),
            offset: 0,
        }
    }
}

impl<R: ?Sized> BufReader<R> {
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    pub fn buffer(&self) -> &[u8] {
        unsafe { self.buf.as_slice().get_unchecked(self.offset..) }
    }

    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    pub fn into_inner(self) -> R
    where
        R: Sized,
    {
        self.inner
    }

    #[inline]
    fn discard_buffer(&mut self) {
        unsafe { self.buf.set_len(0) };
        self.offset = 0;
    }
}

impl<R: ?Sized + Seek> BufReader<R> {
    pub fn seek_relative(&mut self, offset: i64) -> Result<()> {
        let pos = self.offset as u64;
        if offset < 0 {
            if let Some(new_offset) = pos.checked_sub((-offset) as u64) {
                self.offset = new_offset as usize;
                return Ok(());
            }
        } else if let Some(new_pos) = pos.checked_add(offset as u64) {
            if new_pos <= self.buf.len() as u64 {
                self.offset = new_pos as usize;
                return Ok(());
            }
        }

        self.seek(SeekFrom::Current(offset)).map(drop)
    }
}

impl<R: ?Sized + Seek> Seek for BufReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        let result: u64;
        if let SeekFrom::Current(n) = pos {
            let remainder = (self.buf.len() - self.offset) as i64;
            if let Some(offset) = n.checked_sub(remainder) {
                result = self.inner.seek(SeekFrom::Current(offset))?;
            } else {
                self.inner.seek(SeekFrom::Current(-remainder))?;
                self.discard_buffer();
                result = self.inner.seek(SeekFrom::Current(n))?;
            }
        } else {
            result = self.inner.seek(pos)?;
        }
        self.discard_buffer();
        Ok(result)
    }
}

impl<R: ?Sized + Read> Read for BufReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.offset >= self.buf.len() && buf.len() >= self.capacity() {
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

impl<R: ?Sized + Read> BufRead for BufReader<R> {
    fn fill_buf(&mut self) -> Result<&[u8]> {
        if self.offset >= self.buf.len() {
            unsafe {
                let len = self.inner.read(core::slice::from_raw_parts_mut(
                    self.buf.as_mut_ptr(),
                    self.buf.capacity(),
                ))?;
                self.buf.set_len(len);
                self.offset = 0;
            }
        }
        Ok(self.buffer())
    }

    fn consume(&mut self, amt: usize) {
        self.offset = cmp::min(self.offset + amt, self.buf.len());
    }
}

impl<R> fmt::Debug for BufReader<R>
where
    R: ?Sized + fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("BufReader")
            .field("reader", &&self.inner)
            .field(
                "buffer",
                &format_args!("{}/{}", self.buf.len() - self.offset, self.capacity()),
            )
            .finish()
    }
}

pub struct BufWriter<W: ?Sized + Write> {
    buf: Vec<u8>,
    panicked: bool,
    inner: W,
}

pub struct WriterPanicked {
    buf: Vec<u8>,
}

impl WriterPanicked {
    #[must_use = "`self` will be dropped if the result is not used"]
    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }

    const DESCRIPTION: &'static str =
        "BufWriter inner writer panicked, what data remains unwritten is not known";
}

impl no_std_io::error::Error for WriterPanicked {}

impl fmt::Display for WriterPanicked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::DESCRIPTION)
    }
}

impl fmt::Debug for WriterPanicked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriterPanicked")
            .field(
                "buffer",
                &format_args!("{}/{}", self.buf.len(), self.buf.capacity()),
            )
            .finish()
    }
}

#[derive(Debug)]
pub struct IntoInnerError<W>(W, Error);

impl<W> IntoInnerError<W> {
    fn new(writer: W, error: Error) -> Self {
        Self(writer, error)
    }

    pub fn error(&self) -> &Error {
        &self.1
    }

    pub fn into_inner(self) -> W {
        self.0
    }

    pub fn into_error(self) -> Error {
        self.1
    }

    pub fn into_parts(self) -> (Error, W) {
        (self.1, self.0)
    }
}

impl<W> From<IntoInnerError<W>> for Error {
    fn from(iie: IntoInnerError<W>) -> Error {
        iie.1
    }
}

impl<W: Send + fmt::Debug> no_std_io::error::Error for IntoInnerError<W> {}

impl<W> fmt::Display for IntoInnerError<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error().fmt(f)
    }
}

impl<W: Write> BufWriter<W> {
    pub fn new(inner: W) -> Self {
        Self::with_capacity(DEFAULT_BUF_SIZE, inner)
    }

    pub fn with_capacity(capacity: usize, inner: W) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
            panicked: false,
            inner,
        }
    }

    pub fn into_inner(mut self) -> core::result::Result<W, IntoInnerError<BufWriter<W>>> {
        match self.flush_buf() {
            Err(e) => Err(IntoInnerError::new(self, e)),
            Ok(()) => Ok(self.into_parts().0),
        }
    }

    pub fn into_parts(mut self) -> (W, core::result::Result<Vec<u8>, WriterPanicked>) {
        let buf = mem::take(&mut self.buf);
        let buf = if !self.panicked {
            Ok(buf)
        } else {
            Err(WriterPanicked { buf })
        };

        let inner = unsafe { ptr::read(&self.inner) };
        mem::forget(self);

        (inner, buf)
    }
}

impl<W: ?Sized + Write> BufWriter<W> {
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    pub fn buffer(&self) -> &[u8] {
        &self.buf
    }

    pub fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    #[inline]
    unsafe fn write_to_buffer_unchecked(&mut self, buf: &[u8]) {
        debug_assert!(buf.len() <= self.spare_capacity());
        let old_len = self.buf.len();
        let buf_len = buf.len();
        let src = buf.as_ptr();
        let dst = self.buf.as_mut_ptr().add(old_len);
        ptr::copy_nonoverlapping(src, dst, buf_len);
        self.buf.set_len(old_len + buf_len);
    }

    #[inline]
    fn spare_capacity(&self) -> usize {
        self.buf.capacity() - self.buf.len()
    }

    fn flush_buf(&mut self) -> Result<()> {
        struct BufGuard<'a> {
            buffer: &'a mut Vec<u8>,
            written: usize,
        }

        impl<'a> BufGuard<'a> {
            fn new(buffer: &'a mut Vec<u8>) -> Self {
                Self { buffer, written: 0 }
            }

            fn remaining(&self) -> &[u8] {
                &self.buffer[self.written..]
            }

            fn consume(&mut self, amt: usize) {
                self.written += amt;
            }

            fn done(&self) -> bool {
                self.written >= self.buffer.len()
            }
        }

        impl Drop for BufGuard<'_> {
            fn drop(&mut self) {
                if self.written > 0 {
                    self.buffer.drain(..self.written);
                }
            }
        }

        let mut guard = BufGuard::new(&mut self.buf);
        while !guard.done() {
            self.panicked = true;
            let r = self.inner.write(guard.remaining());
            self.panicked = false;

            match r {
                Ok(0) => {
                    return Err(Error::new(
                        ErrorKind::WriteZero,
                        "failed to write the buffered data",
                    ));
                }
                Ok(n) => guard.consume(n),
                Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    #[cold]
    #[inline(never)]
    fn write_cold(&mut self, buf: &[u8]) -> Result<usize> {
        if buf.len() > self.spare_capacity() {
            self.flush_buf()?;
        }

        if buf.len() >= self.buf.capacity() {
            self.panicked = true;
            let r = self.get_mut().write(buf);
            self.panicked = false;
            r
        } else {
            unsafe {
                self.write_to_buffer_unchecked(buf);
            }

            Ok(buf.len())
        }
    }

    #[cold]
    #[inline(never)]
    fn write_all_cold(&mut self, buf: &[u8]) -> Result<()> {
        if buf.len() > self.spare_capacity() {
            self.flush_buf()?;
        }

        if buf.len() >= self.buf.capacity() {
            self.panicked = true;
            let r = self.get_mut().write_all(buf);
            self.panicked = false;
            r
        } else {
            unsafe {
                self.write_to_buffer_unchecked(buf);
            }

            Ok(())
        }
    }
}

impl<W: ?Sized + Write> Write for BufWriter<W> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if buf.len() < self.spare_capacity() {
            unsafe {
                self.write_to_buffer_unchecked(buf);
            }

            Ok(buf.len())
        } else {
            self.write_cold(buf)
        }
    }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        if buf.len() < self.spare_capacity() {
            unsafe {
                self.write_to_buffer_unchecked(buf);
            }

            Ok(())
        } else {
            self.write_all_cold(buf)
        }
    }

    fn flush(&mut self) -> Result<()> {
        self.flush_buf().and_then(|()| self.get_mut().flush())
    }
}

impl<W: ?Sized + Write> fmt::Debug for BufWriter<W>
where
    W: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("BufWriter")
            .field("writer", &&self.inner)
            .field(
                "buffer",
                &format_args!("{}/{}", self.buf.len(), self.buf.capacity()),
            )
            .finish()
    }
}

impl<W: ?Sized + Write + Seek> Seek for BufWriter<W> {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        self.flush_buf()?;
        self.get_mut().seek(pos)
    }
}

impl<W: ?Sized + Write> Drop for BufWriter<W> {
    fn drop(&mut self) {
        if !self.panicked {
            _ = self.flush_buf();
        }
    }
}
