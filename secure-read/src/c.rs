use core::{
    borrow::{Borrow, BorrowMut},
    fmt, mem,
    ops::{ControlFlow, Deref, DerefMut},
    ptr, slice,
};

#[inline]
fn nonnull<O, T>(ptr: *mut O) -> *mut T {
    if ptr.is_null() {
        panic!("allocation failed");
    }
    ptr.cast()
}

unsafe fn realloc<T>(ptr: *mut T, size: usize) -> *mut T {
    if size == 0 {
        if !ptr.is_null() {
            libc::free(ptr.cast());
        }
        ptr::null_mut()
    } else {
        nonnull(if ptr.is_null() {
            libc::malloc(size * mem::size_of::<T>())
        } else {
            libc::realloc(ptr.cast(), size * mem::size_of::<T>())
        })
    }
}

pub struct CBuffer {
    ptr: *mut u8,
    capacity: usize,
    len: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct InvalidZeroCharacter;

impl fmt::Display for InvalidZeroCharacter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "found character 0")
    }
}

impl From<InvalidZeroCharacter> for std::io::Error {
    #[inline]
    fn from(_value: InvalidZeroCharacter) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, "found character 0")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidZeroCharacter {}

impl CBuffer {
    #[inline]
    pub fn new() -> Self {
        Self {
            ptr: ptr::null_mut(),
            capacity: 0,
            len: 0,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    #[inline]
    pub fn as_ptr(&self) -> *mut i8 {
        if self.is_empty() {
            ptr::null_mut()
        } else {
            self.ptr.cast()
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.ptr, self.len()) }
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.ptr, self.len()) }
    }

    pub unsafe fn into_raw_parts(mut self) -> (*mut i8, usize) {
        if self.is_empty() {
            (ptr::null_mut(), 0)
        } else {
            let len = self.len() + 1;
            if len != self.capacity {
                slice::from_raw_parts_mut(self.ptr.add(len), self.capacity - len).fill(0);
                self.ptr = realloc(self.ptr, len);
            }
            let res = (self.ptr.cast(), self.len);
            mem::forget(self);
            res
        }
    }

    pub unsafe fn from_raw_parts(ptr: *mut i8, len: usize, capacity: usize) -> Self {
        Self {
            ptr: ptr.cast(),
            len,
            capacity,
        }
    }

    #[inline]
    pub unsafe fn leak(self) -> *mut i8 {
        self.into_raw_parts().0
    }

    #[inline]
    pub unsafe fn set_len(&mut self, new_len: usize) {
        self.len = new_len;
    }

    pub fn push_slice(&mut self, b: &[u8]) {
        let new_len = self.len() + b.len();
        let new_size = new_len + 1;
        if new_size > self.capacity() {
            unsafe {
                self.ptr = realloc(self.ptr, new_size);
                self.capacity = new_size;
            }
        }

        unsafe {
            ptr::copy_nonoverlapping(b.as_ptr(), self.ptr.add(self.len()), b.len());
            *self.ptr.add(new_len) = 0;
            self.set_len(new_len);
        }
    }

    fn normalize(&mut self) {
        if let Some(last2) = self
            .len()
            .checked_sub(2)
            .map(|p| unsafe { self.as_mut_slice().get_unchecked_mut(p..) })
        {
            if last2 == b"\r\n" {
                unsafe {
                    ptr::copy_nonoverlapping(b"\n\0".as_slice().as_ptr(), last2.as_mut_ptr(), 2);
                    self.set_len(self.len() - 1);
                }
            }
        } else if let Some(c) = self.as_mut_slice().last_mut() {
            if *c == b'\r' {
                *c = b'\n';
            }
        }
    }

    #[inline]
    pub fn truncate(&mut self, pos: usize) {
        if pos < self.len {
            self.len = pos;
        }
    }

    pub fn push(&mut self, c: u8) {
        unsafe {
            if self.ptr.is_null() {
                self.len = 0;
                self.capacity = 10;
                self.ptr = libc::malloc(self.capacity) as *mut u8;
            }

            if self.len == self.capacity {
                self.capacity += 10;
                self.ptr = libc::realloc(self.ptr as *mut _, self.capacity) as *mut u8;
            }

            *self.ptr.add(self.len) = c;
            self.len += 1;
        }
    }

    pub fn shrink_to_fit(&mut self) {
        if self.len != self.capacity && !self.ptr.is_null() {
            self.capacity = self.len;
            self.ptr = unsafe { libc::realloc(self.ptr as *mut _, self.capacity) as *mut u8 };
        }
    }

    pub fn leak_c_string(mut self) -> *mut u8 {
        self.push(b'\0');
        self.shrink_to_fit();
        let res = self.ptr;
        mem::forget(self);
        res
    }
}

impl Drop for CBuffer {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                slice::from_raw_parts_mut(self.ptr, self.capacity).fill(0);
                libc::free(self.ptr.cast());
            }
        }
    }
}

impl Default for CBuffer {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for CBuffer {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl DerefMut for CBuffer {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl Borrow<[u8]> for CBuffer {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self.as_slice()
    }
}

impl BorrowMut<[u8]> for CBuffer {
    #[inline]
    fn borrow_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl AsRef<[u8]> for CBuffer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsMut<[u8]> for CBuffer {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl super::FeedRead for CBuffer {
    type Error = InvalidZeroCharacter;

    fn feed(
        &mut self,
        mut buf: &[u8],
    ) -> Result<core::ops::ControlFlow<usize, usize>, Self::Error> {
        let mut skipped = 0;
        loop {
            match memchr::memchr3(b'\0', b'\n', b'\x15', buf) {
                Some(pos) => match unsafe { *buf.get_unchecked(pos) } {
                    b'\0' => return Err(InvalidZeroCharacter),
                    b'\n' => unsafe {
                        let mut len = pos + 1;
                        self.push_slice(buf.get_unchecked(..len));
                        self.normalize();
                        if matches!(buf.get(len).copied(), Some(b'\r')) {
                            len += 1;
                        }
                        return Ok(ControlFlow::Break(skipped + len));
                    },
                    b'\x15' => unsafe {
                        self.set_len(0);
                        let len = pos + 1;
                        skipped += len;
                        buf = buf.get_unchecked(len..);
                    },
                    _ => unreachable!(),
                },
                None => {
                    self.push_slice(buf);
                    return Ok(ControlFlow::Continue(skipped + buf.len()));
                }
            }
        }
    }
}
