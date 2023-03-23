use std::{mem, ptr};

mod noecho;
mod nonblock;
mod uname;

pub use noecho::noecho;
pub use nonblock::nonblock;
pub use uname::uname;

pub struct CBuffer {
    pub(crate) len: usize,
    pub(crate) cap: usize,
    pub(crate) data: *mut u8,
}

impl CBuffer {
    pub fn new() -> Self {
        Self {
            len: 0,
            cap: 0,
            data: ptr::null_mut(),
        }
    }

    pub fn push(&mut self, c: u8) {
        unsafe {
            if self.data.is_null() {
                self.len = 0;
                self.cap = 10;
                self.data = libc::malloc(self.cap) as *mut u8;
            }

            if self.len == self.cap {
                self.cap += 10;
                self.data = libc::realloc(self.data as *mut _, self.cap) as *mut u8;
            }

            *self.data.add(self.len) = c;
            self.len += 1;
        }
    }

    pub fn push_slice(&mut self, c: &[u8]) {
        unsafe {
            let new_cap = self.len + c.len();
            if self.cap < new_cap {
                self.cap = new_cap;
                self.data = libc::realloc(self.data as *mut _, self.cap) as *mut u8;
            }
            ptr::copy(c.as_ptr(), self.data.add(self.len), c.len());
            self.len = new_cap;
        }
    }

    pub fn shrink_to_fit(&mut self) {
        if self.len != self.cap && !self.data.is_null() {
            self.cap = self.len;
            self.data = unsafe { libc::realloc(self.data as *mut _, self.cap) as *mut u8 };
        }
    }

    pub fn clear(&mut self) {
        if !self.data.is_null() {
            unsafe {
                std::slice::from_raw_parts_mut(self.data, self.len).fill(0);
                self.len = 0;
            }
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.data, self.len) }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn leak_c_string(mut self) -> *mut u8 {
        self.push(b'\0');
        self.shrink_to_fit();
        let res = self.data;
        mem::forget(self);
        res
    }
}

impl Drop for CBuffer {
    fn drop(&mut self) {
        unsafe {
            if !self.data.is_null() {
                libc::free(self.data as *mut _)
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
