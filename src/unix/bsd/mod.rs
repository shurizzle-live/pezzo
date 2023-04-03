#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

use std::{
    borrow::{Borrow, BorrowMut},
    ffi::CStr,
    io, mem,
    ops::{Deref, DerefMut},
    os::raw::c_void,
    path::PathBuf,
    ptr,
    sync::Arc,
};

fn proc_info<T>(mibs: &mut [libc::c_int]) -> io::Result<CBox<T>> {
    unsafe {
        let mut ki_proc: *mut T = ptr::null_mut();
        let mut size = mem::size_of::<T>();

        let mut rc;
        loop {
            {
                size += size / 10;
                let kp = libc::realloc(ki_proc as *mut c_void, size) as *mut T;
                if kp.is_null() {
                    rc = -1;
                    break;
                }
                ki_proc = kp;
            }

            rc = libc::sysctl(
                mibs.as_mut_ptr(),
                mibs.len() as u32,
                ki_proc as *mut _,
                &mut size,
                ptr::null_mut(),
                0,
            );

            if rc != -1 || *libc::__error() != libc::ENOMEM {
                break;
            }
        }

        if rc == -1 {
            let err = io::Error::last_os_error();
            if !ki_proc.is_null() {
                libc::free(ki_proc as *mut _);
            }
            Err(err)
        } else {
            Ok(CBox::from_raw(ki_proc))
        }
    }
}

pub struct CBox<T>(*mut T);

impl<T> CBox<T> {
    #[inline]
    pub unsafe fn from_raw(raw: *mut T) -> Self {
        Self(raw)
    }
}

impl<T> Deref for CBox<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.0 }
    }
}

impl<T> DerefMut for CBox<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.0 }
    }
}

impl<T> Borrow<T> for CBox<T> {
    #[inline]
    fn borrow(&self) -> &T {
        &*self
    }
}

impl<T> BorrowMut<T> for CBox<T> {
    #[inline]
    fn borrow_mut(&mut self) -> &mut T {
        &mut *self
    }
}

impl<T> AsRef<T> for CBox<T> {
    #[inline]
    fn as_ref(&self) -> &T {
        &*self
    }
}

impl<T> AsMut<T> for CBox<T> {
    #[inline]
    fn as_mut(&mut self) -> &mut T {
        &mut *self
    }
}

impl<T> Drop for CBox<T> {
    fn drop(&mut self) {
        unsafe {
            libc::free(self.0 as *mut libc::c_void);
        }
    }
}

extern "C" {
    fn devname(dev: libc::dev_t, r#type: libc::mode_t) -> *const i8;
}

impl super::tty::TtyInfo {
    pub fn for_ttyno(ttyno: u32) -> io::Result<Self> {
        unsafe {
            if ttyno == mem::transmute::<_, u32>(-1) {
                return Err(io::Error::new(io::ErrorKind::NotFound, "invalid tty"));
            }

            let name = devname(ttyno as _, libc::S_IFCHR);
            if name.is_null() {
                return Err(io::Error::new(io::ErrorKind::NotFound, "invalid tty"));
            }

            let name = CStr::from_ptr(name).to_string_lossy();
            let mut path: PathBuf = PathBuf::from("/dev");
            path.push(&*name);

            Ok(Self {
                path: Arc::new(path),
                name: Arc::new(name.to_string().into_boxed_str()),
            })
        }
    }
}

pub mod time {
    use std::mem::{self, MaybeUninit};

    pub fn now() -> u64 {
        unsafe {
            let mut time = MaybeUninit::<libc::timespec>::uninit();
            libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, time.as_mut_ptr());
            let time = time.assume_init();
            mem::transmute(time.tv_sec)
        }
    }
}
