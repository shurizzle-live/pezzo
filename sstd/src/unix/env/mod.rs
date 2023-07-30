use crate::ffi::{CStr, CString};
use alloc_crate::vec::Vec;
use core::iter::FusedIterator;

mod builder;
mod var_name;

pub use builder::*;
pub use var_name::*;

#[used]
static mut ARGS: &[*const u8] = &[];
#[used]
static mut ENV: *const *const u8 = core::ptr::null();

#[allow(clippy::missing_safety_doc)]
pub unsafe fn init(argc: isize, argv: *const *const u8, envp: *const *const u8) {
    ARGS = core::slice::from_raw_parts(argv, argc as _);
    ENV = envp;
    #[cfg(target_os = "linux")]
    linux_syscalls::init_from_environ(envp);
}

pub fn args() -> &'static [*const u8] {
    unsafe { ARGS }
}

pub(self) fn strip_var_name(mut s: *const u8, pref: &VarName) -> Option<*const u8> {
    unsafe {
        if !pref.is_empty() {
            let mut ptr = pref.as_ptr();
            let end = ptr.add(pref.len() - 1);

            loop {
                if *s != *ptr {
                    return None;
                }

                s = s.add(1);
                if ptr == end {
                    break;
                }
                ptr = ptr.add(1);
            }
        }

        match *s {
            b'=' => Some(s.add(1)),
            0 => Some(s),
            _ => None,
        }
    }
}

pub fn var(name: &VarName) -> Option<&'static CStr> {
    unsafe {
        if ENV.is_null() {
            return None;
        }
        let mut ptr = ENV;
        while !(*ptr).is_null() {
            if let Some(var) = strip_var_name(*ptr, name) {
                return Some(CStr::from_ptr(var.cast()));
            }
            ptr = ptr.add(1);
        }
        None
    }
}

pub struct Vars(*const *const u8);

impl Iterator for Vars {
    type Item = (&'static VarName, &'static CStr);

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_null() {
            return None;
        }

        unsafe {
            if (*self.0).is_null() {
                self.0 = core::ptr::null();
                return None;
            }

            let name = *self.0;
            let mut ptr = *self.0;
            self.0 = self.0.add(1);
            loop {
                if *ptr == 0 {
                    return Some((
                        VarName::from_raw_parts(name, (ptr as usize) - (name as usize)),
                        CStr::from_ptr(ptr.cast()),
                    ));
                }

                if *ptr == b'=' {
                    return Some((
                        VarName::from_raw_parts(name, (ptr as usize) - (name as usize)),
                        CStr::from_ptr(ptr.add(1).cast()),
                    ));
                }

                ptr = ptr.add(1);
            }
        }
    }
}

impl FusedIterator for Vars {}

pub fn vars() -> Vars {
    Vars(unsafe { ENV })
}

#[cfg(target_os = "linux")]
fn getcwd(buf: &mut Vec<u8>) -> crate::io::Result<()> {
    use linux_stat::Errno;
    use linux_syscalls::{syscall, Sysno};

    if buf.capacity() == 0 {
        buf.reserve(1);
    }

    unsafe {
        buf.set_len(0);

        loop {
            match syscall!(Sysno::getcwd, buf.as_ptr(), buf.capacity()) {
                Err(Errno::ERANGE) => {
                    buf.reserve(buf.capacity().max(1) * 2);
                }
                Err(err) => return Err(err.into()),
                Ok(len) => {
                    buf.set_len(len);
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn getcwd(buf: &mut Vec<u8>) -> crate::io::Result<()> {
    if buf.capacity() == 0 {
        buf.reserve(1);
    }

    unsafe {
        buf.set_len(0);

        while libc::getcwd(buf.as_mut_ptr().cast(), buf.capacity()).is_null() {
            let err = crate::io::Errno::last_os_error();

            if err != crate::io::Errno::ERANGE {
                return Err(err.into());
            }

            buf.reserve(buf.capacity().max(1) * 2);
        }
    }

    Ok(())
}

pub fn current_dir_in(buf: &mut Vec<u8>) -> crate::io::Result<()> {
    getcwd(buf)?;

    if buf.last().map(|&c| c != 0).unwrap_or(true) {
        buf.reserve_exact(1);
        buf.push(0);
    }

    Ok(())
}

pub fn current_dir() -> crate::io::Result<CString> {
    let mut buf = Vec::new();
    current_dir_in(&mut buf)?;
    Ok(unsafe { CString::from_vec_with_nul_unchecked(buf) })
}

pub fn temp_dir() -> &'static CStr {
    #[cfg(target_os = "android")]
    const DEFAULT: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"/data/local/tmp\0") };
    #[cfg(not(target_os = "android"))]
    const DEFAULT: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"/tmp\0") };
    crate::env::var(unsafe { VarName::from_slice_unchecked(b"TMPDIR") }).unwrap_or(DEFAULT)
}
