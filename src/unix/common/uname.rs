use std::{ffi::CStr, fmt, io, mem::MaybeUninit};

#[repr(transparent)]
#[allow(non_camel_case_types)]
pub struct utsname(libc::utsname);

impl utsname {
    #[inline]
    pub fn sysname(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.0.sysname.as_ptr() as *const _) }
    }

    #[inline]
    pub fn nodename(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.0.nodename.as_ptr() as *const _) }
    }

    #[inline]
    pub fn release(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.0.release.as_ptr() as *const _) }
    }

    #[inline]
    pub fn version(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.0.version.as_ptr() as *const _) }
    }

    #[inline]
    pub fn machine(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.0.machine.as_ptr() as *const _) }
    }

    #[inline]
    pub fn domainname(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.0.domainname.as_ptr() as *const _) }
    }
}

impl fmt::Debug for utsname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("utsname")
            .field("sysname", &self.sysname())
            .field("nodename", &self.nodename())
            .field("release", &self.release())
            .field("version", &self.version())
            .field("machine", &self.machine())
            .field("domainname", &self.domainname())
            .finish()
    }
}

pub fn uname() -> io::Result<utsname> {
    unsafe {
        let mut buf = MaybeUninit::<utsname>::uninit();
        if libc::uname(buf.as_mut_ptr() as *mut _) != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(buf.assume_init())
        }
    }
}
