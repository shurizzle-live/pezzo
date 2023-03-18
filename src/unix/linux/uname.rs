use std::{ffi::CStr, fmt, io, mem::MaybeUninit};

use syscalls::{syscall, Sysno};

#[allow(non_camel_case_types)]
pub struct utsname {
    pub sysname: [u8; 65],
    pub nodename: [u8; 65],
    pub release: [u8; 65],
    pub version: [u8; 65],
    pub machine: [u8; 65],
    pub domainname: [u8; 65],
}

impl utsname {
    #[inline]
    pub fn sysname(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.sysname.as_ptr() as *const _) }
    }

    #[inline]
    pub fn nodename(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.nodename.as_ptr() as *const _) }
    }

    #[inline]
    pub fn release(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.release.as_ptr() as *const _) }
    }

    #[inline]
    pub fn version(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.version.as_ptr() as *const _) }
    }

    #[inline]
    pub fn machine(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.machine.as_ptr() as *const _) }
    }

    #[inline]
    pub fn domainname(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.domainname.as_ptr() as *const _) }
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
        syscall!(Sysno::uname, buf.as_mut_ptr())?;
        Ok(buf.assume_init())
    }
}
