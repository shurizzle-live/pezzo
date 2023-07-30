#[cfg(any(
    all(any(target_os = "linux", target_os = "android"), feature = "c"),
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "watchos",
        target_os = "tvos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    )
))]
#[path = "c_exit.rs"]
mod exit;

#[cfg(all(any(target_os = "linux", target_os = "android"), not(feature = "c")))]
#[path = "linux_bare_exit.rs"]
mod exit;

pub use exit::*;

use crate::{ffi::CString, io};

#[cfg(target_os = "linux")]
pub fn current_exe() -> io::Result<CString> {
    use crate::ffi::CStr;

    match crate::fs::read_link::<&'static CStr>(unsafe {
        CStr::from_bytes_with_nul_unchecked(b"/proc/self/exe\0")
    }) {
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => Err(io::Error::new_static(
            io::ErrorKind::Uncategorized,
            "no /proc/self/exe available. Is /proc mounted?",
        )),
        other => other,
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "tvos"
))]
pub fn current_exe() -> io::Result<CString> {
    use crate::vec::Vec;

    unsafe {
        let mut sz: u32 = 0;
        libc::_NSGetExecutablePath(core::ptr::null_mut(), &mut sz);
        if sz == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut v: Vec<u8> = Vec::with_capacity(sz as usize);
        let err = libc::_NSGetExecutablePath(v.as_mut_ptr() as *mut i8, &mut sz);
        if err != 0 {
            return Err(io::Error::last_os_error());
        }
        v.set_len(sz as usize - 1); // chop off trailing NUL
        Ok(CString::from_vec_unchecked(v))
    }
}

#[cfg(target_os = "openbsd")]
pub fn current_exe() -> io::Result<CString> {
    unsafe {
        let mut mib = [
            libc::CTL_KERN,
            libc::KERN_PROC_ARGS,
            libc::getpid(),
            libc::KERN_PROC_ARGV,
        ];
        let mib = mib.as_mut_ptr();
        let mut argv_len = 0;
        if libc::sysctl(
            mib,
            4,
            core::ptr::null_mut(),
            &mut argv_len,
            core::ptr::null_mut(),
            0,
        ) == -1
        {
            return Err(io::Error::last_os_error());
        }
        let mut argv = Vec::<*const libc::c_char>::with_capacity(argv_len as usize);
        if libc::sysctl(
            mib,
            4,
            argv.as_mut_ptr() as *mut _,
            &mut argv_len,
            core::ptr::null_mut(),
            0,
        ) == -1
        {
            return Err(io::Error::last_os_error());
        }
        argv.set_len(argv_len.min(1));
        let argv0 = argv.remove(0);
        if argv0.is_null() {
            return Err(io::Error::new_static(
                io::ErrorKind::Uncategorized,
                "no current exe available",
            ));
        }
        let argv0 = CStr::from_ptr(argv0);
        if argv0[0] == b'.' || argv0.iter().any(|b| *b == b'/') {
            crate::fs::canonicalize(argv0)
        } else {
            Ok(CString::from_vec_unchecked(argv0.to_bytes().to_vec()))
        }
    }
}

#[cfg(target_os = "netbsd")]
pub fn current_exe() -> io::Result<CString> {
    fn sysctl() -> io::Result<CString> {
        unsafe {
            let mib = [
                libc::CTL_KERN,
                libc::KERN_PROC_ARGS,
                -1,
                libc::KERN_PROC_PATHNAME,
            ];
            let mut path_len: usize = 0;
            if libc::sysctl(
                mib.as_ptr(),
                mib.len() as libc::c_uint,
                core::ptr::null_mut(),
                &mut path_len,
                core::ptr::null(),
                0,
            ) == -1
            {
                return Err(io::Error::last_os_error());
            }
            if path_len <= 1 {
                return Err(io::Error::new_static(
                    io::ErrorKind::Uncategorized,
                    "KERN_PROC_PATHNAME sysctl returned zero-length string",
                ));
            }
            let mut path: Vec<u8> = Vec::with_capacity(path_len);
            if libc::sysctl(
                mib.as_ptr(),
                mib.len() as libc::c_uint,
                path.as_ptr() as *mut libc::c_void,
                &mut path_len,
                core::ptr::null(),
                0,
            ) == -1
            {
                return Err(io::Error::last_os_error());
            }
            path.set_len(path_len - 1); // chop off NUL
            Ok(CString::from_vec_unchecked(path))
        }
    }
    fn procfs() -> io::Result<CString> {
        crate::fs::read_link(unsafe { CStr::from_bytes_with_nul_unchecked(b"/proc/curproc/exe\0") })
    }
    sysctl().or_else(|_| procfs())
}

#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
pub fn current_exe() -> io::Result<CString> {
    unsafe {
        let mut mib = [
            libc::CTL_KERN as libc::c_int,
            libc::KERN_PROC as libc::c_int,
            libc::KERN_PROC_PATHNAME as libc::c_int,
            -1 as libc::c_int,
        ];
        let mut sz = 0;
        if libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            core::ptr::null_mut(),
            &mut sz,
            core::ptr::null_mut(),
            0,
        ) == -1
            || sz == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut v: Vec<u8> = Vec::with_capacity(sz);
        if libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            v.as_mut_ptr() as *mut libc::c_void,
            &mut sz,
            core::ptr::null_mut(),
            0,
        ) == -1
            || sz == 0
        {
            return Err(io::Error::last_os_error());
        }
        v.set_len(sz - 1); // chop off trailing NUL
        Ok(CString::from_vec_unchecked(v))
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn id() -> u32 {
    use linux_syscalls::{raw_syscall, Sysno};

    unsafe { raw_syscall!([ro] Sysno::getpid) as u32 }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn id() -> u32 {
    unsafe { libc::getpid() as u32 }
}
