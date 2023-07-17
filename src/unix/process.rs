use crate::{
    ffi::{CStr, CString},
    io,
};
use alloc_crate::{boxed::Box, rc::Rc, vec::Vec};

use tty_info::TtyInfo;

use super::IAMContext;

#[derive(Debug, Clone)]
pub struct User {
    pub(crate) name: Box<CStr>,
    pub(crate) id: u32,
}

#[derive(Debug, Clone)]
pub struct Group {
    pub(crate) name: Box<CStr>,
    pub(crate) id: u32,
}

impl User {
    #[inline]
    pub fn new(id: u32, name: Box<CStr>) -> User {
        User { id, name }
    }

    #[inline]
    pub fn name(&self) -> &CStr {
        self.name.as_ref()
    }

    #[inline]
    pub fn id(&self) -> u32 {
        self.id
    }

    #[inline]
    pub fn into_name(self) -> Box<CStr> {
        self.name
    }
}

impl Group {
    #[inline]
    pub fn name(&self) -> &CStr {
        self.name.as_ref()
    }

    #[inline]
    pub fn id(&self) -> u32 {
        self.id
    }

    #[inline]
    pub fn into_name(self) -> Box<CStr> {
        self.name
    }
}

#[cfg(target_os = "linux")]
pub fn current_exe() -> io::Result<CString> {
    match crate::io::read_link::<&'static CStr>(unsafe {
        CStr::from_bytes_with_nul_unchecked(b"/proc/self/exe\0")
    }) {
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => Err(io::Error::new(
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
    unsafe {
        let mut sz: u32 = 0;
        libc::_NSGetExecutablePath(core::ptr::null_mut(), &mut sz);
        if sz == 0 {
            return Err(io::last_os_error());
        }
        let mut v: Vec<u8> = Vec::with_capacity(sz as usize);
        let err = libc::_NSGetExecutablePath(v.as_mut_ptr() as *mut i8, &mut sz);
        if err != 0 {
            return Err(io::last_os_error());
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
            return Err(io::last_os_error());
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
            return Err(io::last_os_error());
        }
        argv.set_len(argv_len.min(1));
        let argv0 = argv.remove(0);
        if argv0.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::Uncategorized,
                "no current exe available",
            ));
        }
        let argv0 = CStr::from_ptr(argv0);
        if argv0[0] == b'.' || argv0.iter().any(|b| *b == b'/') {
            crate::io::canonicalize(argv0)
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
                return Err(io::last_os_error());
            }
            if path_len <= 1 {
                return Err(io::Error::new(
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
                return Err(io::last_os_error());
            }
            path.set_len(path_len - 1); // chop off NUL
            Ok(CString::from_vec_unchecked(path))
        }
    }
    fn procfs() -> io::Result<CString> {
        crate::io::read_link(unsafe { CStr::from_bytes_with_nul_unchecked(b"/proc/curproc/exe\0") })
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
            return Err(io::last_os_error());
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
            return Err(io::last_os_error());
        }
        v.set_len(sz - 1); // chop off trailing NUL
        Ok(CString::from_vec_unchecked(v))
    }
}

#[derive(Debug, Clone)]
pub struct ProcessContext {
    pub exe: CString,
    pub pid: u32,
    pub original_user: User,
    pub original_group: Group,
    pub original_groups: Vec<Group>,
    pub sid: u32,
    pub tty: Rc<TtyInfo>,
}

impl ProcessContext {
    pub fn current(iam: &IAMContext) -> io::Result<Self> {
        let (pid, uid, gid, session, tty) = super::process_infos()?;

        let tty = if let Some(tty) = tty {
            tty
        } else {
            return Err(io::ErrorKind::NotFound.into());
        };

        iam.set_effective_identity(uid, gid)?;

        let exe = crate::io::canonicalize(&current_exe()?)?;

        let user_name = if let Some(user_name) = iam.user_name_by_id(uid)? {
            user_name
        } else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "invalid user"));
        };

        let group_name = if let Some(group_name) = iam.group_name_by_id(gid)? {
            group_name
        } else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "invalid group"));
        };

        let original_user = User {
            name: user_name,
            id: uid,
        };

        let original_group = Group {
            name: group_name,
            id: gid,
        };

        let original_groups = iam.get_groups(original_user.name())?;

        Ok(Self {
            exe,
            pid,
            original_user,
            original_group,
            original_groups,
            sid: session,
            tty: Rc::new(tty),
        })
    }
}
