use std::{ffi::CStr, io};

use super::{Group, User};

#[derive(Debug)]
pub struct IAMContext;

impl IAMContext {
    #[inline]
    pub fn new() -> io::Result<Self> {
        unsafe {
            if libc::initgroups(b"root\0".as_ptr() as *const _, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self)
    }

    pub fn default_user(&self) -> io::Result<User> {
        Ok(User {
            name: unsafe {
                CStr::from_ptr(b"root\0".as_ptr() as *const _)
                    .to_owned()
                    .into_boxed_c_str()
            },
            id: 0,
        })
    }

    #[cfg(target_os = "linux")]
    pub fn user_id_by_name<S: AsRef<CStr>>(&self, name: S) -> io::Result<Option<u32>> {
        let name = name.as_ref();

        unsafe {
            *libc::__errno_location() = 0;
            let pwd = libc::getpwnam(name.as_ptr());
            if pwd.is_null() {
                if *libc::__errno_location() == 0 {
                    Ok(None)
                } else {
                    Err(io::Error::last_os_error())
                }
            } else {
                Ok(Some((*pwd).pw_uid))
            }
        }
    }

    #[cfg(target_os = "linux")]
    pub fn user_name_by_id(&self, uid: u32) -> io::Result<Option<Box<CStr>>> {
        unsafe {
            *libc::__errno_location() = 0;
            let pwd = libc::getpwuid(uid);
            if pwd.is_null() {
                if *libc::__errno_location() == 0 {
                    Ok(None)
                } else {
                    Err(io::Error::last_os_error())
                }
            } else {
                Ok(Some(
                    CStr::from_ptr((*pwd).pw_name).to_owned().into_boxed_c_str(),
                ))
            }
        }
    }

    #[cfg(target_os = "macos")]
    pub fn user_name_by_id(&self, uid: u32) -> io::Result<Option<Box<CStr>>> {
        unsafe {
            *libc::__error() = 0;
            let pwd = libc::getpwuid(uid);
            if pwd.is_null() {
                if *libc::__error() == 0 {
                    Ok(None)
                } else {
                    Err(io::Error::last_os_error())
                }
            } else {
                Ok(Some(
                    CStr::from_ptr((*pwd).pw_name).to_owned().into_boxed_c_str(),
                ))
            }
        }
    }

    #[cfg(target_os = "linux")]
    pub fn group_id_by_name<S: AsRef<CStr>>(&self, name: S) -> io::Result<Option<u32>> {
        let name = name.as_ref();
        unsafe {
            *libc::__errno_location() = 0;
            let grd = libc::getgrnam(name.as_ptr());
            if grd.is_null() {
                if *libc::__errno_location() == 0 {
                    Ok(None)
                } else {
                    Err(io::Error::last_os_error())
                }
            } else {
                Ok(Some((*grd).gr_gid))
            }
        }
    }

    #[cfg(target_os = "linux")]
    pub fn group_name_by_id(&self, gid: u32) -> io::Result<Option<Box<CStr>>> {
        unsafe {
            *libc::__errno_location() = 0;
            let grd = libc::getgrgid(gid);
            if grd.is_null() {
                if *libc::__errno_location() == 0 {
                    Ok(None)
                } else {
                    Err(io::Error::last_os_error())
                }
            } else {
                Ok(Some(
                    CStr::from_ptr((*grd).gr_name).to_owned().into_boxed_c_str(),
                ))
            }
        }
    }

    #[cfg(target_os = "macos")]
    pub fn group_name_by_id(&self, uid: u32) -> io::Result<Option<Box<CStr>>> {
        unsafe {
            *libc::__error() = 0;
            let pwd = libc::getgrgid(uid);
            if pwd.is_null() {
                if *libc::__error() == 0 {
                    Ok(None)
                } else {
                    Err(io::Error::last_os_error())
                }
            } else {
                Ok(Some(
                    CStr::from_ptr((*pwd).pw_name).to_owned().into_boxed_c_str(),
                ))
            }
        }
    }

    pub fn user_by_name(&self, name: Box<CStr>) -> io::Result<Result<User, Box<CStr>>> {
        Ok(match self.user_id_by_name(name.as_ref())? {
            Some(id) => Ok(User { id, name }),
            None => Err(name),
        })
    }

    pub fn group_by_name(&self, name: Box<CStr>) -> io::Result<Result<Group, Box<CStr>>> {
        Ok(match self.group_id_by_name(name.as_ref())? {
            Some(id) => Ok(Group { id, name }),
            None => Err(name),
        })
    }

    pub fn set_identity(&self, uid: u32, gid: u32) -> io::Result<()> {
        unsafe {
            if libc::setuid(uid) == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::setgid(gid) == -1 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    pub fn set_effective_identity(&self, uid: u32, gid: u32) -> io::Result<()> {
        unsafe {
            if libc::seteuid(uid) == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::setegid(gid) == -1 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}
