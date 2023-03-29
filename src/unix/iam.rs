use std::{ffi::CStr, io};

use super::{Group, User, __errno};

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

    pub fn user_id_by_name<S: AsRef<CStr>>(&self, name: S) -> io::Result<Option<u32>> {
        let name = name.as_ref();

        unsafe {
            *__errno() = 0;
            let pwd = libc::getpwnam(name.as_ptr());
            if pwd.is_null() {
                if *__errno() == 0 {
                    Ok(None)
                } else {
                    Err(io::Error::last_os_error())
                }
            } else {
                Ok(Some((*pwd).pw_uid))
            }
        }
    }

    pub fn user_name_by_id(&self, uid: u32) -> io::Result<Option<Box<CStr>>> {
        unsafe {
            *__errno() = 0;
            let pwd = libc::getpwuid(uid);
            if pwd.is_null() {
                if *__errno() == 0 {
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

    pub fn group_id_by_name<S: AsRef<CStr>>(&self, name: S) -> io::Result<Option<u32>> {
        let name = name.as_ref();
        unsafe {
            *__errno() = 0;
            let grd = libc::getgrnam(name.as_ptr());
            if grd.is_null() {
                if *__errno() == 0 {
                    Ok(None)
                } else {
                    Err(io::Error::last_os_error())
                }
            } else {
                Ok(Some((*grd).gr_gid))
            }
        }
    }

    pub fn group_name_by_id(&self, gid: u32) -> io::Result<Option<Box<CStr>>> {
        unsafe {
            *__errno() = 0;
            let grd = libc::getgrgid(gid);
            if grd.is_null() {
                if *__errno() == 0 {
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

    pub fn get_groups<B: AsRef<[u8]>>(&self, user_name: B) -> io::Result<Vec<Group>> {
        let name = user_name.as_ref();

        unsafe {
            let mut buf = Vec::new();

            libc::setgrent();

            *crate::unix::__errno() = 0;

            loop {
                let group = libc::getgrent();
                if group.is_null() {
                    break;
                }

                let is_member = 'member: {
                    let mut it = (*group).gr_mem;

                    while !(*it).is_null() {
                        if CStr::from_ptr(*it).to_bytes() == name {
                            break 'member true;
                        }

                        it = it.add(1);
                    }
                    false
                };

                if is_member {
                    let name = CStr::from_ptr((*group).gr_name)
                        .to_owned()
                        .into_boxed_c_str();
                    let id = (*group).gr_gid;

                    buf.push(Group { name, id })
                }
            }

            let errno = *crate::unix::__errno();
            libc::endgrent();

            if errno != 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(buf)
            }
        }
    }

    pub fn get_group_ids<B: AsRef<[u8]>>(&self, user_name: B) -> io::Result<Vec<u32>> {
        let name = user_name.as_ref();

        unsafe {
            let mut buf = Vec::new();

            libc::setgrent();

            *crate::unix::__errno() = 0;

            loop {
                let group = libc::getgrent();
                if group.is_null() {
                    break;
                }

                let is_member = 'member: {
                    let mut it = (*group).gr_mem;

                    while !(*it).is_null() {
                        if CStr::from_ptr(*it).to_bytes() == name {
                            break 'member true;
                        }

                        it = it.add(1);
                    }
                    false
                };

                if is_member {
                    buf.push((*group).gr_gid);
                }
            }

            let errno = *crate::unix::__errno();
            libc::endgrent();

            if errno != 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(buf)
            }
        }
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

    #[inline]
    pub fn escalate_permissions(&self) -> io::Result<()> {
        self.set_effective_identity(0, 0)
    }
}
