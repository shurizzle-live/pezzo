use std::{ffi::CStr, io};

use super::{Group, Pwd, User, __errno};

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

    #[inline]
    pub fn default_user(&self) -> io::Result<Option<Pwd>> {
        self.pwd_by_id(0)
    }

    fn convert_pwd(raw: *const libc::passwd) -> Pwd {
        unsafe {
            let uid = (*raw).pw_uid;
            let gid = (*raw).pw_gid;
            let name = CStr::from_ptr((*raw).pw_name).to_owned().into_boxed_c_str();
            let home = CStr::from_ptr((*raw).pw_dir).to_owned().into_boxed_c_str();

            Pwd {
                uid,
                gid,
                name,
                home,
            }
        }
    }

    fn raw_pwd_by_name<S: AsRef<CStr>>(&self, name: S) -> io::Result<Option<*const libc::passwd>> {
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
                Ok(Some(pwd))
            }
        }
    }

    fn raw_pwd_by_uid(&self, uid: u32) -> io::Result<Option<*const libc::passwd>> {
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
                Ok(Some(pwd))
            }
        }
    }

    pub fn user_id_by_name<S: AsRef<CStr>>(&self, name: S) -> io::Result<Option<u32>> {
        self.raw_pwd_by_name(name)
            .map(|o| o.map(|pwd| unsafe { (*pwd).pw_uid }))
    }

    pub fn pwd_by_name<S: AsRef<CStr>>(&self, name: S) -> io::Result<Option<Pwd>> {
        Ok(self.raw_pwd_by_name(name)?.map(Self::convert_pwd))
    }

    pub fn pwd_by_id(&self, id: u32) -> io::Result<Option<Pwd>> {
        Ok(self.raw_pwd_by_uid(id)?.map(Self::convert_pwd))
    }

    pub fn user_id_home_by_name<S: AsRef<CStr>>(
        &self,
        name: S,
    ) -> io::Result<Option<(u32, Box<CStr>)>> {
        self.raw_pwd_by_name(name).map(|o| {
            o.map(|pwd| unsafe {
                (
                    (*pwd).pw_uid,
                    CStr::from_ptr((*pwd).pw_dir).to_owned().into_boxed_c_str(),
                )
            })
        })
    }

    pub fn user_name_home_by_id(&self, uid: u32) -> io::Result<Option<(Box<CStr>, Box<CStr>)>> {
        self.raw_pwd_by_uid(uid).map(|o| {
            o.map(|pwd| unsafe {
                (
                    CStr::from_ptr((*pwd).pw_name).to_owned().into_boxed_c_str(),
                    CStr::from_ptr((*pwd).pw_dir).to_owned().into_boxed_c_str(),
                )
            })
        })
    }

    pub fn user_name_by_id(&self, uid: u32) -> io::Result<Option<Box<CStr>>> {
        self.raw_pwd_by_uid(uid).map(|o| {
            o.map(|pwd| unsafe { CStr::from_ptr((*pwd).pw_name).to_owned().into_boxed_c_str() })
        })
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

    pub fn user_by_id(&self, id: u32) -> io::Result<Option<User>> {
        self.user_name_by_id(id)
            .map(|o| o.map(|name| User { id, name }))
    }

    #[allow(clippy::type_complexity)]
    pub fn user_home_by_name(
        &self,
        name: Box<CStr>,
    ) -> io::Result<Result<(User, Box<CStr>), Box<CStr>>> {
        Ok(match self.user_id_home_by_name(name.as_ref())? {
            Some((id, home)) => Ok((User { id, name }, home)),
            None => Err(name),
        })
    }

    pub fn user_home_by_id(&self, id: u32) -> io::Result<Option<(User, Box<CStr>)>> {
        self.user_name_home_by_id(id)
            .map(|o| o.map(|(name, home)| (User { id, name }, home)))
    }

    pub fn group_by_id(&self, id: u32) -> io::Result<Option<Group>> {
        Ok(self.group_name_by_id(id)?.map(|name| Group { id, name }))
    }

    pub fn group_by_name(&self, name: Box<CStr>) -> io::Result<Result<Group, Box<CStr>>> {
        Ok(match self.group_id_by_name(name.as_ref())? {
            Some(id) => Ok(Group { id, name }),
            None => Err(name),
        })
    }

    // TODO: get groups on macos
    // #include <grp.h>
    // #include <pwd.h>
    // #include <stdio.h>
    // #include <stdlib.h>
    // #include <unistd.h>
    //
    // int32_t getgrouplist_2(const char *, gid_t, gid_t **);
    //
    // int main(void) {
    //   struct passwd *pw;
    //   pw = getpwuid(getuid());
    //
    //   gid_t *groups = NULL;
    //   int32_t ngroups = getgrouplist_2(pw->pw_name, pw->pw_gid, &groups);
    //
    //   for (int i = 0; i < ngroups; i++) {
    //     gid_t gid = groups[i];
    //     struct group *gr = getgrgid(gid);
    //     printf("%d(%s)\n", gid, gr ? gr->gr_name : NULL);
    //   }
    //
    //   free(groups);
    //
    //   return 0;
    // }

    pub fn get_groups<B: AsRef<CStr>>(&self, user_name: B) -> io::Result<Vec<Group>> {
        let mut groups = Vec::new();
        for gid in self.get_group_ids(user_name)? {
            if let Some(g) = self.group_by_id(gid)? {
                groups.push(g);
            }
        }
        Ok(groups)
    }

    pub fn get_group_ids<B: AsRef<CStr>>(&self, user_name: B) -> io::Result<Vec<u32>> {
        let user_name = user_name.as_ref();
        let gid = match self.raw_pwd_by_name(user_name)? {
            Some(pwd) => unsafe { (*pwd).pw_gid },
            _ => return Ok(Vec::new()),
        };
        let mut groups = unsafe {
            let mut len = libc::sysconf(libc::_SC_NGROUPS_MAX) as usize;
            let mut buf = Vec::<libc::gid_t>::new();
            loop {
                buf.reserve_exact(len);
                *__errno() = 0;

                if libc::getgrouplist(
                    user_name.as_ptr().cast(),
                    gid,
                    buf.as_mut_ptr(),
                    &mut len as *mut usize as _,
                ) == -1
                {
                    if *__errno() != 0 {
                        return Err(io::Error::last_os_error());
                    }
                } else {
                    buf.set_len(len);
                    break;
                }
            }

            buf
        };
        groups.sort();
        groups.dedup();

        if let Err(pos) = groups.binary_search(&gid) {
            groups.insert(pos, gid);
        }

        groups.shrink_to_fit();

        Ok(groups)
    }

    pub fn get_group_names<B: AsRef<CStr>>(&self, user_name: B) -> io::Result<Vec<Box<CStr>>> {
        let mut groups = Vec::new();
        for gid in self.get_group_ids(user_name)? {
            if let Some(g) = self.group_name_by_id(gid)? {
                if let Err(pos) = groups.binary_search(&g) {
                    groups.insert(pos, g);
                }
            }
        }
        Ok(groups)
    }

    pub fn set_identity(&self, uid: u32, gid: u32) -> io::Result<()> {
        unsafe {
            if libc::setgid(gid) == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::setuid(uid) == -1 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    pub fn set_effective_identity(&self, uid: u32, gid: u32) -> io::Result<()> {
        unsafe {
            if libc::setegid(gid) == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::seteuid(uid) == -1 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    #[inline]
    pub fn escalate_permissions(&self) -> io::Result<()> {
        unsafe {
            if libc::seteuid(0) == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::setegid(0) == -1 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    pub fn set_groups<B: AsRef<[u32]>>(&self, groups: B) -> io::Result<()> {
        let groups = groups.as_ref();
        unsafe {
            let rc = libc::setgroups(groups.len() as _, groups.as_ptr());
            if rc == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}
