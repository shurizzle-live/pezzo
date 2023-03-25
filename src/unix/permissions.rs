use std::io;

pub struct PermissionsContext;

impl PermissionsContext {
    #[inline]
    pub fn new() -> io::Result<Self> {
        unsafe {
            if libc::initgroups(b"root\0".as_ptr() as *const _, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self)
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
