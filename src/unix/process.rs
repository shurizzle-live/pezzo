use alloc_crate::{boxed::Box, rc::Rc, vec::Vec};
use sstd::{
    ffi::{CStr, CString},
    io,
};

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

        let exe = sstd::fs::canonicalize(&sstd::process::current_exe()?)?;

        let user_name = if let Some(user_name) = iam.user_name_by_id(uid)? {
            user_name
        } else {
            return Err(io::Error::new_static(
                io::ErrorKind::NotFound,
                "invalid user",
            ));
        };

        let group_name = if let Some(group_name) = iam.group_name_by_id(gid)? {
            group_name
        } else {
            return Err(io::Error::new_static(
                io::ErrorKind::NotFound,
                "invalid group",
            ));
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
