use std::{ffi::CStr, path::PathBuf};

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
    pub exe: PathBuf,
    pub pid: u32,
    pub original_user: User,
    pub original_group: Group,
    pub original_groups: Vec<Group>,
    pub sid: u32,
    pub ttyno: u32,
}
