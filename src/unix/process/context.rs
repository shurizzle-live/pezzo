use std::{
    ffi::{CStr, CString},
    path::PathBuf,
};

#[derive(Debug, Clone)]
pub struct User {
    pub(crate) name: CString,
    pub(crate) id: u32,
}

#[derive(Debug, Clone)]
pub struct Group {
    pub(crate) name: CString,
    pub(crate) id: u32,
}

impl User {
    #[inline]
    pub fn name(&self) -> &CStr {
        self.name.as_c_str()
    }

    #[inline]
    pub fn id(&self) -> u32 {
        self.id
    }
}

impl Group {
    #[inline]
    pub fn name(&self) -> &CStr {
        self.name.as_c_str()
    }

    #[inline]
    pub fn id(&self) -> u32 {
        self.id
    }
}

#[derive(Debug, Clone)]
pub struct ProcessContext {
    pub exe: PathBuf,
    pub pid: u32,
    pub original_user: User,
    pub original_group: Group,
    pub sid: u32,
    pub ttyno: u32,
}
