use std::{io, path::Path};

use crate::{
    unix::iam::{add_groups, add_users},
    util::slurp,
};

pub struct Builder;

pub struct BuilderWithPasswdBuffer<B: AsRef<[u8]>> {
    passwd: B,
}

pub struct BuilderWithPasswdPath<P: AsRef<Path>> {
    passwd: P,
}

pub struct BuilderWithGroupBuffer<B: AsRef<[u8]>> {
    group: B,
}

pub struct BuilderWithGroupPath<P: AsRef<Path>> {
    group: P,
}

pub struct BuilderWithPasswdBufferGroupBuffer<B1: AsRef<[u8]>, B2: AsRef<[u8]>> {
    passwd: B1,
    group: B2,
}

pub struct BuilderWithPasswdBufferGroupPath<B: AsRef<[u8]>, P: AsRef<Path>> {
    passwd: B,
    group: P,
}

pub struct BuilderWithPasswdPathGroupBuffer<P: AsRef<Path>, B: AsRef<[u8]>> {
    passwd: P,
    group: B,
}

pub struct BuilderWithPasswdPathGroupPath<P1: AsRef<Path>, P2: AsRef<Path>> {
    passwd: P1,
    group: P2,
}

impl Builder {
    #[inline]
    pub fn new() -> Self {
        Self
    }

    #[inline]
    pub fn with_passwd_buffer<B: AsRef<[u8]>>(self, passwd: B) -> BuilderWithPasswdBuffer<B> {
        BuilderWithPasswdBuffer { passwd }
    }

    #[inline]
    pub fn with_passwd_path<P: AsRef<Path>>(self, passwd: P) -> BuilderWithPasswdPath<P> {
        BuilderWithPasswdPath { passwd }
    }

    #[inline]
    pub fn with_group_buffer<B: AsRef<[u8]>>(self, group: B) -> BuilderWithGroupBuffer<B> {
        BuilderWithGroupBuffer { group }
    }

    #[inline]
    pub fn with_group_path<P: AsRef<Path>>(self, group: P) -> BuilderWithGroupPath<P> {
        BuilderWithGroupPath { group }
    }
}

impl<B: AsRef<[u8]>> BuilderWithPasswdBuffer<B> {
    #[inline]
    pub fn with_group_buffer<B2: AsRef<[u8]>>(
        self,
        group: B2,
    ) -> BuilderWithPasswdBufferGroupBuffer<B, B2> {
        BuilderWithPasswdBufferGroupBuffer {
            passwd: self.passwd,
            group,
        }
    }

    #[inline]
    pub fn with_group_path<P: AsRef<Path>>(
        self,
        group: P,
    ) -> BuilderWithPasswdBufferGroupPath<B, P> {
        BuilderWithPasswdBufferGroupPath {
            passwd: self.passwd,
            group,
        }
    }
}

impl<P: AsRef<Path>> BuilderWithPasswdPath<P> {
    #[inline]
    pub fn with_group_buffer<B: AsRef<[u8]>>(
        self,
        group: B,
    ) -> BuilderWithPasswdPathGroupBuffer<P, B> {
        BuilderWithPasswdPathGroupBuffer {
            passwd: self.passwd,
            group,
        }
    }

    #[inline]
    pub fn with_group_path<P2: AsRef<Path>>(
        self,
        group: P2,
    ) -> BuilderWithPasswdPathGroupPath<P, P2> {
        BuilderWithPasswdPathGroupPath {
            passwd: self.passwd,
            group,
        }
    }
}

impl<B: AsRef<[u8]>> BuilderWithGroupBuffer<B> {
    #[inline]
    pub fn with_passwd_buffer<B2: AsRef<[u8]>>(
        self,
        passwd: B2,
    ) -> BuilderWithPasswdBufferGroupBuffer<B2, B> {
        BuilderWithPasswdBufferGroupBuffer {
            passwd,
            group: self.group,
        }
    }

    #[inline]
    pub fn with_passwd_path<P: AsRef<Path>>(
        self,
        passwd: P,
    ) -> BuilderWithPasswdPathGroupBuffer<P, B> {
        BuilderWithPasswdPathGroupBuffer {
            passwd,
            group: self.group,
        }
    }
}

impl<P: AsRef<Path>> BuilderWithGroupPath<P> {
    #[inline]
    pub fn with_passwd_buffer<B: AsRef<[u8]>>(
        self,
        passwd: B,
    ) -> BuilderWithPasswdBufferGroupPath<B, P> {
        BuilderWithPasswdBufferGroupPath {
            passwd,
            group: self.group,
        }
    }

    #[inline]
    pub fn with_passwd_path<P2: AsRef<Path>>(
        self,
        passwd: P2,
    ) -> BuilderWithPasswdPathGroupPath<P2, P> {
        BuilderWithPasswdPathGroupPath {
            passwd,
            group: self.group,
        }
    }
}

impl<B1: AsRef<[u8]>, B2: AsRef<[u8]>> BuilderWithPasswdBufferGroupBuffer<B1, B2> {
    pub fn build(self) -> super::IAM {
        let mut iam = super::IAM::empty();
        let adds = add_users(self.passwd, &mut iam);
        add_groups(self.group, &mut iam, adds);
        iam.shrink_to_fit();
        iam
    }
}

impl<B: AsRef<[u8]>, P: AsRef<Path>> BuilderWithPasswdBufferGroupPath<B, P> {
    pub fn build(self) -> io::Result<super::IAM> {
        let mut iam = super::IAM::empty();
        let adds = add_users(self.passwd, &mut iam);
        let group = slurp(self.group)?;
        add_groups(group, &mut iam, adds);
        iam.shrink_to_fit();
        Ok(iam)
    }
}

impl<P: AsRef<Path>, B: AsRef<[u8]>> BuilderWithPasswdPathGroupBuffer<P, B> {
    pub fn build(self) -> io::Result<super::IAM> {
        let mut iam = super::IAM::empty();
        let passwd = slurp(self.passwd)?;
        let adds = add_users(passwd, &mut iam);
        add_groups(self.group, &mut iam, adds);
        iam.shrink_to_fit();
        Ok(iam)
    }
}

impl<P1: AsRef<Path>, P2: AsRef<Path>> BuilderWithPasswdPathGroupPath<P1, P2> {
    pub fn build(self) -> io::Result<super::IAM> {
        let mut iam = super::IAM::empty();
        let passwd = slurp(self.passwd)?;
        let adds = add_users(passwd, &mut iam);
        let group = slurp(self.group)?;
        add_groups(group, &mut iam, adds);
        iam.shrink_to_fit();
        Ok(iam)
    }
}

impl Default for Builder {
    #[inline]
    fn default() -> Self {
        Self
    }
}
