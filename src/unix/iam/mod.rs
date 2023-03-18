use std::{borrow::Borrow, collections::BTreeMap, ffi::CStr, fmt, io};

use self::cache::StringCache;

mod build;
pub mod builder;
mod cache;
mod groups;
mod passwd;

pub(self) use build::*;
pub use builder::Builder;

struct Lines<'a> {
    buf: Option<&'a [u8]>,
}

impl<'a> Lines<'a> {
    #[inline]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf: Some(buf) }
    }
}

impl<'a> Iterator for Lines<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let buf = self.buf.take()?;

        match memchr::memchr(b'\n', buf) {
            Some(i) => {
                let res = match &buf[..i] {
                    res if matches!(res.last(), Some(b'\r')) => unsafe {
                        res.get_unchecked(..(res.len() - 1))
                    },
                    res => res,
                };
                self.buf = buf.get((i + 1)..);
                Some(res)
            }
            None => Some(buf),
        }
    }
}

#[derive(Debug)]
pub struct UserRepr {
    uid: u32,
    name: usize,
    password: Option<usize>,
    default_group: u32,
    groups: Vec<u32>,
    comment: Option<usize>,
    home: Option<usize>,
    shell: Option<usize>,
}

impl PartialEq for UserRepr {
    fn eq(&self, other: &Self) -> bool {
        self.uid == other.uid
    }
}

impl Eq for UserRepr {}

impl PartialOrd for UserRepr {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for UserRepr {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.uid.cmp(&other.uid)
    }
}

#[derive(Debug)]
pub struct GroupRepr {
    gid: u32,
    name: usize,
    password: Option<usize>,
    users: Vec<u32>,
}

impl PartialEq for GroupRepr {
    fn eq(&self, other: &Self) -> bool {
        self.gid == other.gid
    }
}

impl Eq for GroupRepr {}

impl PartialOrd for GroupRepr {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for GroupRepr {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.gid.cmp(&other.gid)
    }
}

#[derive(Debug)]
pub struct IAM {
    strings: StringCache,
    users: Vec<UserRepr>,
    users_by_name: BTreeMap<usize, u32>,
    groups: Vec<GroupRepr>,
    groups_by_name: BTreeMap<usize, u32>,
}

pub struct User<'a> {
    iam: &'a IAM,
    inner: &'a UserRepr,
}

impl<'a> User<'a> {
    #[inline]
    pub fn uid(&self) -> u32 {
        self.inner.uid
    }

    #[inline]
    pub fn name(&self) -> &'a CStr {
        unsafe { self.iam.strings.get_unchecked(self.inner.name) }
    }

    #[inline]
    pub fn password(&self) -> Option<&'a CStr> {
        self.inner
            .password
            .map(|c| unsafe { self.iam.strings.get_unchecked(c) })
    }

    #[inline]
    pub fn default_group(&self) -> u32 {
        self.inner.default_group
    }

    #[inline]
    pub fn groups(&self) -> &'a [u32] {
        self.inner.groups.as_slice()
    }

    #[inline]
    pub fn comment(&self) -> Option<&'a CStr> {
        self.inner
            .comment
            .map(|c| unsafe { self.iam.strings.get_unchecked(c) })
    }

    #[inline]
    pub fn home(&self) -> Option<&'a CStr> {
        self.inner
            .home
            .map(|c| unsafe { self.iam.strings.get_unchecked(c) })
    }

    #[inline]
    pub fn shell(&self) -> Option<&'a CStr> {
        self.inner
            .shell
            .map(|c| unsafe { self.iam.strings.get_unchecked(c) })
    }
}

impl fmt::Debug for User<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("User")
            .field("uid", &self.uid())
            .field("name", &self.name())
            .field("groups", &self.groups())
            .field("comment", &self.comment())
            .field("home", &self.home())
            .field("shell", &self.shell())
            .finish()
    }
}

pub struct Group<'a> {
    iam: &'a IAM,
    inner: &'a GroupRepr,
}

impl<'a> Group<'a> {
    #[inline]
    pub fn gid(&self) -> u32 {
        self.inner.gid
    }

    #[inline]
    pub fn password(&self) -> Option<&'a CStr> {
        self.inner
            .password
            .map(|c| unsafe { self.iam.strings.get_unchecked(c) })
    }

    #[inline]
    pub fn name(&self) -> &'a CStr {
        unsafe { self.iam.strings.get_unchecked(self.inner.name) }
    }

    #[inline]
    pub fn users(&self) -> &'a [u32] {
        self.inner.users.as_slice()
    }
}

impl fmt::Debug for Group<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Group")
            .field("gid", &self.gid())
            .field("name", &self.name())
            .field("users", &self.users())
            .finish()
    }
}

impl IAM {
    pub fn new() -> io::Result<Self> {
        Builder::new()
            .with_passwd_path("/etc/passwd")
            .with_group_path("/etc/group")
            .build()
    }

    pub fn empty() -> Self {
        Self {
            strings: StringCache::new(),
            users: Vec::new(),
            users_by_name: BTreeMap::new(),
            groups: Vec::new(),
            groups_by_name: BTreeMap::new(),
        }
    }

    pub fn user(&self, uid: u32) -> Option<User> {
        let index = self.users.binary_search_by_key(&uid, |u| u.uid).ok()?;
        let inner = unsafe { self.users.get_unchecked(index) };
        Some(User { iam: self, inner })
    }

    pub fn user_by_name<T: Borrow<CStr>>(&self, s: T) -> Option<User> {
        self.strings
            .get_index(s.borrow())
            .and_then(|idx| self.users_by_name.get(&idx))
            .and_then(|&uid| self.user(uid))
    }

    pub fn group(&self, gid: u32) -> Option<Group> {
        let index = self.groups.binary_search_by_key(&gid, |g| g.gid).ok()?;
        let inner = unsafe { self.groups.get_unchecked(index) };
        Some(Group { iam: self, inner })
    }

    pub fn group_by_name<T: Borrow<CStr>>(&self, s: T) -> Option<Group> {
        self.strings
            .get_index(s.borrow())
            .and_then(|idx| self.groups_by_name.get(&idx))
            .and_then(|&uid| self.group(uid))
    }

    pub fn shrink_to_fit(&mut self) {
        self.strings.shrink_to_fit();
        self.users.shrink_to_fit();
        self.users.iter_mut().for_each(|u| u.groups.shrink_to_fit());
        self.groups.shrink_to_fit();
        self.groups.iter_mut().for_each(|u| u.users.shrink_to_fit());
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn current_user_groups() {
        use syscalls::{syscall, Sysno};

        let iam = super::IAM::new().unwrap();

        let uid = unsafe { syscall!(Sysno::geteuid).unwrap() } as u32;

        if let Some(me) = iam.user(uid) {
            println!("{}", me.name().to_string_lossy());
        }

        let groups = unsafe {
            let len = syscall!(Sysno::getgroups, 0, 0).unwrap();
            let mut groups = Vec::<u32>::with_capacity(len);
            syscall!(Sysno::getgroups, len, groups.as_ptr()).unwrap();
            groups.set_len(len);
            groups
        };

        for (i, group) in groups
            .into_iter()
            .flat_map(|gid| iam.group(gid))
            .map(|g| g.name().to_string_lossy())
            .enumerate()
        {
            if i != 0 {
                print!(" ");
            }
            print!("{}", group);
        }
        println!();
    }
}
