use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
};

use super::{GroupRepr, UserRepr};

mod __private {
    pub struct CheckedSlice<'a>(&'a [u8]);

    impl<'a> CheckedSlice<'a> {
        #[inline]
        pub unsafe fn new(inner: &'a [u8]) -> Self {
            Self(inner)
        }

        #[inline]
        pub fn as_bytes(&self) -> &'a [u8] {
            self.0
        }
    }
}

use __private::*;

use super::cache::OrdCStr;

impl<'a> OrdCStr for CheckedSlice<'a> {
    #[inline]
    fn cmp(&self, other: &std::ffi::CStr) -> std::cmp::Ordering {
        self.as_bytes().cmp(other.to_bytes())
    }
}

#[allow(clippy::from_over_into)]
impl<'a> Into<CString> for CheckedSlice<'a> {
    #[inline]
    fn into(self) -> CString {
        unsafe { CString::from_vec_unchecked(self.as_bytes().to_vec()) }
    }
}

#[inline(always)]
fn is_valid_cstr(s: &[u8]) -> bool {
    memchr::memchr(b'\0', s).is_none()
}

fn map_ocstr(iam: &mut super::IAM, s: Option<&[u8]>) -> Option<usize> {
    let s = s?;
    if is_valid_cstr(s) {
        Some(iam.strings.insert(unsafe { CheckedSlice::new(s) }))
    } else {
        None
    }
}

pub fn add_users<B: AsRef<[u8]>>(content: B, iam: &mut super::IAM) -> BTreeMap<u32, BTreeSet<u32>> {
    let mut groups = BTreeMap::new();
    for e in super::passwd::parse_content(content.as_ref()).flatten() {
        if is_valid_cstr(e.name) {
            groups
                .entry(e.gid)
                .and_modify(|s: &mut BTreeSet<u32>| {
                    s.insert(e.uid);
                })
                .or_insert_with(|| {
                    let mut s = BTreeSet::new();
                    s.insert(e.uid);
                    s
                });

            let name = iam.strings.insert(unsafe { CheckedSlice::new(e.name) });
            let password = map_ocstr(iam, e.password);
            let comment = map_ocstr(iam, e.comment);
            let home = map_ocstr(iam, e.home);
            let shell = map_ocstr(iam, e.shell);

            let i = match iam.users.binary_search_by_key(&e.uid, |e| e.uid) {
                Ok(i) => {
                    iam.users.remove(i);
                    i
                }
                Err(i) => i,
            };

            iam.users.insert(
                i,
                UserRepr {
                    uid: e.uid,
                    name,
                    password,
                    default_group: e.gid,
                    groups: vec![e.gid],
                    comment,
                    home,
                    shell,
                },
            );
            iam.users_by_name.insert(name, e.uid);
        }
    }

    groups
}

fn unique_add<T: Ord>(v: &mut Vec<T>, value: T) {
    let i = match v.binary_search(&value) {
        Ok(i) => {
            v.remove(i);
            i
        }
        Err(i) => i,
    };
    v.insert(i, value);
}

pub fn add_groups<B: AsRef<[u8]>>(
    content: B,
    iam: &mut super::IAM,
    additionals: BTreeMap<u32, BTreeSet<u32>>,
) {
    for e in super::groups::parse_content(content.as_ref()).flatten() {
        if is_valid_cstr(e.name) {
            let name = iam.strings.insert(unsafe { CheckedSlice::new(e.name) });
            let password = map_ocstr(iam, e.password);
            let mut users = Vec::new();

            if let Some(us) = e.users {
                for name in us {
                    if is_valid_cstr(name) {
                        let name = unsafe { CheckedSlice::new(name) };
                        if let Some(user) = iam
                            .strings
                            .get_index(name)
                            .and_then(|idx| iam.users_by_name.get(&idx))
                            .and_then(|uid| iam.users.binary_search_by_key(uid, |u| u.uid).ok())
                            .map(|idx| unsafe { iam.users.get_unchecked_mut(idx) })
                        {
                            unique_add(&mut users, user.uid);
                            unique_add(&mut user.groups, e.gid);
                        }
                    }
                }
            }
            if let Some(adds) = additionals.get(&e.gid) {
                for &uid in adds {
                    unique_add(&mut users, uid);
                }
            }

            unique_add(
                &mut iam.groups,
                GroupRepr {
                    name,
                    gid: e.gid,
                    password,
                    users,
                },
            );
            iam.groups_by_name.insert(name, e.gid);
        }
    }
}
