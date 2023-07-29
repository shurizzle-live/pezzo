use sstd::prelude::rust_2018::*;

use sstd::{
    cell::UnsafeCell,
    collections::HashMap,
    ffi::{CStr, CString},
};

use anyhow::{anyhow, bail, Context, Result};
use pezzo::{
    conf::{Env, Origin, Target},
    unix::{Group, IAMContext, ProcessContext, User},
};

#[derive(Debug, Default)]
pub struct MatchResult {
    timeout: Option<u64>,
    askpass: Option<bool>,
    keepenv: Option<bool>,
    setenv: Option<Box<[Env]>>,
}

impl MatchResult {
    #[inline]
    pub fn timeout(&self) -> Option<u64> {
        self.timeout
    }

    #[inline]
    pub fn askpass(&self) -> Option<bool> {
        self.askpass
    }

    #[inline]
    pub fn keepenv(&self) -> Option<bool> {
        self.keepenv
    }

    #[inline]
    pub fn setenv(&self) -> Option<&[Env]> {
        self.setenv.as_ref().map(|e| e.as_ref())
    }
}

#[derive(Debug)]
pub struct MatchContext {
    pub(crate) command: CString,
    pub(crate) arguments: Vec<CString>,
    pub(crate) target_user: User,
    pub(crate) target_group: Group,
    pub(crate) target_home: Box<CStr>,
    pub(crate) iam: IAMContext,
    pub(crate) proc: ProcessContext,
    root_name: UnsafeCell<Option<Box<CStr>>>,
    groups_cache: UnsafeCell<HashMap<Box<CStr>, Vec<Box<CStr>>>>,
}

impl MatchContext {
    pub fn new(
        iam: IAMContext,
        proc: ProcessContext,
        user: Option<Box<CStr>>,
        group: Option<Box<CStr>>,
        mut arguments: Vec<CString>,
    ) -> Result<Self> {
        let mut command = arguments.remove(0).into_bytes_with_nul();
        let command = CString::from_vec_with_nul(command).map_err(anyhow::Error::msg)?;
        let command = if let Ok(command) = pezzo::which::which(&command) {
            command
        } else {
            bail!("Command {:?} not found", command);
        };

        let pwd = if let Some(name) = user {
            iam.pwd_by_name(name.as_ref())
                .map_err(anyhow::Error::msg)
                .context("Cannot get users informations")?
                .ok_or_else(|| anyhow!("Invalid user {:?}", name))?
        } else {
            iam.default_user()
                .map_err(anyhow::Error::msg)
                .context("Cannot get groups informations")?
                .ok_or_else(|| anyhow!("Invalid root user"))?
        };

        let (target_user, default_gid, target_home) =
            (User::new(pwd.uid, pwd.name), pwd.gid, pwd.home);

        let target_group = group.map_or_else(
            || {
                iam.group_by_id(default_gid)
                    .map_err(anyhow::Error::msg)
                    .context("Cannot get groups informations")?
                    .ok_or_else(|| anyhow!("Invalid group {}", default_gid))
            },
            |name| {
                iam.group_by_name(name)
                    .map_err(anyhow::Error::msg)
                    .context("Cannot get groups informations")?
                    .map_err(|name| anyhow!("Invalid group {:?}", name))
            },
        )?;

        Ok(Self {
            command,
            arguments,
            target_user,
            target_group,
            target_home,
            iam,
            proc,
            root_name: UnsafeCell::new(None),
            groups_cache: UnsafeCell::new(HashMap::new()),
        })
    }

    fn is_root(&self, name: &CStr) -> Result<bool> {
        unsafe {
            if let Some(root_name) = (*self.root_name.get()).as_ref() {
                return Ok(root_name.as_ref() == name);
            }

            let root_name = self
                .iam
                .group_name_by_id(0)
                .map_err(anyhow::Error::msg)
                .context("cannot get groups informations")?
                .ok_or_else(|| anyhow!("Cannot get root user"))?;

            let res = root_name.as_ref() == name;
            sstd::ptr::write(self.root_name.get(), Some(root_name));
            Ok(res)
        }
    }

    fn get_groups(&self, name: &CStr) -> Result<&[Box<CStr>]> {
        unsafe {
            {
                let cache = &mut *self.groups_cache.get();
                if let Some(groups) = cache.get(name) {
                    return Ok(groups.as_slice());
                }
            }

            {
                let groups = self.iam.get_group_names(name).map_err(anyhow::Error::msg)?;
                let cache = &mut *self.groups_cache.get();
                cache.insert(name.to_owned().into_boxed_c_str(), groups);
            }

            Ok((*self.groups_cache.get()).get(name).unwrap_unchecked())
        }
    }

    pub fn matches(&self, conf: &pezzo::conf::Rules) -> Result<Option<MatchResult>> {
        let mut last = None;

        for rule in conf.rules().iter() {
            {
                let groups_match = rule.origin.iter().any(|x| match x {
                    Origin::User(users) => users
                        .iter()
                        .any(|u| self.proc.original_user.name() == u.as_c_str()),
                    Origin::Group(groups) => groups.iter().any(|g| {
                        let g = g.as_c_str();
                        self.proc.original_group.name() == g
                            || self.proc.original_groups.iter().any(|og| og.name() == g)
                    }),
                });

                if !groups_match {
                    continue;
                }
            }

            {
                let target_match = if let Some(ref target) = rule.target {
                    'target: {
                        for x in target {
                            let m = match x {
                                Target::User(users) => 'users: {
                                    for u in users {
                                        if self.is_root(u.as_c_str())?
                                            || (self.target_user.name() == u.as_c_str()
                                                && self.get_groups(u.as_c_str())?.iter().any(
                                                    |group| {
                                                        group.as_ref() == self.target_group.name()
                                                    },
                                                ))
                                        {
                                            break 'users true;
                                        }
                                    }
                                    false
                                }
                                Target::UserGroup(users, groups) => 'ug_matches: {
                                    let users_matches = 'users: {
                                        for u in users {
                                            if self.is_root(u.as_c_str())? {
                                                break 'ug_matches true;
                                            } else if self.target_user.name() == u.as_c_str() {
                                                break 'users true;
                                            }
                                        }
                                        false
                                    };
                                    if !users_matches {
                                        break 'ug_matches false;
                                    }

                                    groups
                                        .iter()
                                        .any(|u| self.target_group.name() == u.as_c_str())
                                }
                            };

                            if m {
                                break 'target true;
                            }
                        }
                        false
                    }
                } else {
                    true
                };

                if !target_match {
                    continue;
                }
            }

            if rule.exe.as_ref().map_or(true, |exe| {
                exe.is_match(OsStr::from_bytes(self.command.to_bytes()))
            }) {
                last = Some(MatchResult {
                    timeout: rule.timeout,
                    askpass: rule.askpass,
                    keepenv: rule.keepenv,
                    setenv: rule.setenv.clone(),
                });
            }
        }

        Ok(last)
    }
}
