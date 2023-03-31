use std::{
    ffi::{CStr, OsString},
    path::PathBuf,
};

use anyhow::{anyhow, bail, Context, Result};
use pezzo::{
    conf::{Origin, Target},
    unix::{Group, IAMContext, ProcessContext, User},
};

#[derive(Debug)]
pub struct MatchContext {
    pub(crate) command: PathBuf,
    pub(crate) arguments: Vec<OsString>,
    pub(crate) target_user: User,
    pub(crate) target_group: Group,
    pub(crate) target_home: Box<CStr>,
    pub(crate) default_gid: u32,
    pub(crate) iam: IAMContext,
    pub(crate) proc: ProcessContext,
}

impl MatchContext {
    pub fn new(
        iam: IAMContext,
        proc: ProcessContext,
        user: Option<Box<CStr>>,
        group: Option<Box<CStr>>,
        mut arguments: Vec<OsString>,
    ) -> Result<Self> {
        let command = arguments.remove(0);
        let command = if let Ok(command) = which::which(&command) {
            std::fs::canonicalize(&command)
                .with_context(move || anyhow!("Cannot resolve path {:?}", command))?
        } else {
            bail!("Command {:?} not found", command);
        };

        let pwd = if let Some(name) = user {
            iam.pwd_by_name(name.as_ref())
                .context("Cannot get users informations")?
                .ok_or_else(|| anyhow!("Invalid user {:?}", name))?
        } else {
            iam.default_user()
                .context("Cannot get groups informations")?
                .ok_or_else(|| anyhow!("Invalid root user"))?
        };

        let (target_user, default_gid, target_home) =
            (User::new(pwd.uid, pwd.name), pwd.gid, pwd.home);

        let target_group = group.map_or_else(
            || {
                iam.group_by_id(default_gid)
                    .context("Cannot get groups informations")?
                    .ok_or_else(|| anyhow!("Invalid group {}", default_gid))
            },
            |name| {
                iam.group_by_name(name)
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
            default_gid,
            iam,
            proc,
        })
    }

    pub fn matches(&self, conf: &pezzo::conf::Rules) -> bool {
        conf.rules()
            .iter()
            .filter(|&rule| {
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
                        return false;
                    }
                }

                {
                    let target_match = if let Some(ref target) = rule.target {
                        target.iter().any(|x| match x {
                            Target::User(users) => users
                                .iter()
                                .any(|u| self.target_user.name() == u.as_c_str()),
                            Target::UserGroup(users, groups) => {
                                users
                                    .iter()
                                    .any(|u| self.target_user.name() == u.as_c_str())
                                    && groups
                                        .iter()
                                        .any(|u| self.target_group.name() == u.as_c_str())
                            }
                        })
                    } else {
                        true
                    };

                    if !target_match {
                        return false;
                    }
                }

                rule.exe
                    .as_ref()
                    .map_or(true, |exe| exe.is_match(&self.command))
            })
            .last()
            .is_some()
    }
}
