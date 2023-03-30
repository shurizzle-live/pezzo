use std::{
    ffi::{CStr, CString, OsString},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use pezzo::{
    conf::{Origin, Target},
    unix::{Group, IAMContext, ProcessContext, User},
};

extern crate pezzo;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long, value_parser = parse_box_c_str, value_name = "USER")]
    pub user: Option<Box<CStr>>,
    #[arg(short, long, value_parser = parse_box_c_str, value_name = "GROUP")]
    pub group: Option<Box<CStr>>,
    #[arg(trailing_var_arg(true), required(true))]
    pub command: Vec<OsString>,
}

fn parse_box_c_str(input: &str) -> Result<Box<CStr>, &'static str> {
    match memchr::memchr(b'\0', input.as_bytes()) {
        Some(i) if i + 1 == input.len() => unsafe {
            Ok(CStr::from_ptr(input.as_bytes().as_ptr() as *const _)
                .to_owned()
                .into_boxed_c_str())
        },
        Some(_) => Err("Invalid string"),
        None => unsafe {
            Ok(CString::from_vec_unchecked(input.as_bytes().to_vec()).into_boxed_c_str())
        },
    }
}

fn check_file_permissions<P: AsRef<Path>>(path: P) -> Result<()> {
    #[cfg(target_os = "linux")]
    use std::os::linux::fs::MetadataExt;
    #[cfg(target_os = "macos")]
    use std::os::macos::fs::MetadataExt;
    use std::os::unix::prelude::PermissionsExt;

    let path = path.as_ref();
    match path.metadata() {
        Ok(md) => {
            if md.st_uid() != 0 || (md.permissions().mode() & 0o022) != 0 {
                bail!(
                    "Wrong permissions on file '{}`. Your system has been compromised.",
                    path.display()
                );
            }
        }
        Err(_) => {
            bail!("Cannot find file '{}`", path.display());
        }
    }

    Ok(())
}

fn parse_conf<P: AsRef<Path>>(path: P) -> Result<pezzo::conf::Rules> {
    let path = path.as_ref();

    check_file_permissions(path)?;

    let content = pezzo::util::slurp(path).context("Cannot read configuration file.")?;
    match pezzo::conf::parse(&content) {
        Ok(c) => Ok(c),
        Err(err) => {
            let buf = &content[..err.location];
            let mut line = 1;
            let mut pos = 0;
            for p in memchr::memchr_iter(b'\n', buf) {
                line += 1;
                pos = p;
            }

            let col = buf.len() - pos;
            bail!(
                "{}:{}: expected {}, got {}",
                line,
                col + 1,
                err.expected,
                content[err.location]
            );
        }
    }
}

#[derive(Debug)]
pub struct MatchContext {
    command: PathBuf,
    arguments: Vec<OsString>,
    target_user: User,
    target_group: Option<Group>,
    iam: IAMContext,
    proc: ProcessContext,
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
            bail!("Command {:?} not found.", command);
        };

        let target_user = user.map_or_else(
            || iam.default_user().context("Cannot get root informations."),
            |name| {
                iam.user_by_name(name)
                    .context("Cannot get users informations.")?
                    .map_err(|name| anyhow!("Invalid user {:?}", name))
            },
        )?;

        let target_group = group.map_or_else(
            || Ok(None),
            |name| {
                iam.group_by_name(name)
                    .context("Cannot get groups informations.")?
                    .map(Some)
                    .map_err(|name| anyhow!("Invalid group {:?}", name))
            },
        )?;

        Ok(Self {
            command,
            arguments,
            target_user,
            target_group,
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
                        Origin::UserGroup(users, groups) => {
                            users
                                .iter()
                                .any(|u| self.proc.original_user.name() == u.as_c_str())
                                && groups.iter().any(|g| {
                                    let g = g.as_c_str();
                                    self.proc.original_group.name() == g
                                        || self.proc.original_groups.iter().any(|og| og.name() == g)
                                })
                        }
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
                                    && self.target_group.as_ref().map_or(true, |target_group| {
                                        let target_group = target_group.name();
                                        groups.iter().any(|u| target_group == u.as_c_str())
                                    })
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

fn _main() -> Result<()> {
    let iam = IAMContext::new().context("Cannot initialize users and groups.")?;

    iam.escalate_permissions()
        .context("Cannot set root permissions.")?;

    let proc = ProcessContext::current(&iam).context("Cannot get process informations")?;

    check_file_permissions(&proc.exe)?;

    let Cli {
        user,
        group,
        command: args,
    } = Cli::parse();

    let ctx = MatchContext::new(iam, proc, user, group, args)?;

    let rules = parse_conf("pezzo.conf")?;

    if !ctx.matches(&rules) {
        bail!("Cannot match any rule.");
    }

    ctx.iam
        .escalate_permissions()
        .context("Cannot set root permissions.")?;

    let (ctx, _command, _arguments) = {
        (
            pezzo::unix::Context::new(ctx.iam, ctx.proc, ctx.target_user, ctx.target_group)
                .context("Cannot instantiate tty")?,
            ctx.command,
            ctx.arguments,
        )
    };

    ctx.authenticate();

    // std::process::Command::new(command).args(args).exec();
    Ok(())
}

fn main() {
    if let Err(err) = _main() {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}
