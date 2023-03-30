use std::{
    ffi::{CStr, CString, OsStr, OsString},
    os::unix::{prelude::OsStrExt, process::CommandExt},
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
    target_group: Group,
    target_home: Box<CStr>,
    default_gid: u32,
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

        let pwd = if let Some(name) = user {
            iam.pwd_by_name(name.as_ref())
                .context("Cannot get users informations.")?
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
                    .context("Cannot get groups informations.")?
                    .ok_or_else(|| anyhow!("Invalid group {}", default_gid))
            },
            |name| {
                iam.group_by_name(name)
                    .context("Cannot get groups informations.")?
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

    let (ctx, command, arguments, home, default_gid) = {
        (
            pezzo::unix::Context::new(ctx.iam, ctx.proc, ctx.target_user, ctx.target_group)
                .context("Cannot instantiate tty")?,
            ctx.command,
            ctx.arguments,
            ctx.target_home,
            ctx.default_gid,
        )
    };

    ctx.authenticate();

    ctx.escalate_permissions()
        .context("Cannot set root permissions.")?;

    {
        let uid = ctx.target_user().id();
        let gid = ctx.target_group().id();

        {
            let mut groups = ctx
                .get_group_ids(ctx.target_user().name().to_bytes())
                .context("Cannot get user groups.")?;
            if !groups.iter().any(|&g| g == default_gid) {
                groups.push(default_gid);
            }
            if !groups.iter().any(|&g| g == gid) {
                groups.push(gid);
            }
            ctx.set_groups(groups.as_slice())
                .context("Cannot set process groups.")?;
        }

        ctx.set_identity(uid, gid)
            .context("Cannot set uid and gid.")?;

        ctx.set_effective_identity(uid, gid)
            .context("Cannot set euid and egid.")?;
    }

    std::process::Command::new(command)
        .args(arguments)
        .env_clear()
        .env("HOME", OsStr::from_bytes(home.as_ref().to_bytes()))
        .env(
            "PATH",
            OsStr::from_bytes(b"/usr/local/sbin:/usr/local/bin:/usr/bin".as_slice()),
        )
        .exec();
    Ok(())
}

fn main() {
    if let Err(err) = _main() {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}
