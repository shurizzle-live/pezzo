mod context;
mod util;

use context::MatchContext;
use tty_info::Dev;
use util::*;

use std::{
    cell::RefCell,
    ffi::{CStr, OsStr, OsString},
    io::Write,
    os::unix::{
        prelude::{OsStrExt, OsStringExt},
        process::CommandExt,
    },
    rc::Rc,
};

use anyhow::{bail, Context, Result};
use clap::Parser;
use pezzo::{
    conf::Env,
    database::{Database, Entry},
    unix::{
        tty::{TtyIn, TtyOut},
        IAMContext, ProcessContext,
    },
    DEFAULT_MAX_RETRIES, DEFAULT_PROMPT_TIMEOUT, DEFAULT_SESSION_TIMEOUT, PEZZO_NAME_CSTR,
};

extern crate pezzo;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(
        short = 'v',
        long,
        exclusive(true),
        help("update user's timestamp without running a command")
    )]
    pub validate: bool,
    #[arg(
        short = 'K',
        long,
        exclusive(true),
        help("remove timestamp file completely")
    )]
    pub remove_timestamp: bool,
    #[arg(short = 'k', long, exclusive(true), help("invalidate timestamp file"))]
    pub reset_timestamp: bool,
    #[arg(short = 'B', long, help("ring bell when prompting"))]
    pub bell: bool,
    #[arg(short, long, value_parser = parse_box_c_str, value_name = "USER", help("run command as specified user name or ID"))]
    pub user: Option<Box<CStr>>,
    #[arg(short, long, value_parser = parse_box_c_str, value_name = "GROUP", help("run command as the specified group name or ID"))]
    pub group: Option<Box<CStr>>,
    #[arg(trailing_var_arg(true), required(true))]
    pub command: Vec<OsString>,
}

fn _main() -> Result<()> {
    let iam = IAMContext::new().context("Cannot initialize users and groups")?;

    iam.escalate_permissions()
        .context("Cannot set root permissions")?;

    let proc = ProcessContext::current(&iam).context("Cannot get process informations")?;

    check_file_permissions(&proc.exe)?;

    let Cli {
        validate,
        remove_timestamp,
        reset_timestamp,
        bell,
        user,
        group,
        command: args,
    } = Cli::parse();

    if remove_timestamp {
        iam.escalate_permissions()
            .context("Cannot set root permissions")?;
        Database::delete(proc.original_user.name()).context("Cannot access database")?;
        return Ok(());
    }

    if reset_timestamp {
        iam.escalate_permissions()
            .context("Cannot set root permissions")?;
        let mut db = Database::new(proc.original_user.name()).context("Cannot open database")?;
        db.retain(|e| e.session_id() != proc.sid && e.tty() != proc.tty.device());
        db.save().context("Cannot save database")?;
        return Ok(());
    }

    if validate {
        iam.escalate_permissions()
            .context("Cannot set root permissions")?;

        if is_expired(
            proc.original_user.name(),
            proc.sid,
            proc.tty.device(),
            DEFAULT_SESSION_TIMEOUT,
        )? {
            let tty_info = Rc::new(
                tty_info::TtyInfo::by_device(proc.tty.device())
                    .context("Cannot get a valid tty")?,
            );

            let out = Rc::new(RefCell::new(
                TtyOut::open(tty_info.clone()).context("Cannot get a valid tty")?,
            ));

            let mut auth = pezzo::unix::pam::Authenticator::new(
                PEZZO_NAME_CSTR,
                Some(proc.original_user.name()),
                pezzo::unix::pam::PezzoConversation::from_values(
                    DEFAULT_PROMPT_TIMEOUT,
                    Rc::new(RefCell::new(
                        TtyIn::open(tty_info).context("Cannot get a valid tty")?,
                    )),
                    out.clone(),
                    proc.original_user.name(),
                    bell,
                ),
            )
            .context("Cannot instantiate PAM authenticator")?;

            autenticate(&mut auth, DEFAULT_MAX_RETRIES, out);
        }

        update_db(proc.original_user.name(), proc.sid, proc.tty.device())?;
        return Ok(());
    }

    let ctx = MatchContext::new(iam, proc, user, group, args)?;

    let rules = parse_conf_cstr(unsafe { CStr::from_ptr(pezzo::CONFIG_PATH.as_ptr().cast()) })?;

    let match_res = if let Some(res) = ctx.matches(&rules)? {
        res
    } else {
        bail!("Cannot match any rule");
    };

    ctx.iam
        .escalate_permissions()
        .context("Cannot set root permissions")?;

    let (ctx, command, arguments, home) = {
        (
            pezzo::unix::Context::new(ctx.iam, ctx.proc, ctx.target_user, ctx.target_group, bell)
                .context("Cannot instantiate tty")?,
            ctx.command,
            ctx.arguments,
            ctx.target_home,
        )
    };

    if match_res.askpass().unwrap_or(true)
        && is_expired(
            ctx.original_user().name(),
            ctx.sid(),
            ctx.ttyno(),
            match_res.timeout().unwrap_or(DEFAULT_SESSION_TIMEOUT),
        )?
    {
        let mut auth = ctx
            .authenticator()
            .context("Cannot instantiate PAM authenticator")?;

        autenticate(&mut auth, ctx.max_retries(), ctx.tty_out());
    }

    update_db(ctx.original_user().name(), ctx.sid(), ctx.ttyno())?;

    ctx.escalate_permissions()
        .context("Cannot set root permissions")?;

    {
        let uid = ctx.target_user().id();
        let gid = ctx.target_group().id();

        {
            let mut groups = ctx
                .get_group_ids(ctx.target_user().name())
                .context("Cannot get user groups")?;
            if let Err(pos) = groups.binary_search(&gid) {
                groups.insert(pos, gid);
            }
            ctx.set_groups(groups.as_slice())
                .context("Cannot set process groups")?;
        }

        ctx.set_identity(uid, gid)
            .context("Cannot set uid and gid")?;

        ctx.set_effective_identity(uid, gid)
            .context("Cannot set euid and egid")?;
    }

    let cmd = OsString::from_vec(command.into_bytes());
    let mut proc = std::process::Command::new(&cmd);
    proc.args(arguments);

    fn set_default_path(proc: &mut std::process::Command) -> &mut std::process::Command {
        proc.env(
            "PATH",
            OsStr::from_bytes(b"/usr/local/sbin:/usr/local/bin:/usr/bin".as_slice()),
        )
    }

    let keepenv = match_res.keepenv().unwrap_or(false);
    if !keepenv {
        proc.env_clear();
        set_default_path(&mut proc);
    } else if matches!(std::env::var_os("PATH"), None) {
        set_default_path(&mut proc);
    }

    if let Some(envs) = match_res.setenv() {
        for env in envs {
            match env {
                Env::Unset(ref name) if keepenv => {
                    proc.env_remove(&***name);
                }
                Env::Copy(ref name) if !keepenv => {
                    if let Ok(value) = std::env::var(&***name) {
                        proc.env(&***name, value);
                    }
                }
                Env::Set(ref name, ref template) => {
                    let value = template.format();
                    if !value.is_empty() {
                        proc.env(&***name, value);
                    }
                }
                _ => (),
            }
        }
    }

    proc.env("HOME", OsStr::from_bytes(home.as_ref().to_bytes()))
        .env("SUDO_COMMAND", cmd)
        .env(
            "SUDO_USER",
            OsStr::from_bytes(ctx.original_user().name().to_bytes()),
        )
        .env("SUDO_UID", ctx.original_user().id().to_string())
        .env("SUDO_GID", ctx.original_group().id().to_string())
        .exec();

    Ok(())
}

fn main() {
    #[cfg(target_os = "linux")]
    linux_syscalls::init();

    if let Err(err) = _main() {
        eprintln!("{:?}", err);
        std::process::exit(1);
    }
}

fn update_db(user_name: &CStr, sid: u32, ttyno: Dev) -> Result<()> {
    let mut db = Database::new(user_name).context("Failed to open database")?;
    db.retain(|e| e.session_id() != sid && e.tty() != ttyno);
    db.push(Entry {
        session_id: sid,
        tty: ttyno,
        last_login: pezzo::unix::time::now(),
    });
    db.save().context("Unable to write database")
}

fn is_expired(user_name: &CStr, sid: u32, ttyno: Dev, timeout: u64) -> Result<bool> {
    let db = Database::new(user_name).context("Failed to open database")?;
    if let Some(entry) = db
        .iter()
        .find(|&e| e.session_id() == sid && e.tty() == ttyno)
    {
        let time = pezzo::unix::time::now();
        if (entry.last_login()..=(entry.last_login() + timeout)).contains(&time) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn autenticate(
    auth: &mut pezzo::unix::pam::Authenticator<pezzo::unix::pam::PezzoConversation>,
    max_retries: usize,
    out: Rc<RefCell<TtyOut>>,
) {
    for i in 1..=max_retries {
        if matches!(auth.authenticate(), Ok(_)) {
            return;
        }

        if auth.get_conv().is_timedout() {
            break;
        }

        {
            let mut out = out.borrow_mut();
            if i == max_retries {
                _ = writeln!(out, "pezzo: {} incorrect password attempts", i);
            } else {
                _ = writeln!(out, "Sorry, try again.");
            }
            _ = out.flush();
        }
    }
    std::process::exit(1);
}
