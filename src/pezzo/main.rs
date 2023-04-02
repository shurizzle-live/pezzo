mod context;
mod util;

use context::MatchContext;
use util::*;

use std::{
    ffi::{CStr, OsStr, OsString},
    os::unix::{prelude::OsStrExt, process::CommandExt},
};

use anyhow::{bail, Context, Result};
use clap::Parser;
use pezzo::unix::{IAMContext, ProcessContext};

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

fn _main() -> Result<()> {
    let iam = IAMContext::new().context("Cannot initialize users and groups")?;

    iam.escalate_permissions()
        .context("Cannot set root permissions")?;

    let proc = ProcessContext::current(&iam).context("Cannot get process informations")?;

    check_file_permissions(&proc.exe)?;

    let Cli {
        user,
        group,
        command: args,
    } = Cli::parse();

    let ctx = MatchContext::new(iam, proc, user, group, args)?;

    let rules = parse_conf("/etc/pezzo.conf")?;

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
            pezzo::unix::Context::new(ctx.iam, ctx.proc, ctx.target_user, ctx.target_group)
                .context("Cannot instantiate tty")?,
            ctx.command,
            ctx.arguments,
            ctx.target_home,
        )
    };

    if match_res.askpass().unwrap_or(true) {
        ctx.authenticate(match_res.timeout().unwrap_or(600));
    }

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
        // eprintln!("{}.", err);
        eprintln!("{:?}", err);
        std::process::exit(1);
    }
}
