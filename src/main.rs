use std::{
    ffi::{CStr, CString, OsString},
    io,
    os::unix::process::CommandExt,
    path::PathBuf,
};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use pezzo::unix::{Group, IAMContext, ProcessContext, User};

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

fn parse_conf() -> Vec<pezzo::conf::Rule> {
    let content = pezzo::util::slurp("pezzo.conf").unwrap();
    match pezzo::conf::parse(&content) {
        Ok(c) => c,
        Err(err) => {
            let buf = &content[..err.location];
            let mut line = 1;
            let mut pos = 0;
            for p in memchr::memchr_iter(b'\n', buf) {
                line += 1;
                pos = p;
            }

            let col = buf.len() - pos;
            eprintln!(
                "{}:{}: expected {}, got {}",
                line,
                col + 1,
                err.expected,
                content[err.location]
            );

            std::process::exit(1);
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
        user: Option<Box<CStr>>,
        group: Option<Box<CStr>>,
        mut arguments: Vec<OsString>,
    ) -> Result<Self> {
        let command = arguments.remove(0);
        let command = if let Ok(command) = which::which(&command) {
            command
        } else {
            bail!("Command {:?} not found.", command);
        };

        let iam = IAMContext::new().context("Cannot initialize users and groups.")?;
        let proc = ProcessContext::current(&iam).context("Cannot get process informations")?;

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
}

fn _main() -> Result<()> {
    // TODO: migrate this methods to iam/proc and call them
    // ctx.escalate_permissions();
    // ctx.check_file_permissions(ctx.exe());

    let Cli {
        user,
        group,
        command: args,
    } = Cli::parse();

    let ctx = MatchContext::new(user, group, args)?;

    println!("{ctx:#?}");

    // TODO: match through rules

    // ctx.authenticate();

    // std::process::Command::new(command).args(args).exec();
    Ok(())
}

fn main() {
    if let Err(err) = _main() {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}
