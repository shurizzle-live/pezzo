use std::{ffi::OsString, os::unix::process::CommandExt};

use clap::Parser;
use pezzo::unix::Context;

extern crate pezzo;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long, value_name = "USER")]
    pub user: Option<OsString>,
    #[arg(short, long, value_name = "GROUP")]
    pub group: Option<OsString>,
    #[arg(trailing_var_arg(true), required(true))]
    pub command: Vec<OsString>,
}

fn main() {
    let Cli {
        user,
        group,
        command: mut args,
    } = Cli::parse();

    let command = args.remove(0);
    let command = if let Ok(command) = which::which(&command) {
        command
    } else {
        eprintln!("Command {:?} not found.", command);
        std::process::exit(1);
    };

    let ctx = Context::current().unwrap();

    ctx.escalate_permissions();
    ctx.check_file_permissions(ctx.exe());

    ctx.authenticate();

    // std::process::Command::new(command).args(args).exec();
}
