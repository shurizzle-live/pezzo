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

// fn parse_conf() -> Vec<pezzo::conf::Rule> {
fn parse_conf() -> pezzo::conf::Rule {
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

            std::process::exit(0);
        }
    }
}

fn main() {
    println!("{:#?}", parse_conf());
    return;

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
