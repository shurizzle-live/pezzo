use std::io::Write;

use pezzo::unix::Context;

extern crate pezzo;

fn main() {
    let ctx = Context::current().unwrap();

    let out = ctx.tty_out();
    let mut auth = ctx.authenticator().unwrap();

    for i in 1..=ctx.max_retries() {
        if matches!(auth.authenticate(), Ok(_)) {
            return;
        }

        if auth.get_conv().is_timedout() {
            break;
        }

        {
            let mut out = out.lock().expect("tty is poisoned");
            if i == ctx.max_retries() {
                _ = writeln!(out, "pezzo: {} incorrect password attemps", i);
            } else {
                _ = writeln!(out, "Sorry, try again.");
            }
            _ = out.flush();
        }
    }

    std::process::exit(1);
}
