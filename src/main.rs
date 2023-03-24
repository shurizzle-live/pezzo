use std::{ffi::CStr, io::Write};

use pezzo::unix::Context;

extern crate pezzo;

fn main() {
    let mut ctx = Context::current().unwrap();
    let out = ctx.tty_out();
    let tty_name = ctx.tty_name();
    {
        writeln!(out.lock().unwrap(), "{}", tty_name).unwrap();
    }

    unsafe { ctx.authenticate(Some(CStr::from_bytes_with_nul_unchecked(b"shura\0"))) }.unwrap();
}
