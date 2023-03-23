use std::ffi::CStr;

use pezzo::unix::Context;

extern crate pezzo;

fn main() {
    let mut ctx = Context::current().unwrap();

    unsafe {
        ctx.authenticate(
            CStr::from_bytes_with_nul_unchecked(b"sudo\0"),
            None, // Some(CStr::from_bytes_with_nul_unchecked(b"shura\0")),
        )
    }
    .unwrap();
}
