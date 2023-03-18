use std::io::{self, Write};

use pezzo::unix::tty::{TtyIn, TtyOut};
use zeroize::Zeroizing;

extern crate pezzo;

fn prompt_password<P>(
    prompt: P,
    writer: &mut TtyOut,
    reader: &mut TtyIn,
) -> io::Result<Zeroizing<Box<[u8]>>>
where
    P: AsRef<[u8]>,
{
    writer.write_all(prompt.as_ref())?;
    writer.flush()?;
    reader.read_password()
}

fn main() {
    let stat = pezzo::unix::linux::proc::stat::Stat::current().unwrap();
    let info = pezzo::unix::linux::tty::find_by_ttynr(stat.tty_nr).unwrap();
    let mut ttyin = info.input().unwrap();
    let mut ttyout = info.output().unwrap();

    let password = prompt_password(b"Password: ", &mut ttyout, &mut ttyin).unwrap();
    dbg!(unsafe { std::str::from_utf8_unchecked(&password[..]) });
}
