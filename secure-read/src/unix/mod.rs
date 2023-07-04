#![allow(clippy::useless_conversion)]

#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(not(target_os = "linux"), path = "c/mod.rs")]
mod unix_platform;

pub mod io;
pub use unix_platform::*;

use core::ops::ControlFlow;

use crate::{io::ErrorExt, FeedRead, IsTerminal};

impl<T: io::AsRawFd> super::IsTerminal for T {
    #[inline]
    fn is_terminal(&self) -> bool {
        is_terminal(self.as_raw_fd())
    }
}

macro_rules! ok {
    ($e:expr) => {
        match $e {
            Err(err) => return Err(err.into()),
            Ok(x) => x,
        }
    };
}

fn _secure_read<B, F, E>(reader: &mut B, mut feed: F, timeout: u32) -> Result<F, E>
where
    B: io::BufRead + io::AsRawFd,
    F: FeedRead,
    F::Error: Into<E>,
    E: From<io::Error>,
{
    let _nonblock = nonblock(reader)?;

    loop {
        match reader.fill_buf() {
            Ok(buf) => match ok!(feed.feed(buf)) {
                ControlFlow::Continue(consumed) => reader.consume(consumed),
                ControlFlow::Break(consumed) => {
                    reader.consume(consumed);
                    ok!(feed.finish());
                    return Ok(feed);
                }
            },
            Err(err) if err.would_block() => break,
            Err(err) => return Err(err.into()),
        }
    }

    loop {
        ok!(poll_read(reader.as_raw_fd(), timeout as i32));

        loop {
            let buf = match reader.fill_buf() {
                Ok(buf) => buf,
                Err(err) if err.is_interrupted() => continue,
                Err(err) if err.would_block() => {
                    ok!(feed.finish());
                    return Ok(feed);
                }
                Err(err) => return Err(err.into()),
            };

            if buf.is_empty() {
                ok!(feed.finish());
                return Ok(feed);
            }

            match ok!(feed.feed(buf)) {
                ControlFlow::Continue(n) => reader.consume(n),
                ControlFlow::Break(n) => {
                    reader.consume(n);
                    ok!(feed.finish());
                    return Ok(feed);
                }
            }
        }
    }
}

#[inline]
fn check_tty(fd: io::RawFd) -> io::Result<()> {
    if !fd.is_terminal() {
        Err(Errno::ENOTTY.into())
    } else {
        Ok(())
    }
}

pub fn secure_read<B, F, E>(reader: &mut B, feed: F, timeout: u32) -> Result<F, E>
where
    B: io::BufRead + io::AsRawFd,
    F: FeedRead,
    F::Error: Into<E>,
    E: From<io::Error>,
{
    ok!(check_tty(reader.as_raw_fd()));
    _secure_read(reader, feed, timeout)
}

pub fn secure_read_noecho<B, F, E>(reader: &mut B, feed: F, timeout: u32) -> Result<F, E>
where
    B: io::BufRead + io::AsRawFd,
    F: FeedRead,
    F::Error: Into<E>,
    E: From<io::Error>,
{
    ok!(check_tty(reader.as_raw_fd()));
    let _noecho = noecho(reader)?;
    _secure_read(reader, feed, timeout)
}
