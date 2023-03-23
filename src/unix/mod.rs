mod common;
mod pam;
pub mod tty;
#[cfg(target_os = "linux")]
#[macro_use]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
use std::{ffi::CStr, io, path::Path};

mod process;

pub use process::*;
pub use tty::TtyInfo;

use self::tty::{TtyIn, TtyOut};

pub struct Context {
    proc_ctx: ProcessContext,
    tty_ctx: TtyInfo,
    tty_in: TtyIn,
    tty_out: TtyOut,
}

impl Context {
    pub fn current() -> io::Result<Self> {
        let proc_ctx = ProcessContext::current()?;
        let tty_ctx = TtyInfo::for_ttyno(proc_ctx.ttyno)?;
        let tty_in = tty_ctx.open_in()?;
        let tty_out = tty_ctx.open_out()?;

        Ok(Self {
            proc_ctx,
            tty_ctx,
            tty_in,
            tty_out,
        })
    }

    #[inline]
    pub fn exe(&self) -> &Path {
        &self.proc_ctx.exe
    }

    #[inline]
    pub fn pid(&self) -> u32 {
        self.proc_ctx.pid
    }

    #[inline]
    pub fn original_uid(&self) -> u32 {
        self.proc_ctx.original_uid
    }

    #[inline]
    pub fn original_gid(&self) -> u32 {
        self.proc_ctx.original_gid
    }

    #[inline]
    pub fn sid(&self) -> u32 {
        self.proc_ctx.sid
    }

    #[inline]
    pub fn ttyno(&self) -> u32 {
        self.proc_ctx.ttyno
    }

    #[inline]
    pub fn tty_path(&self) -> &Path {
        self.tty_ctx.path()
    }

    #[inline]
    pub fn tty_name(&self) -> &str {
        self.tty_ctx.name()
    }

    #[inline]
    pub fn tty_in(&mut self) -> &mut TtyIn {
        &mut self.tty_in
    }

    #[inline]
    pub fn tty_out(&mut self) -> &mut TtyOut {
        &mut self.tty_out
    }

    #[inline]
    pub fn tty_inout(&mut self) -> (&mut TtyIn, &mut TtyOut) {
        (&mut self.tty_in, &mut self.tty_out)
    }

    #[inline]
    pub fn prompt_timeout(&self) -> libc::time_t {
        30
    }

    #[inline]
    pub fn authenticate(&mut self, user: Option<&CStr>) -> Result<(), &'static CStr> {
        const SERVICE_NAME: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"sudo\0") };

        pam::authenticate(SERVICE_NAME, user, self)
    }
}
