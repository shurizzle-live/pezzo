mod common;
mod pam;
pub mod tty;
#[cfg(target_os = "linux")]
#[macro_use]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
use std::{
    ffi::CStr,
    io,
    path::Path,
    sync::{Arc, Mutex},
};

mod process;

pub use process::*;
pub use tty::TtyInfo;

use self::tty::{TtyIn, TtyOut};

pub struct Context {
    proc_ctx: ProcessContext,
    tty_ctx: TtyInfo,
    tty_in: Arc<Mutex<TtyIn>>,
    tty_out: Arc<Mutex<TtyOut>>,
}

impl Context {
    pub fn current() -> io::Result<Self> {
        let proc_ctx = ProcessContext::current()?;
        let tty_ctx = TtyInfo::for_ttyno(proc_ctx.ttyno)?;
        let tty_in = Arc::new(Mutex::new(tty_ctx.open_in()?));
        let tty_out = Arc::new(Mutex::new(tty_ctx.open_out()?));

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
    pub fn original_user(&self) -> &User {
        &self.proc_ctx.original_user
    }

    #[inline]
    pub fn original_group(&self) -> &Group {
        &self.proc_ctx.original_group
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
    pub fn tty_in(&self) -> Arc<Mutex<TtyIn>> {
        self.tty_in.clone()
    }

    #[inline]
    pub fn tty_out(&self) -> Arc<Mutex<TtyOut>> {
        self.tty_out.clone()
    }

    #[inline]
    pub fn tty_inout(&self) -> (Arc<Mutex<TtyIn>>, Arc<Mutex<TtyOut>>) {
        (self.tty_in.clone(), self.tty_out.clone())
    }

    #[inline]
    pub fn prompt_timeout(&self) -> libc::time_t {
        30
    }

    #[inline]
    pub fn authenticator(&self) -> pam::Result<pam::Authenticator<pam::PezzoConversation>> {
        const SERVICE_NAME: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"pezzo\0") };

        pam::Authenticator::new(
            SERVICE_NAME,
            Some(self.original_user().name()),
            pam::PezzoConversation::new(self),
        )
    }
}
