mod common;
mod iam;
mod pam;
pub mod tty;
#[cfg(target_os = "linux")]
#[macro_use]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
use std::{
    ffi::CStr,
    io::{self, Write},
    path::Path,
    sync::{Arc, Mutex},
};

mod process;

pub use iam::IAMContext;
pub use process::*;
pub use tty::TtyInfo;

use self::tty::{TtyIn, TtyOut};

#[cfg(target_os = "linux")]
#[inline(always)]
#[doc(hidden)]
pub unsafe fn __errno() -> *mut libc::c_int {
    libc::__errno_location()
}

#[cfg(target_os = "macos")]
#[inline(always)]
#[doc(hidden)]
pub unsafe fn __errno() -> *mut libc::c_int {
    libc::__error()
}

pub struct Context {
    iam: IAMContext,
    proc_ctx: ProcessContext,
    tty_ctx: TtyInfo,
    tty_in: Arc<Mutex<TtyIn>>,
    tty_out: Arc<Mutex<TtyOut>>,
    target_user: User,
    target_group: Option<Group>,
}

impl Context {
    pub fn new(
        iam: IAMContext,
        proc_ctx: ProcessContext,
        target_user: User,
        target_group: Option<Group>,
    ) -> io::Result<Self> {
        let tty_ctx = TtyInfo::for_ttyno(proc_ctx.ttyno)?;
        let tty_in = Arc::new(Mutex::new(tty_ctx.open_in()?));
        let tty_out = Arc::new(Mutex::new(tty_ctx.open_out()?));

        Ok(Self {
            iam,
            proc_ctx,
            tty_ctx,
            tty_in,
            tty_out,
            target_user,
            target_group,
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
    pub fn target_user(&self) -> &User {
        &self.target_user
    }

    #[inline]
    pub fn target_group(&self) -> Option<&Group> {
        self.target_group.as_ref()
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
    pub fn max_retries(&self) -> usize {
        3
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

    pub fn authenticate(&self) {
        let out = self.tty_out();

        {
            let uid = self.target_user.id();
            let gid = self
                .target_group()
                .map(|g| g.id)
                .unwrap_or_else(|| self.original_group().id);
            self.iam.set_effective_identity(uid, gid).unwrap();
        }

        let mut auth = self.authenticator().unwrap();

        for i in 1..=self.max_retries() {
            if matches!(auth.authenticate(), Ok(_)) {
                return;
            }

            if auth.get_conv().is_timedout() {
                break;
            }

            {
                let mut out = out.lock().expect("tty is poisoned");
                if i == self.max_retries() {
                    _ = writeln!(out, "pezzo: {} incorrect password attempts", i);
                } else {
                    _ = writeln!(out, "Sorry, try again.");
                }
                _ = out.flush();
            }
        }
        std::process::exit(1);
    }
}
