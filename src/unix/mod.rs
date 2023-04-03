mod common;
mod iam;
mod pam;
pub mod tty;
#[cfg(target_os = "linux")]
#[macro_use]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod bsd;
use std::{
    ffi::CStr,
    io::{self, Write},
    path::Path,
    sync::{Arc, Mutex},
};

mod process;

#[cfg(target_os = "macos")]
pub use bsd::*;
#[cfg(target_os = "linux")]
pub use linux::*;

pub use iam::IAMContext;
pub use process::*;
pub use tty::TtyInfo;

use crate::database::{Database, Entry};

use self::tty::{TtyIn, TtyOut};

pub struct Pwd {
    pub name: Box<CStr>,
    pub uid: u32,
    pub home: Box<CStr>,
    pub gid: u32,
}

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
    target_group: Group,
}

impl Context {
    pub fn new(
        iam: IAMContext,
        proc_ctx: ProcessContext,
        target_user: User,
        target_group: Group,
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
    pub fn target_group(&self) -> &Group {
        &self.target_group
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

    // TODO: implement proper error handling
    pub fn authenticate(&self, timeout: u64) {
        let out = self.tty_out();

        {
            let db = Database::new(self.original_user().name()).unwrap();
            if let Some(entry) = db
                .iter()
                .find(|&e| e.session_id() == self.proc_ctx.sid && e.tty() == self.ttyno())
            {
                let time = time::now();
                if (entry.last_login()..=(entry.last_login() + timeout)).contains(&time) {
                    return;
                }
            }
        }

        let mut auth = self.authenticator().unwrap();

        for i in 1..=self.max_retries() {
            if matches!(auth.authenticate(), Ok(_)) {
                let mut db = Database::new(self.original_user().name()).unwrap();
                db.retain(|e| e.session_id() != self.proc_ctx.sid && e.tty() != self.ttyno());
                db.push(Entry {
                    session_id: self.proc_ctx.sid,
                    tty: self.ttyno(),
                    last_login: time::now(),
                });
                db.save().unwrap();

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

    #[inline]
    pub fn escalate_permissions(&self) -> io::Result<()> {
        self.iam.escalate_permissions()
    }

    #[inline]
    pub fn set_identity(&self, uid: u32, gid: u32) -> io::Result<()> {
        self.iam.set_identity(uid, gid)
    }

    #[inline]
    pub fn set_effective_identity(&self, uid: u32, gid: u32) -> io::Result<()> {
        self.iam.set_effective_identity(uid, gid)
    }

    #[inline]
    pub fn set_groups<B: AsRef<[u32]>>(&self, groups: B) -> io::Result<()> {
        self.iam.set_groups(groups)
    }

    #[inline]
    pub fn get_group_ids<B: AsRef<CStr>>(&self, user_name: B) -> io::Result<Vec<u32>> {
        self.iam.get_group_ids(user_name)
    }
}
