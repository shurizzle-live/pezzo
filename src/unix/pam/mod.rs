#![allow(non_camel_case_types)]

mod sys;

use std::{
    ffi::CStr,
    io::{self, Write},
    marker::PhantomData,
    mem::{self, MaybeUninit},
    pin::Pin,
    ptr,
    sync::{Arc, Mutex},
};

use super::{
    common::CBuffer,
    tty::{TtyIn, TtyOut},
};

#[derive(Debug, Clone, Copy)]
pub enum Error {
    Abort,
    Buffer,
    System,
    Authorization,
    CredentialInsufficient,
    InfoUnavailable,
    MaxTries,
    UserUnknown,
    AccountExpired,
    NewAuthTokenRequired,
    PermissionDenied,
    AuthorizationToken,
}

impl From<libc::c_int> for Error {
    fn from(raw: libc::c_int) -> Self {
        match raw {
            sys::PAM_ABORT => Self::Abort,
            sys::PAM_BUF_ERR => Self::Buffer,
            sys::PAM_SYSTEM_ERR => Self::System,
            sys::PAM_AUTH_ERR => Self::Authorization,
            sys::PAM_CRED_INSUFFICIENT => Self::CredentialInsufficient,
            sys::PAM_AUTHINFO_UNAVAIL => Self::InfoUnavailable,
            sys::PAM_MAXTRIES => Self::MaxTries,
            sys::PAM_USER_UNKNOWN => Self::UserUnknown,
            sys::PAM_ACCT_EXPIRED => Self::AccountExpired,
            sys::PAM_NEW_AUTHTOK_REQD => Self::NewAuthTokenRequired,
            sys::PAM_PERM_DENIED => Self::PermissionDenied,
            sys::PAM_AUTHTOK_ERR => Self::AuthorizationToken,
            x => unreachable!("unknown error {}", x),
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<libc::c_int> for Error {
    fn into(self) -> libc::c_int {
        match self {
            Self::Abort => sys::PAM_ABORT,
            Self::Buffer => sys::PAM_BUF_ERR,
            Self::System => sys::PAM_SYSTEM_ERR,
            Self::Authorization => sys::PAM_AUTH_ERR,
            Self::CredentialInsufficient => sys::PAM_CRED_INSUFFICIENT,
            Self::InfoUnavailable => sys::PAM_AUTHINFO_UNAVAIL,
            Self::MaxTries => sys::PAM_MAXTRIES,
            Self::UserUnknown => sys::PAM_USER_UNKNOWN,
            Self::AccountExpired => sys::PAM_ACCT_EXPIRED,
            Self::NewAuthTokenRequired => sys::PAM_NEW_AUTHTOK_REQD,
            Self::PermissionDenied => sys::PAM_PERM_DENIED,
            Self::AuthorizationToken => sys::PAM_AUTHTOK_ERR,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ConvError {
    Conversation,
    BufferError,
}

impl From<libc::c_int> for ConvError {
    fn from(raw: libc::c_int) -> Self {
        match raw {
            sys::PAM_CONV_ERR => Self::Conversation,
            sys::PAM_BUF_ERR => Self::BufferError,
            _ => unreachable!(),
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<libc::c_int> for ConvError {
    fn into(self) -> libc::c_int {
        match self {
            Self::Conversation => sys::PAM_CONV_ERR,
            Self::BufferError => sys::PAM_BUF_ERR,
        }
    }
}

unsafe extern "C" fn conversation_trampoline<C: Conversation>(
    num_msg: core::ffi::c_int,
    msg: *mut *const sys::pam_message,
    resp: *mut *mut sys::pam_response,
    appdata_ptr: *mut core::ffi::c_void,
) -> core::ffi::c_int {
    unsafe {
        *resp = libc::malloc(mem::size_of::<sys::pam_response>() * num_msg as usize)
            as *mut sys::pam_response;
        if (*resp).is_null() {
            return sys::PAM_BUF_ERR;
        }
        let conv = &mut *(appdata_ptr as *mut C);

        for (i, msg) in std::slice::from_raw_parts(*msg, num_msg as usize)
            .iter()
            .enumerate()
        {
            let resp = &mut *(*resp).add(i);

            match msg.msg_style {
                sys::PAM_PROMPT_ECHO_OFF => match conv.prompt_noecho(CStr::from_ptr(msg.msg)) {
                    Ok(buf) => {
                        resp.resp = buf.leak_c_string() as *mut i8;
                        resp.resp_retcode = sys::PAM_SUCCESS;
                    }
                    Err(err) => {
                        resp.resp = ptr::null_mut();
                        resp.resp_retcode = err.into();
                    }
                },
                sys::PAM_PROMPT_ECHO_ON => match conv.prompt_noecho(CStr::from_ptr(msg.msg)) {
                    Ok(buf) => {
                        resp.resp = buf.leak_c_string() as *mut i8;
                        resp.resp_retcode = sys::PAM_SUCCESS;
                    }
                    Err(err) => {
                        resp.resp = ptr::null_mut();
                        resp.resp_retcode = err.into();
                    }
                },
                sys::PAM_TEXT_INFO => match conv.info(CStr::from_ptr(msg.msg)) {
                    Ok(()) => {
                        resp.resp = ptr::null_mut();
                        resp.resp_retcode = sys::PAM_SUCCESS;
                    }
                    Err(err) => {
                        resp.resp = ptr::null_mut();
                        resp.resp_retcode = err.into();
                    }
                },
                sys::PAM_ERROR_MSG => match conv.error(CStr::from_ptr(msg.msg)) {
                    Ok(()) => {
                        resp.resp = ptr::null_mut();
                        resp.resp_retcode = sys::PAM_SUCCESS;
                    }
                    Err(err) => {
                        resp.resp = ptr::null_mut();
                        resp.resp_retcode = err.into();
                    }
                },
                _ => {
                    resp.resp = ptr::null_mut();
                    resp.resp_retcode = sys::PAM_CONV_ERR;
                }
            }
        }
    }

    sys::PAM_SUCCESS
}

pub type Result<T> = std::result::Result<T, Error>;

pub type ConvResult<T> = std::result::Result<T, ConvError>;

pub trait Conversation {
    fn preflight(&mut self) {}

    fn prompt(&mut self, prompt: &CStr) -> ConvResult<CBuffer>;

    fn prompt_noecho(&mut self, prompt: &CStr) -> ConvResult<CBuffer>;

    fn info(&mut self, prompt: &CStr) -> ConvResult<()>;

    fn error(&mut self, prompt: &CStr) -> ConvResult<()>;
}

pub struct Authenticator<'a, C: Conversation> {
    last_status: libc::c_int,
    pamh: *mut sys::pam_handle_t,
    conv: Pin<Box<C>>,
    _life: PhantomData<&'a ()>,
}

impl<'a, C: Conversation> Authenticator<'a, C> {
    pub fn new(service_name: &'a CStr, user: Option<&'a CStr>, conv: C) -> Result<Self> {
        unsafe {
            let mut conv = Box::pin(conv);
            let c = sys::pam_conv {
                conv: Some(conversation_trampoline::<C>),
                appdata_ptr: conv.as_mut().get_unchecked_mut() as *mut C as *mut libc::c_void,
            };

            let mut pamh = MaybeUninit::<*mut sys::pam_handle_t>::uninit();
            let rc = sys::pam_start(
                service_name.as_ptr(),
                user.map_or(ptr::null(), |x| x.as_ptr()),
                &c,
                pamh.as_mut_ptr(),
            );

            if rc != sys::PAM_SUCCESS {
                Err(rc.into())
            } else {
                Ok(Authenticator {
                    last_status: sys::PAM_SUCCESS,
                    pamh: pamh.assume_init(),
                    conv,
                    _life: PhantomData,
                })
            }
        }
    }

    pub fn authenticate(&mut self) -> Result<()> {
        const FLAGS: libc::c_int = sys::PAM_SILENT | sys::PAM_DISALLOW_NULL_AUTHTOK;

        unsafe {
            self.get_conv_mut().get_unchecked_mut().preflight();

            self.last_status = sys::pam_authenticate(self.pamh, FLAGS);
            if self.last_status != sys::PAM_SUCCESS {
                return Err(self.last_status.into());
            }

            self.last_status = sys::pam_acct_mgmt(self.pamh, FLAGS);
            if self.last_status != sys::PAM_SUCCESS {
                return Err(self.last_status.into());
            }
        }
        Ok(())
    }

    #[inline]
    pub fn get_conv(&self) -> Pin<&C> {
        self.conv.as_ref()
    }

    #[inline]
    pub fn get_conv_mut(&mut self) -> Pin<&mut C> {
        self.conv.as_mut()
    }
}

impl<'a, C: Conversation> Drop for Authenticator<'a, C> {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            _ = sys::pam_end(self.pamh, self.last_status);
        }
    }
}

pub struct PezzoConversation<'a> {
    name: &'a CStr,
    timedout: bool,
    timeout: libc::time_t,
    tty_in: Arc<Mutex<TtyIn>>,
    tty_out: Arc<Mutex<TtyOut>>,
}

impl<'a> PezzoConversation<'a> {
    pub fn new(ctx: &'a super::Context) -> Self {
        Self {
            timeout: ctx.prompt_timeout(),
            timedout: false,
            tty_in: ctx.tty_in(),
            tty_out: ctx.tty_out(),
            name: ctx.original_user().name(),
        }
    }

    fn _prompt(&mut self, prompt: &CStr, echo: bool) -> ConvResult<CBuffer> {
        fn base_prompt_is_password(prompt: &CStr) -> bool {
            if let Some(rest) = prompt.to_bytes().strip_prefix(b"Password:") {
                rest.is_empty() || rest == b" "
            } else {
                false
            }
        }

        #[cfg(not(target_os = "linux"))]
        #[inline(always)]
        fn prompt_is_password(prompt: &CStr) -> bool {
            base_prompt_is_password(prompt)
        }

        #[cfg(target_os = "linux")]
        #[inline(always)]
        fn prompt_is_password(prompt: &CStr) -> bool {
            extern "C" {
                fn dgettext(domainname: *const i8, msgid: *const i8) -> *const i8;
            }
            const DOMAIN: *const i8 = b"Linux-PAM\0".as_ptr() as *const i8;

            unsafe {
                libc::strcmp(
                    prompt.as_ptr(),
                    dgettext(DOMAIN, "Password:".as_ptr() as *const i8),
                ) == 0
                    || libc::strcmp(
                        prompt.as_ptr(),
                        dgettext(DOMAIN, "Password: ".as_ptr() as *const i8),
                    ) == 0
                    || base_prompt_is_password(prompt)
            }
        }

        if prompt_is_password(prompt) {
            _ = self.print_prompt_password();
        } else {
            let mut out = self.tty_out.lock().expect("tty is poisoned");
            _ = out.write_all(prompt.to_bytes());
            _ = out.flush();
        }

        let timeout = self.prompt_timeout();
        let buf = {
            let mut inp = self.tty_in.lock().expect("tty is poisoned");
            match if echo {
                inp.c_readline(timeout)
            } else {
                inp.c_readline_noecho(timeout)
            } {
                Err(err) => {
                    {
                        let mut out = self.tty_out.lock().expect("tty is poisoned");
                        _ = out.write_all(b"\n");
                        _ = out.flush();

                        if err.kind() == io::ErrorKind::TimedOut {
                            self.timedout = true;
                            _ = out.write_all(b"pezzo: timed out reading password\n");
                            _ = out.flush();
                        }
                    }
                    Err(ConvError::Conversation)
                }
                Ok(mut buf) => {
                    if buf.as_slice().last().map_or(false, |&c| c == b'\n') {
                        if let Some(l) = buf.len().checked_sub(1) {
                            buf.truncate(l)
                        }
                    } else {
                        let mut out = self.tty_out.lock().expect("tty is poisoned");
                        _ = out.write_all(b"\n");
                        _ = out.flush();
                    }
                    Ok(buf)
                }
            }?
        };

        Ok(buf)
    }

    pub fn print_prompt_password(&mut self) -> ConvResult<()> {
        let mut out = self.tty_out.lock().expect("tty is poisoned");
        write!(
            out,
            "[pezzo] Password for {}: ",
            self.name.to_string_lossy(),
        )
        .map_err(|_| ConvError::Conversation)?;
        out.flush().map_err(|_| ConvError::Conversation)
    }

    #[inline]
    pub fn prompt_timeout(&self) -> libc::time_t {
        self.timeout
    }

    #[inline]
    pub fn is_timedout(&self) -> bool {
        self.timedout
    }
}

impl<'a> Conversation for PezzoConversation<'a> {
    fn preflight(&mut self) {
        self.timedout = false;
    }

    #[inline]
    fn prompt(&mut self, prompt: &CStr) -> ConvResult<CBuffer> {
        self._prompt(prompt, true)
    }

    #[inline]
    fn prompt_noecho(&mut self, prompt: &CStr) -> ConvResult<CBuffer> {
        self._prompt(prompt, false)
    }

    fn info(&mut self, prompt: &CStr) -> ConvResult<()> {
        let mut out = self.tty_out.lock().expect("tty is poisoned");
        _ = out.write_all(prompt.to_bytes());
        _ = out.flush();
        Ok(())
    }

    fn error(&mut self, prompt: &CStr) -> ConvResult<()> {
        let mut out = self.tty_out.lock().expect("tty is poisoned");
        _ = out.write_all(prompt.to_bytes());
        _ = out.flush();
        Ok(())
    }
}
