#![allow(non_camel_case_types)]

mod sys;

use std::{
    ffi::CStr,
    fmt,
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

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum Error {
    Open,
    Symbol,
    Service,
    System,
    Buffer,
    PermissionDenied,
    Authorization,
    CredentialsInsufficient,
    AuthInfoUnavailable,
    UserUnknown,
    MaxTries,
    NewAuthTokenRequired,
    AccountExpired,
    Session,
    CredentialsUnavailable,
    CredentialsExpired,
    Credentials,
    NoModuleData,
    Conversation,
    AuthorizationToken,
    AuthorizationTokenRecover,
    AuthorizationTokenLock,
    AuthorizationTokenDisableAging,
    TryAgain,
    Ignore,
    Abort,
    AuthorizationTokenExpired,
    ModuleUnknown,
    BadItem,
    ConversationAgain,
    Incomplete,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let error_str = match self {
            Self::Open => "Failed to load module",
            Self::Symbol => "Symbol not found",
            Self::Service => "Error in service module",
            Self::System => "System error",
            Self::Buffer => "Memory buffer error",
            Self::PermissionDenied => "Permission denied",
            Self::Authorization => "Authentication failure",
            Self::CredentialsInsufficient => {
                "Insufficient credentials to access authentication data"
            }
            Self::AuthInfoUnavailable => {
                "Authentication service cannot retrieve authentication info"
            }
            Self::UserUnknown => "User not known to the underlying authentication module",
            Self::MaxTries => "Have exhausted maximum number of retries for service",
            Self::NewAuthTokenRequired => {
                "Authentication token is no longer valid; new one required"
            }
            Self::AccountExpired => "User account has expired",
            Self::Session => "Cannot make/remove an entry for the specified session",
            Self::CredentialsUnavailable => {
                "Authentication service cannot retrieve user credentials"
            }
            Self::CredentialsExpired => "User credentials expired",
            Self::Credentials => "Failure setting user credentials",
            Self::NoModuleData => "No module specific data is present",
            Self::Conversation => "Conversation error",
            Self::AuthorizationToken => "Authentication token manipulation error",
            Self::AuthorizationTokenRecover => "Authentication information cannot be recovered",
            Self::AuthorizationTokenLock => "Authentication token lock busy",
            Self::AuthorizationTokenDisableAging => "Authentication token aging disabled",
            Self::TryAgain => "Failed preliminary check by password service",
            Self::Ignore => "The return value should be ignored by PAM dispatch",
            Self::Abort => "Critical error - immediate abort",
            Self::AuthorizationTokenExpired => "Authentication token expired",
            Self::ModuleUnknown => "Module is unknown",
            Self::BadItem => "Bad item passed to pam_*_item()",
            Self::ConversationAgain => "Conversation is waiting for event",
            Self::Incomplete => "Application needs to call libpam again",
        };
        fmt::Display::fmt(error_str, f)
    }
}

impl std::error::Error for Error {}

impl From<libc::c_int> for Error {
    fn from(raw: libc::c_int) -> Self {
        match raw {
            sys::PAM_OPEN_ERR => Self::Open,
            sys::PAM_SYMBOL_ERR => Self::Symbol,
            sys::PAM_SERVICE_ERR => Self::Service,
            sys::PAM_SYSTEM_ERR => Self::System,
            sys::PAM_BUF_ERR => Self::Buffer,
            sys::PAM_PERM_DENIED => Self::PermissionDenied,
            sys::PAM_AUTH_ERR => Self::Authorization,
            sys::PAM_CRED_INSUFFICIENT => Self::CredentialsInsufficient,
            sys::PAM_AUTHINFO_UNAVAIL => Self::AuthInfoUnavailable,
            sys::PAM_USER_UNKNOWN => Self::UserUnknown,
            sys::PAM_MAXTRIES => Self::MaxTries,
            sys::PAM_NEW_AUTHTOK_REQD => Self::NewAuthTokenRequired,
            sys::PAM_ACCT_EXPIRED => Self::AccountExpired,
            sys::PAM_SESSION_ERR => Self::Session,
            sys::PAM_CRED_UNAVAIL => Self::CredentialsUnavailable,
            sys::PAM_CRED_EXPIRED => Self::CredentialsExpired,
            sys::PAM_CRED_ERR => Self::Credentials,
            sys::PAM_NO_MODULE_DATA => Self::NoModuleData,
            sys::PAM_CONV_ERR => Self::Conversation,
            sys::PAM_AUTHTOK_ERR => Self::AuthorizationToken,
            sys::PAM_AUTHTOK_RECOVER_ERR => Self::AuthorizationTokenRecover,
            sys::PAM_AUTHTOK_LOCK_BUSY => Self::AuthorizationTokenLock,
            sys::PAM_AUTHTOK_DISABLE_AGING => Self::AuthorizationTokenDisableAging,
            sys::PAM_TRY_AGAIN => Self::TryAgain,
            sys::PAM_IGNORE => Self::Ignore,
            sys::PAM_ABORT => Self::Abort,
            sys::PAM_AUTHTOK_EXPIRED => Self::AuthorizationTokenExpired,
            sys::PAM_MODULE_UNKNOWN => Self::ModuleUnknown,
            sys::PAM_BAD_ITEM => Self::BadItem,
            sys::PAM_CONV_AGAIN => Self::ConversationAgain,
            sys::PAM_INCOMPLETE => Self::Incomplete,
            x => unreachable!("unknown error {}", x),
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<libc::c_int> for Error {
    fn into(self) -> libc::c_int {
        match self {
            Self::Open => sys::PAM_OPEN_ERR,
            Self::Symbol => sys::PAM_SYMBOL_ERR,
            Self::Service => sys::PAM_SERVICE_ERR,
            Self::System => sys::PAM_SYSTEM_ERR,
            Self::Buffer => sys::PAM_BUF_ERR,
            Self::PermissionDenied => sys::PAM_PERM_DENIED,
            Self::Authorization => sys::PAM_AUTH_ERR,
            Self::CredentialsInsufficient => sys::PAM_CRED_INSUFFICIENT,
            Self::AuthInfoUnavailable => sys::PAM_AUTHINFO_UNAVAIL,
            Self::UserUnknown => sys::PAM_USER_UNKNOWN,
            Self::MaxTries => sys::PAM_MAXTRIES,
            Self::NewAuthTokenRequired => sys::PAM_NEW_AUTHTOK_REQD,
            Self::AccountExpired => sys::PAM_ACCT_EXPIRED,
            Self::Session => sys::PAM_SESSION_ERR,
            Self::CredentialsUnavailable => sys::PAM_CRED_UNAVAIL,
            Self::CredentialsExpired => sys::PAM_CRED_EXPIRED,
            Self::Credentials => sys::PAM_CRED_ERR,
            Self::NoModuleData => sys::PAM_NO_MODULE_DATA,
            Self::Conversation => sys::PAM_CONV_ERR,
            Self::AuthorizationToken => sys::PAM_AUTHTOK_ERR,
            Self::AuthorizationTokenRecover => sys::PAM_AUTHTOK_RECOVER_ERR,
            Self::AuthorizationTokenLock => sys::PAM_AUTHTOK_LOCK_BUSY,
            Self::AuthorizationTokenDisableAging => sys::PAM_AUTHTOK_DISABLE_AGING,
            Self::TryAgain => sys::PAM_TRY_AGAIN,
            Self::Ignore => sys::PAM_IGNORE,
            Self::Abort => sys::PAM_ABORT,
            Self::AuthorizationTokenExpired => sys::PAM_AUTHTOK_EXPIRED,
            Self::ModuleUnknown => sys::PAM_MODULE_UNKNOWN,
            Self::BadItem => sys::PAM_BAD_ITEM,
            Self::ConversationAgain => sys::PAM_CONV_AGAIN,
            Self::Incomplete => sys::PAM_INCOMPLETE,
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
                        resp.resp = buf.leak_c_string().cast();
                        resp.resp_retcode = sys::PAM_SUCCESS;
                    }
                    Err(err) => {
                        resp.resp = ptr::null_mut();
                        resp.resp_retcode = err.into();
                    }
                },
                sys::PAM_PROMPT_ECHO_ON => match conv.prompt_noecho(CStr::from_ptr(msg.msg)) {
                    Ok(buf) => {
                        resp.resp = buf.leak_c_string().cast();
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

pub struct LinesIterator<'a> {
    slice: Option<&'a [u8]>,
}

impl<'a> LinesIterator<'a> {
    #[inline]
    pub fn new(slice: &'a [u8]) -> Self {
        Self { slice: Some(slice) }
    }
}

impl<'a> Iterator for LinesIterator<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let s = self.slice.take()?;
        if let Some(pos) = memchr::memchr2(b'\r', b'\n', s) {
            let end = match unsafe { s.get_unchecked(pos) } {
                b'\n' if matches!(s.get(pos + 1), Some(b'\r')) => pos + 2,
                b'\r' if matches!(s.get(pos + 1), Some(b'\n')) => pos + 2,
                _ => pos + 1,
            };

            self.slice = s.get(end..);
            s.get(..pos)
        } else {
            Some(s)
        }
    }
}

pub struct PezzoConversation<'a> {
    name: &'a CStr,
    timedout: bool,
    timeout: libc::time_t,
    tty_in: Arc<Mutex<TtyIn>>,
    tty_out: Arc<Mutex<TtyOut>>,
    bell: bool,
}

impl<'a> PezzoConversation<'a> {
    #[inline]
    pub fn new(ctx: &'a super::Context) -> Self {
        Self::from_values(
            ctx.prompt_timeout(),
            ctx.tty_in(),
            ctx.tty_out(),
            ctx.original_user().name(),
            ctx.bell(),
        )
    }

    #[inline]
    pub fn from_values(
        timeout: libc::time_t,
        tty_in: Arc<Mutex<TtyIn>>,
        tty_out: Arc<Mutex<TtyOut>>,
        name: &'a CStr,
        bell: bool,
    ) -> Self {
        Self {
            timeout,
            timedout: false,
            tty_in,
            tty_out,
            name,
            bell,
        }
    }

    fn _prompt(&mut self, prompt: &CStr, echo: bool) -> ConvResult<CBuffer> {
        fn base_prompt_is_password(prompt: &CStr, name: &CStr) -> bool {
            if let Some(rest) = prompt.to_bytes().strip_prefix(b"Password:") {
                return rest.is_empty() || rest == b" ";
            } else if let Some(rest) = prompt.to_bytes().get(name.to_bytes().len()..) {
                if let Some(rest) = rest.strip_prefix(b"'s Password:") {
                    return rest.is_empty() || rest == b" ";
                }
            }

            false
        }

        #[cfg(not(target_os = "linux"))]
        #[inline(always)]
        fn prompt_is_password(prompt: &CStr, name: &CStr) -> bool {
            base_prompt_is_password(prompt, name)
        }

        #[cfg(target_os = "linux")]
        #[inline(always)]
        fn prompt_is_password(prompt: &CStr, name: &CStr) -> bool {
            extern "C" {
                fn dgettext(domainname: *const i8, msgid: *const i8) -> *const i8;
            }
            const DOMAIN: *const i8 = b"Linux-PAM\0".as_ptr() as *const i8;

            unsafe {
                libc::strcmp(
                    prompt.as_ptr(),
                    dgettext(DOMAIN, "Password:".as_ptr().cast()).cast(),
                ) == 0
                    || libc::strcmp(
                        prompt.as_ptr(),
                        dgettext(DOMAIN, "Password: ".as_ptr().cast()).cast(),
                    ) == 0
                    || base_prompt_is_password(prompt, name)
            }
        }

        if prompt_is_password(prompt, self.name) {
            self.print_prompt_password()?;
        } else {
            let mut out = self.tty_out.lock().expect("tty is poisoned");
            let mut it = LinesIterator::new(prompt.to_bytes());
            if let Some(mut prev) = it.next() {
                for mut line in it {
                    mem::swap(&mut line, &mut prev);

                    out.write_all(line).map_err(|_| ConvError::Conversation)?;
                    out.write_all(b"\r\n")
                        .map_err(|_| ConvError::Conversation)?;
                }
                let line = prev;
                if !line.is_empty() {
                    out.write_all(line).map_err(|_| ConvError::Conversation)?;
                    if unsafe { *line.get_unchecked(line.len() - 1) } != b' ' {
                        out.write_all(b" ").map_err(|_| ConvError::Conversation)?;
                    }
                }
            }

            if self.bell {
                out.write_all(b"\x07")
                    .map_err(|_| ConvError::Conversation)?;
            }

            out.flush().map_err(|_| ConvError::Conversation)?;
        }

        let timeout = self.prompt_timeout();
        let buf = {
            let mut inp = self.tty_in.lock().expect("tty is poisoned");
            let line_res = if echo {
                inp.c_readline(timeout)
            } else {
                inp.c_readline_noecho(timeout)
            };
            match line_res {
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

    fn print_message(&mut self, message: &[u8]) -> ConvResult<()> {
        let mut out = self.tty_out.lock().expect("tty is poisoned");
        let mut it = LinesIterator::new(message);
        if let Some(mut prev) = it.next() {
            for mut line in it {
                mem::swap(&mut line, &mut prev);

                out.write_all(line).map_err(|_| ConvError::Conversation)?;
                out.write_all(b"\r\n")
                    .map_err(|_| ConvError::Conversation)?;
            }
            let line = prev;
            if !line.is_empty() {
                out.write_all(line).map_err(|_| ConvError::Conversation)?;
                out.write_all(b"\r\n")
                    .map_err(|_| ConvError::Conversation)?;
            }
        }
        out.flush().map_err(|_| ConvError::Conversation)
    }

    pub fn print_prompt_password(&mut self) -> ConvResult<()> {
        let mut out = self.tty_out.lock().expect("tty is poisoned");
        out.write_all(b"[pezzo] Password for ")
            .map_err(|_| ConvError::Conversation)?;
        out.write_all(self.name.to_bytes())
            .map_err(|_| ConvError::Conversation)?;
        out.write_all(b": ").map_err(|_| ConvError::Conversation)?;
        if self.bell {
            out.write_all(b"\x07")
                .map_err(|_| ConvError::Conversation)?;
        }
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

    fn info(&mut self, message: &CStr) -> ConvResult<()> {
        self.print_message(message.to_bytes())
    }

    fn error(&mut self, message: &CStr) -> ConvResult<()> {
        self.print_message(message.to_bytes())
    }
}
