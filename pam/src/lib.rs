#![cfg(unix)]
#![no_std]

extern crate alloc as alloc_crate;

use alloc_crate::boxed::Box;
use core::{ffi::CStr, marker::PhantomData, mem::MaybeUninit, pin::Pin};

include!(concat!(env!("OUT_DIR"), "/pam.rs"));

impl ::core2::error::Error for Error {}

impl Error {
    #[inline]
    pub const fn new(value: i32) -> Self {
        Self(value)
    }

    #[inline]
    pub fn as_i32(&self) -> i32 {
        self.0
    }
}

impl From<i32> for Error {
    #[inline]
    fn from(value: i32) -> Self {
        Self::new(value)
    }
}

impl From<Error> for i32 {
    #[inline]
    fn from(value: Error) -> Self {
        value.0
    }
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConvError {
    Generic = self::sys::PAM_CONV_ERR,
    Buffer = self::sys::PAM_BUF_ERR,
}

#[allow(non_upper_case_globals)]
impl ConvError {
    #[inline]
    pub const fn as_i32(&self) -> i32 {
        *self as i32
    }
}

impl From<ConvError> for i32 {
    #[inline]
    fn from(value: ConvError) -> Self {
        value as i32
    }
}

impl From<ConvError> for Error {
    #[inline]
    fn from(value: ConvError) -> Self {
        Self::new(value as i32)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

pub type ConvResult<T> = core::result::Result<T, ConvError>;

pub trait CBuffer {
    fn leak_c_string(self) -> *mut libc::c_char;
}

pub trait Conversation {
    type Buffer: CBuffer;

    fn preflight(&mut self) {}

    fn prompt(&mut self, prompt: &CStr) -> ConvResult<Self::Buffer>;

    fn prompt_noecho(&mut self, prompt: &CStr) -> ConvResult<Self::Buffer>;

    fn info(&mut self, prompt: &CStr) -> ConvResult<()>;

    fn error(&mut self, prompt: &CStr) -> ConvResult<()>;
}

unsafe extern "C" fn conversation_trampoline<C: Conversation>(
    num_msg: libc::c_int,
    msg: *mut *const self::sys::pam_message,
    resp: *mut *mut self::sys::pam_response,
    appdata_ptr: *mut libc::c_void,
) -> i32 {
    unsafe {
        *resp = libc::malloc(core::mem::size_of::<sys::pam_response>() * num_msg as usize)
            as *mut sys::pam_response;
        if (*resp).is_null() {
            return self::sys::PAM_BUF_ERR;
        }
        let conv = &mut *(appdata_ptr as *mut C);

        for (i, msg) in core::slice::from_raw_parts(*msg, num_msg as usize)
            .iter()
            .enumerate()
        {
            let resp = &mut *(*resp).add(i);

            match msg.msg_style {
                self::sys::PAM_PROMPT_ECHO_OFF => match conv.prompt_noecho(CStr::from_ptr(msg.msg))
                {
                    Ok(buf) => {
                        resp.resp = buf.leak_c_string();
                        resp.resp_retcode = self::sys::PAM_SUCCESS as _;
                    }
                    Err(err) => {
                        resp.resp = core::ptr::null_mut();
                        resp.resp_retcode = err as _;
                    }
                },
                sys::PAM_PROMPT_ECHO_ON => match conv.prompt_noecho(CStr::from_ptr(msg.msg)) {
                    Ok(buf) => {
                        resp.resp = buf.leak_c_string().cast();
                        resp.resp_retcode = self::sys::PAM_SUCCESS as _;
                    }
                    Err(err) => {
                        resp.resp = core::ptr::null_mut();
                        resp.resp_retcode = err as _;
                    }
                },
                sys::PAM_TEXT_INFO => match conv.info(CStr::from_ptr(msg.msg)) {
                    Ok(()) => {
                        resp.resp = core::ptr::null_mut();
                        resp.resp_retcode = self::sys::PAM_SUCCESS as _;
                    }
                    Err(err) => {
                        resp.resp = core::ptr::null_mut();
                        resp.resp_retcode = err as _;
                    }
                },
                sys::PAM_ERROR_MSG => match conv.error(CStr::from_ptr(msg.msg)) {
                    Ok(()) => {
                        resp.resp = core::ptr::null_mut();
                        resp.resp_retcode = self::sys::PAM_SUCCESS as _;
                    }
                    Err(err) => {
                        resp.resp = core::ptr::null_mut();
                        resp.resp_retcode = err as _;
                    }
                },
                _ => {
                    resp.resp = core::ptr::null_mut();
                    resp.resp_retcode = self::sys::PAM_CONV_ERR as _;
                }
            }
        }
    }

    sys::PAM_SUCCESS
}

pub struct Pam<'a, C: Conversation> {
    last_status: libc::c_int,
    pamh: *mut sys::pam_handle_t,
    conv: Pin<Box<C>>,
    _life: PhantomData<&'a ()>,
}

impl<'a, C: Conversation> Pam<'a, C> {
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
                user.map_or(core::ptr::null(), |x| x.as_ptr()),
                &c,
                pamh.as_mut_ptr(),
            );

            if rc != self::sys::PAM_SUCCESS {
                Err(rc.into())
            } else {
                Ok(Pam {
                    last_status: self::sys::PAM_SUCCESS as _,
                    pamh: pamh.assume_init(),
                    conv,
                    _life: PhantomData,
                })
            }
        }
    }

    pub fn authenticate(&mut self) -> Result<()> {
        const FLAGS: i32 = sys::PAM_SILENT | sys::PAM_DISALLOW_NULL_AUTHTOK;

        unsafe {
            self.get_conv_mut().get_unchecked_mut().preflight();

            self.last_status = sys::pam_authenticate(self.pamh, FLAGS as _);
            if self.last_status != self::sys::PAM_SUCCESS as _ {
                return Err(self.last_status.into());
            }

            self.last_status = sys::pam_acct_mgmt(self.pamh, FLAGS as _);
            if self.last_status != self::sys::PAM_SUCCESS as _ {
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
