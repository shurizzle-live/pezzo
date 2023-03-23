#![allow(non_camel_case_types)]

use std::{ffi::CStr, io::Write, ptr};

use super::Context;

type pam_handle_t = ();

#[repr(C)]
struct pam_message {
    pub msg_style: core::ffi::c_int,
    pub msg: *const u8,
}

#[repr(C)]
struct pam_response {
    pub resp: *mut u8,
    pub resp_retcode: core::ffi::c_int,
}

#[repr(C)]
struct pam_conv {
    conv: unsafe extern "C" fn(
        num_msg: core::ffi::c_int,
        msg: *const *const pam_message,
        resp: *mut *mut pam_response,
        appdata_ptr: *mut core::ffi::c_void,
    ) -> core::ffi::c_int,
    appdata_ptr: *mut core::ffi::c_void,
}

#[link(name = "pam")]
extern "C" {
    fn pam_start(
        service_name: *const i8,
        user: *const i8,
        pam_conv: *const pam_conv,
        pamh: *mut *mut pam_handle_t,
    ) -> core::ffi::c_int;

    fn pam_authenticate(pamh: *mut pam_handle_t, flags: core::ffi::c_int) -> core::ffi::c_int;

    fn pam_end(pamh: *mut pam_handle_t, pam_status: core::ffi::c_int);

    fn pam_strerror(pamh: *mut pam_handle_t, errnum: core::ffi::c_int) -> *const i8;
}

unsafe extern "C" fn conversation(
    num_msg: core::ffi::c_int,
    msg: *const *const pam_message,
    resp: *mut *mut pam_response,
    appdata_ptr: *mut core::ffi::c_void,
) -> core::ffi::c_int {
    *resp = libc::malloc(std::mem::size_of::<pam_response>() * num_msg as usize) as *mut _;

    if (*resp).is_null() {
        return 5;
    }

    let ctx = &mut *(appdata_ptr as *mut Context);
    let msgs = std::slice::from_raw_parts(*msg, num_msg as usize);
    let resps = std::slice::from_raw_parts_mut(*resp, num_msg as usize);

    for (i, msg) in msgs.iter().enumerate() {
        let res = &mut resps[i];

        match msg.msg_style {
            1 => {
                if !msg.msg.is_null() {
                    _ = ctx
                        .tty_out()
                        .write_all(CStr::from_ptr(msg.msg as *const _).to_bytes());
                    _ = ctx.tty_out().flush();
                }
                let timeout = ctx.prompt_timeout();
                match ctx.tty_in().c_readline_noecho(timeout) {
                    Ok(buf) => {
                        res.resp = buf.leak_c_string();
                        res.resp_retcode = 0;
                    }
                    Err(_) => {
                        res.resp = ptr::null_mut();
                        res.resp_retcode = 19;
                    }
                }
            }
            2 => {
                if !msg.msg.is_null() {
                    _ = ctx
                        .tty_out()
                        .write_all(CStr::from_ptr(msg.msg as *const _).to_bytes());
                    _ = ctx.tty_out().flush();
                }
                let timeout = ctx.prompt_timeout();
                match ctx.tty_in().c_readline(timeout) {
                    Ok(buf) => {
                        res.resp = buf.leak_c_string();
                        res.resp_retcode = 0;
                    }
                    Err(_) => {
                        res.resp = ptr::null_mut();
                        res.resp_retcode = 19;
                    }
                }
            }
            3 | 4 => {
                if !msg.msg.is_null() {
                    _ = ctx
                        .tty_out()
                        .write(CStr::from_ptr(msg.msg as *const _).to_bytes());
                    _ = ctx.tty_out().flush();
                }
            }
            _ => {
                res.resp = ptr::null_mut();
                res.resp_retcode = 19;
            }
        }
    }

    0
}

pub fn authenticate(
    service_name: &CStr,
    user: Option<&CStr>,
    ctx: &mut Context,
) -> Result<(), &'static CStr> {
    unsafe {
        let conv = pam_conv {
            conv: conversation,
            appdata_ptr: ctx as *mut Context as *mut core::ffi::c_void,
        };

        let pamh = {
            let mut pamh = ptr::null_mut();
            let rc = pam_start(
                service_name.as_ptr(),
                user.map(|u| u.as_ptr()).unwrap_or(ptr::null()),
                &conv,
                &mut pamh,
            );
            if rc != 0 {
                return Err(CStr::from_bytes_with_nul_unchecked(
                    b"cannot instantiate pam\0",
                ));
            }
            pamh
        };

        let rc = pam_authenticate(pamh, 1);

        let res = if rc != 0 {
            let err = pam_strerror(pamh, rc);
            if err.is_null() {
                Err(CStr::from_bytes_with_nul_unchecked(b"unknown pam error\0"))
            } else {
                Err(CStr::from_ptr(err))
            }
        } else {
            Ok(())
        };

        pam_end(pamh, rc);

        res
    }
}
