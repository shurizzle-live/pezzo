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

fn prompt(ctx: &mut Context, msg: &pam_message, echo: bool) -> pam_response {
    fn prompt_is_password(msg: *const u8) -> bool {
        if msg.is_null() {
            return false;
        }

        let prompt = unsafe { CStr::from_ptr(msg as *const i8) };

        if let Some(rest) = prompt.to_bytes().strip_prefix(b"Password:") {
            rest.is_empty() || rest == b" "
        } else {
            false
        }
    }

    fn _prompt(ctx: &mut Context, msg: &pam_message, echo: bool) -> Option<pam_response> {
        if !msg.msg.is_null() {
            if prompt_is_password(msg.msg) {
                _ = ctx.print_prompt_password();
            } else {
                let out = ctx.tty_out();
                let mut out = out.lock().ok()?;
                _ = out.write_all(unsafe { CStr::from_ptr(msg.msg as *const _).to_bytes() });
                _ = out.flush();
            }
        } else {
            _ = ctx.print_prompt_password();
        }

        let timeout = ctx.prompt_timeout();
        let buf = {
            let inp = ctx.tty_in();
            let mut inp = inp.lock().ok()?;
            if echo {
                inp.c_readline(timeout)
            } else {
                inp.c_readline_noecho(timeout)
            }
            .ok()?
        };

        Some(pam_response {
            resp: buf.leak_c_string(),
            resp_retcode: 0,
        })
    }

    if let Some(res) = _prompt(ctx, msg, echo) {
        res
    } else {
        pam_response {
            resp: ptr::null_mut(),
            resp_retcode: 19,
        }
    }
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
                *res = prompt(ctx, msg, false);
            }
            2 => {
                *res = prompt(ctx, msg, true);
            }
            3 | 4 => {
                *res = if !msg.msg.is_null() {
                    if let Ok(mut out) = ctx.tty_out().lock() {
                        _ = out.write(CStr::from_ptr(msg.msg as *const _).to_bytes());
                        _ = out.flush();
                        None
                    } else {
                        Some(pam_response {
                            resp: ptr::null_mut(),
                            resp_retcode: 19,
                        })
                    }
                } else {
                    None
                }
                .unwrap_or(pam_response {
                    resp: ptr::null_mut(),
                    resp_retcode: 0,
                });
            }
            _ => {
                res.resp = ptr::null_mut();
                res.resp_retcode = 19;
            }
        }
    }

    0
}

pub fn authenticate(service_name: &CStr, ctx: &mut Context) -> Result<(), &'static CStr> {
    unsafe {
        let conv = pam_conv {
            conv: conversation,
            appdata_ptr: ctx as *mut Context as *mut core::ffi::c_void,
        };

        let pamh = {
            let mut pamh = ptr::null_mut();
            let rc = pam_start(
                service_name.as_ptr(),
                ctx.original_user().name().as_ptr(),
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
