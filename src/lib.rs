use std::ffi::CStr;

pub mod conf;
pub mod database;
#[cfg(unix)]
pub mod unix;
pub mod util;

pub const DEFAULT_PROMPT_TIMEOUT: libc::time_t = 30;
pub const PEZZO_PAM_SERVICE_NAME: &CStr =
    unsafe { CStr::from_bytes_with_nul_unchecked(b"pezzo\0") };
pub const DEFAULT_SESSION_TIMEOUT: u64 = 600;
pub const DEFAULT_MAX_RETRIES: usize = 3;
