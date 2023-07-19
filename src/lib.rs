#![cfg_attr(not(test), no_std)]

extern crate alloc as alloc_crate;

use crate::ffi::CStr;

pub mod conf;
pub mod database;
pub mod ffi;
#[cfg(unix)]
pub mod unix;
pub mod util;
#[cfg(unix)]
pub use unix::{__errno, env, io, which};

pub const DEFAULT_PROMPT_TIMEOUT: u32 = 300;
pub const PEZZO_NAME_CSTR: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"pezzo\0") };
pub const DEFAULT_SESSION_TIMEOUT: u64 = 600;
pub const DEFAULT_MAX_RETRIES: usize = 3;

include!(concat!(env!("OUT_DIR"), "/paths.rs"));
