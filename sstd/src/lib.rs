#![no_std]

extern crate alloc as alloc_crate;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::*;
