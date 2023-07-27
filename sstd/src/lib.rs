#![no_std]

extern crate alloc as alloc_crate;

#[cfg(unix)]
mod unix;
#[macro_use]
mod macros;
#[cfg(unix)]
pub use unix::*;
