#![cfg(unix)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(any(all(target_os = "linux", feature = "c"), not(target_os = "linux")))]
mod c;
#[path = "unix/mod.rs"]
mod platform;

#[cfg(any(all(target_os = "linux", feature = "c"), not(target_os = "linux")))]
pub use c::*;
pub use platform::*;

pub trait FeedRead {
    type Error;

    fn feed(&mut self, buf: &[u8]) -> Result<core::ops::ControlFlow<usize, usize>, Self::Error>;

    #[inline]
    fn finish(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub trait IsTerminal {
    fn is_terminal(&self) -> bool;
}
