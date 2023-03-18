mod common;
pub mod iam;
pub mod tty;
#[cfg(target_os = "linux")]
#[macro_use]
pub mod linux;
#[cfg(not(target_os = "linux"))]
pub use common::uname::*;
#[cfg(target_os = "linux")]
pub use linux::uname::*;
