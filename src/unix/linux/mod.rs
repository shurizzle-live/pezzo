pub mod proc;
pub mod time;
pub mod tty;

pub use proc::context::*;

use std::fmt;

#[macro_export]
macro_rules! prefix {
    ($p:literal) => {
        $p
    };
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub revision: u32,
}

impl fmt::Display for Version {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.revision)
    }
}

#[macro_export]
macro_rules! version {
    (>  $($rest:tt)+) => {
        $crate::unix::linux::kernel_version()  > $crate::version!($($rest)+)
    };
    (<  $($rest:tt)+) => {
        $crate::unix::linux::kernel_version()  < $crate::version!($($rest)+)
    };
    (== $($rest:tt)+) => {
        $crate::unix::linux::kernel_version() == $crate::version!($($rest)+)
    };
    (>= $($rest:tt)+) => {
        $crate::unix::linux::kernel_version() >= $crate::version!($($rest)+)
    };
    (<= $($rest:tt)+) => {
        $crate::unix::linux::kernel_version() <= $crate::version!($($rest)+)
    };
    ($major:expr) => {
        $crate::version!($major, 0)
    };
    ($major:expr, $minor:expr) => {
        $crate::version!($major, $minor, 0)
    };
    ($major:expr, $minor:expr, $revision:expr) => {
        $crate::unix::linux::Version {
            major: $major,
            minor: $minor,
            revision: $revision,
        }
    };
}

static mut KERNEL_VERSION: Version = version!(0);

#[ctor::ctor]
fn _kernel_version_ctor() {
    pub fn _get_kernel_version() -> Option<Version> {
        use atoi::FromRadix10;

        let uts = super::common::uname().ok()?;
        let release = uts.release().to_bytes();

        let (major, length) = u32::from_radix_10(release);
        if length == 0 || !matches!(release.get(length), Some(b'.')) {
            return None;
        }
        let release = unsafe { release.get_unchecked((length + 1)..) };

        let (minor, length) = u32::from_radix_10(release);
        if length == 0 || !matches!(release.get(length), Some(b'.')) {
            return None;
        }
        let release = unsafe { release.get_unchecked((length + 1)..) };

        let (revision, length) = u32::from_radix_10(release);
        if length == 0 {
            return None;
        }

        Some(Version {
            major,
            minor,
            revision,
        })
    }

    unsafe {
        if let Some(v) = _get_kernel_version() {
            KERNEL_VERSION = v;
        } else {
            const ERRMSG: &[u8] = b"Invalid kernel version\n\0";
            _ = libc::write(2, ERRMSG.as_ptr() as *const libc::c_void, ERRMSG.len() - 1);
            libc::exit(1);
        }
    }
}

#[inline(always)]
pub fn kernel_version() -> Version {
    unsafe { KERNEL_VERSION }
}
