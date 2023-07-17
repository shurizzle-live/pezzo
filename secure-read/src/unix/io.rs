pub(crate) trait ErrorExt {
    fn is_interrupted(&self) -> bool;
    fn would_block(&self) -> bool;
}

#[cfg(not(feature = "std"))]
mod imp {
    #[cfg(target_os = "linux")]
    pub use core::ffi::c_int as RawFd;
    #[cfg(not(target_os = "linux"))]
    pub use libc::c_int as RawFd;
    pub use no_std_io::io::{BufRead, BufReader, Error, ErrorKind, Read, Result};

    /// A trait to extract the raw file descriptor from an underlying object.
    pub trait AsRawFd {
        /// Extracts the raw file descriptor.
        fn as_raw_fd(&self) -> RawFd;
    }

    impl AsRawFd for RawFd {
        #[inline]
        fn as_raw_fd(&self) -> RawFd {
            *self
        }
    }

    impl super::ErrorExt for crate::Errno {
        #[inline]
        fn is_interrupted(&self) -> bool {
            *self == crate::Errno::EINTR
        }

        #[inline]
        fn would_block(&self) -> bool {
            *self == crate::Errno::EAGAIN
        }
    }
}

#[cfg(feature = "std")]
mod imp {
    pub use core2::io::{BufRead, BufReader, Error, ErrorKind, Read, Result};
    pub use std::os::fd::{AsRawFd, RawFd};
}

impl ErrorExt for imp::Error {
    #[inline]
    fn is_interrupted(&self) -> bool {
        self.kind() == imp::ErrorKind::Interrupted
    }

    #[inline]
    fn would_block(&self) -> bool {
        self.kind() == imp::ErrorKind::WouldBlock
    }
}

pub use imp::*;
