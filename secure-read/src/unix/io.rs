pub(crate) trait ErrorExt {
    fn is_interrupted(&self) -> bool;
    fn would_block(&self) -> bool;
}

#[cfg(not(feature = "std"))]
mod imp {
    pub use sstd::io::{AsRawFd, BufRead, BufReader, Error, ErrorKind, RawFd, Read, Result};

    impl super::ErrorExt for sstd::io::Errno {
        #[inline]
        fn is_interrupted(&self) -> bool {
            *self == sstd::io::Errno::EINTR
        }

        #[inline]
        fn would_block(&self) -> bool {
            *self == sstd::io::Errno::EAGAIN
        }
    }
}

#[cfg(feature = "std")]
mod imp {
    pub use std::io::{BufRead, BufReader, Error, ErrorKind, Read, Result};
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
