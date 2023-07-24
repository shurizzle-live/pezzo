use alloc_crate::boxed::Box;
use core::fmt;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "tvos",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd"
))]
pub use bsd_errnos::Errno;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux_errnos::Errno;
pub type RawOsError = i32;
pub type Result<T> = core::result::Result<T, Error>;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErrorKind {
    ArgumentListTooLong,
    AddrInUse,
    AddrNotAvailable,
    ResourceBusy,
    ConnectionAborted,
    ConnectionRefused,
    ConnectionReset,
    Deadlock,
    FilesystemQuotaExceeded,
    AlreadyExists,
    FileTooLarge,
    HostUnreachable,
    Interrupted,
    InvalidInput,
    IsADirectory,
    FilesystemLoop,
    NotFound,
    OutOfMemory,
    StorageFull,
    Unsupported,
    TooManyLinks,
    InvalidFilename,
    NetworkDown,
    NetworkUnreachable,
    NotConnected,
    NotADirectory,
    DirectoryNotEmpty,
    BrokenPipe,
    ReadOnlyFilesystem,
    NotSeekable,
    StaleNetworkFileHandle,
    TimedOut,
    ExecutableFileBusy,
    CrossesDevices,
    PermissionDenied,
    WouldBlock,
    Uncategorized,
    Other,
    WriteZero,
    UnexpectedEof,
}

impl ErrorKind {
    pub(crate) fn as_str(&self) -> &'static str {
        use ErrorKind::*;
        // tidy-alphabetical-start
        match *self {
            AddrInUse => "address in use",
            AddrNotAvailable => "address not available",
            AlreadyExists => "entity already exists",
            ArgumentListTooLong => "argument list too long",
            BrokenPipe => "broken pipe",
            ConnectionAborted => "connection aborted",
            ConnectionRefused => "connection refused",
            ConnectionReset => "connection reset",
            CrossesDevices => "cross-device link or rename",
            Deadlock => "deadlock",
            DirectoryNotEmpty => "directory not empty",
            ExecutableFileBusy => "executable file busy",
            FileTooLarge => "file too large",
            FilesystemLoop => "filesystem loop or indirection limit (e.g. symlink loop)",
            FilesystemQuotaExceeded => "filesystem quota exceeded",
            HostUnreachable => "host unreachable",
            Interrupted => "operation interrupted",
            InvalidFilename => "invalid filename",
            InvalidInput => "invalid input parameter",
            IsADirectory => "is a directory",
            NetworkDown => "network down",
            NetworkUnreachable => "network unreachable",
            NotADirectory => "not a directory",
            NotConnected => "not connected",
            NotFound => "entity not found",
            NotSeekable => "seek on unseekable file",
            Other => "other error",
            OutOfMemory => "out of memory",
            PermissionDenied => "permission denied",
            ReadOnlyFilesystem => "read-only filesystem or storage medium",
            ResourceBusy => "resource busy",
            StaleNetworkFileHandle => "stale network file handle",
            StorageFull => "no storage space",
            TimedOut => "timed out",
            TooManyLinks => "too many links",
            Uncategorized => "uncategorized error",
            Unsupported => "unsupported",
            WouldBlock => "operation would block",
            WriteZero => "write zero",
            UnexpectedEof => "unexpected end of file",
        }
        // tidy-alphabetical-end
    }
}

impl fmt::Display for ErrorKind {
    /// Shows a human-readable description of the `ErrorKind`.
    ///
    /// This is similar to `impl Display for Error`, but doesn't require first converting to Error.
    ///
    /// # Examples
    /// ```
    /// use std::io::ErrorKind;
    /// assert_eq!("entity not found", ErrorKind::NotFound.to_string());
    /// ```
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str(self.as_str())
    }
}

enum Repr {
    Os(Errno),
    Simple(ErrorKind),
    Static {
        kind: ErrorKind,
        message: &'static str,
    },
    Custom {
        kind: ErrorKind,
        cause: Box<dyn crate::error::Error + Send + Sync>,
    },
}

pub struct Error(Repr);

impl Error {
    pub fn new<E>(kind: ErrorKind, cause: E) -> Self
    where
        E: Into<Box<dyn crate::error::Error + Send + Sync>>,
    {
        Self(Repr::Custom {
            kind,
            cause: cause.into(),
        })
    }

    pub fn other<E>(cause: E) -> Self
    where
        E: Into<Box<dyn crate::error::Error + Send + Sync>>,
    {
        Self::new(ErrorKind::Other, cause)
    }

    pub const fn new_static(kind: ErrorKind, message: &'static str) -> Self {
        Self(Repr::Static { kind, message })
    }

    #[cfg(feature = "c")]
    #[inline]
    pub fn last_os_error() -> Self {
        Self(Repr::Os(Errno::last_os_error()))
    }

    #[inline]
    pub fn from_raw_os_error(code: RawOsError) -> Self {
        Self(Repr::Os(Errno::new(code)))
    }

    pub fn raw_os_error(&self) -> Option<RawOsError> {
        if let Repr::Os(ref errno) = self.0 {
            Some(errno.into_raw())
        } else {
            None
        }
    }

    pub fn get_ref(&self) -> Option<&(dyn crate::error::Error + Send + Sync + 'static)> {
        if let Repr::Custom { ref cause, .. } = self.0 {
            Some(Box::as_ref(cause))
        } else {
            None
        }
    }

    pub fn get_mut(&mut self) -> Option<&mut (dyn crate::error::Error + Send + Sync + 'static)> {
        if let Repr::Custom { ref mut cause, .. } = self.0 {
            Some(Box::as_mut(cause))
        } else {
            None
        }
    }

    pub fn into_inner(self) -> Option<Box<dyn crate::error::Error + Send + Sync>> {
        if let Repr::Custom { cause, .. } = self.0 {
            Some(cause)
        } else {
            None
        }
    }

    pub fn kind(&self) -> ErrorKind {
        match self.0 {
            Repr::Os(errno) => kind_from_errno(errno),
            Repr::Simple(kind) => kind,
            Repr::Static { kind, .. } => kind,
            Repr::Custom { kind, .. } => kind,
        }
    }
}

impl fmt::Debug for Repr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Os(errno) => f
                .debug_struct("Os")
                .field("code", &errno.into_raw())
                .field("kind", &kind_from_errno(*errno))
                .field("message", &errno.description().unwrap_or("Unknown error"))
                .finish(),
            Self::Simple(kind) => fmt::Debug::fmt(kind, f),
            Self::Static { kind, message } => f
                .debug_struct("Error")
                .field("kind", kind)
                .field("message", message)
                .finish(),
            Self::Custom { kind, cause } => f
                .debug_struct("Error")
                .field("kind", kind)
                .field("message", cause)
                .finish(),
        }
    }
}

impl fmt::Debug for Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Repr::Os(errno) => write!(
                f,
                "{} (os error {})",
                errno.description().unwrap_or("Unknown error"),
                errno.into_raw()
            ),
            Repr::Simple(kind) => fmt::Display::fmt(kind.as_str(), f),
            Repr::Static { message, .. } => fmt::Display::fmt(message, f),
            Repr::Custom { ref cause, .. } => fmt::Display::fmt(Box::as_ref(cause), f),
        }
    }
}

impl From<Errno> for Error {
    #[inline]
    fn from(value: Errno) -> Self {
        Self(Repr::Os(value))
    }
}

impl From<ErrorKind> for Error {
    #[inline]
    fn from(value: ErrorKind) -> Self {
        Self(Repr::Simple(value))
    }
}

pub fn kind_from_errno(errno: Errno) -> ErrorKind {
    use ErrorKind::*;
    match errno {
        Errno::E2BIG => ArgumentListTooLong,
        Errno::EADDRINUSE => AddrInUse,
        Errno::EADDRNOTAVAIL => AddrNotAvailable,
        Errno::EBUSY => ResourceBusy,
        Errno::ECONNABORTED => ConnectionAborted,
        Errno::ECONNREFUSED => ConnectionRefused,
        Errno::ECONNRESET => ConnectionReset,
        Errno::EDEADLK => Deadlock,
        Errno::EDQUOT => FilesystemQuotaExceeded,
        Errno::EEXIST => AlreadyExists,
        Errno::EFBIG => FileTooLarge,
        Errno::EHOSTUNREACH => HostUnreachable,
        Errno::EINTR => Interrupted,
        Errno::EINVAL => InvalidInput,
        Errno::EISDIR => IsADirectory,
        Errno::ELOOP => FilesystemLoop,
        Errno::ENOENT => NotFound,
        Errno::ENOMEM => OutOfMemory,
        Errno::ENOSPC => StorageFull,
        Errno::ENOSYS => Unsupported,
        Errno::EMLINK => TooManyLinks,
        Errno::ENAMETOOLONG => InvalidFilename,
        Errno::ENETDOWN => NetworkDown,
        Errno::ENETUNREACH => NetworkUnreachable,
        Errno::ENOTCONN => NotConnected,
        Errno::ENOTDIR => NotADirectory,
        Errno::ENOTEMPTY => DirectoryNotEmpty,
        Errno::EPIPE => BrokenPipe,
        Errno::EROFS => ReadOnlyFilesystem,
        Errno::ESPIPE => NotSeekable,
        Errno::ESTALE => StaleNetworkFileHandle,
        Errno::ETIMEDOUT => TimedOut,
        Errno::ETXTBSY => ExecutableFileBusy,
        Errno::EXDEV => CrossesDevices,
        Errno::EACCES | Errno::EPERM => PermissionDenied,

        // These two constants can have the same value on some systems,
        // but different values on others, so we can't use a match clause
        x if x == Errno::EAGAIN || x == Errno::EWOULDBLOCK => WouldBlock,

        _ => Uncategorized,
    }
}
