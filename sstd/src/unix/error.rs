pub trait Error: core::fmt::Display + core::fmt::Debug {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl Error for core::fmt::Error {}

impl Error for core::convert::Infallible {}

impl Error for core::ffi::FromBytesWithNulError {}

impl Error for core::ffi::FromBytesUntilNulError {}

impl Error for core::alloc::LayoutError {}

impl Error for core::array::TryFromSliceError {}

impl Error for core::cell::BorrowError {}

impl Error for core::cell::BorrowMutError {}

impl Error for core::char::CharTryFromError {}

impl Error for core::char::ParseCharError {}

impl Error for core::char::TryFromCharError {}

impl Error for alloc_crate::collections::TryReserveError {}

impl Error for alloc_crate::ffi::FromVecWithNulError {}

impl Error for alloc_crate::ffi::IntoStringError {}

impl Error for alloc_crate::ffi::NulError {}

impl Error for core::num::ParseFloatError {}

impl Error for core::num::ParseIntError {}

impl Error for core::num::TryFromIntError {}

impl Error for core::str::ParseBoolError {}

impl Error for core::str::Utf8Error {}

impl Error for alloc_crate::string::FromUtf8Error {}

impl Error for alloc_crate::string::FromUtf16Error {}

// impl Error for crate::time::SystemTimeError {}

impl<'a, T: Error + ?Sized> Error for &'a T {}

impl<T: Error> Error for alloc_crate::boxed::Box<T> {}
