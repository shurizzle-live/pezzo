use crate::ffi::{CStr, CString};
use alloc_crate::{boxed::Box, vec::Vec};
use core::{borrow::Borrow, fmt, hash::Hash, mem::MaybeUninit, ops::Deref};

pub enum VarNameFromBytesErrRepr {
    InteriorNul(usize),
    InteriorEql(usize),
}

impl fmt::Display for VarNameFromBytesErrRepr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InteriorNul(_) => write!(f, "data provided contains an interior nul byte"),
            Self::InteriorEql(_) => write!(f, "data provided contains an interior equal character"),
        }
    }
}

impl fmt::Debug for VarNameFromBytesErrRepr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InteriorNul(pos) => write!(f, "InteriorNul({})", pos),
            Self::InteriorEql(pos) => write!(f, "InteriorEql({})", pos),
        }
    }
}

pub struct VarNameFromBytesError(VarNameFromBytesErrRepr);

impl fmt::Display for VarNameFromBytesError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Debug for VarNameFromBytesError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

#[repr(transparent)]
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct VarName([u8]);

impl VarName {
    pub fn from_slice(slice: &[u8]) -> Result<&Self, VarNameFromBytesError> {
        if let Some(pos) = memchr::memchr2(0, b'=', slice) {
            match unsafe { *slice.get_unchecked(pos) } {
                b'=' => Err(VarNameFromBytesError(VarNameFromBytesErrRepr::InteriorEql(
                    pos,
                ))),
                0 => Err(VarNameFromBytesError(VarNameFromBytesErrRepr::InteriorNul(
                    pos,
                ))),
                _ => unreachable!(),
            }
        } else {
            Ok(unsafe { Self::from_slice_unchecked(slice) })
        }
    }

    pub fn from_c_str(s: &CStr) -> Result<&Self, VarNameFromBytesError> {
        if let Some(pos) = memchr::memchr(b'=', s.to_bytes()) {
            Err(VarNameFromBytesError(VarNameFromBytesErrRepr::InteriorNul(
                pos,
            )))
        } else {
            Ok(unsafe { Self::from_slice_unchecked(s.to_bytes()) })
        }
    }

    #[inline]
    #[allow(clippy::missing_safety_doc)]
    pub const unsafe fn from_raw_parts<'a>(data: *const u8, len: usize) -> &'a Self {
        Self::from_slice_unchecked(core::slice::from_raw_parts(data, len))
    }

    #[inline]
    #[allow(clippy::missing_safety_doc)]
    pub const unsafe fn from_slice_unchecked(slice: &[u8]) -> &Self {
        &*(slice as *const [u8] as *const Self)
    }

    #[inline]
    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn from_ptr<'a>(ptr: *const crate::ffi::c_char) -> &'a Self {
        let start = ptr.cast::<u8>();
        let mut ptr = start;
        while *ptr != b'=' && *ptr != 0 {
            ptr = ptr.add(1);
        }
        Self::from_raw_parts(start, (ptr as usize) - (start as usize))
    }

    #[inline]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[inline]
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    #[inline]
    pub fn to_c_string(&self) -> CString {
        unsafe { CString::from_vec_unchecked(self.to_vec()) }
    }
}

impl Hash for VarName {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        state.write_usize(self.len() + 1);
        let mut end_wrote = false;
        for c in self.0.chunks(core::mem::size_of::<usize>()) {
            if c.len() == core::mem::size_of::<usize>() {
                state.write(c);
            } else {
                let mut buf = MaybeUninit::<[u8; core::mem::size_of::<usize>()]>::uninit();
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        c.as_ptr(),
                        buf.as_mut_ptr().cast::<u8>(),
                        c.len(),
                    );
                    *buf.as_mut_ptr().cast::<u8>().add(c.len()) = 0;
                    state.write(core::slice::from_raw_parts(
                        buf.as_ptr().cast::<u8>(),
                        c.len() + 1,
                    ));
                }
                end_wrote = true;
            }
        }
        if !end_wrote {
            state.write([0].as_slice());
        }
    }
}

impl<'a> TryFrom<&'a CStr> for &'a VarName {
    type Error = VarNameFromBytesError;

    #[inline]
    fn try_from(value: &'a CStr) -> Result<Self, Self::Error> {
        VarName::from_c_str(value)
    }
}

impl<'a> TryFrom<&'a [u8]> for &'a VarName {
    type Error = VarNameFromBytesError;

    #[inline]
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        VarName::from_slice(value)
    }
}

impl PartialEq<[u8]> for VarName {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        self.as_bytes() == other
    }
}

impl<const N: usize> PartialEq<[u8; N]> for VarName {
    #[inline]
    fn eq(&self, other: &[u8; N]) -> bool {
        self.as_bytes() == other.as_slice()
    }
}

impl PartialEq<CStr> for VarName {
    #[inline]
    fn eq(&self, other: &CStr) -> bool {
        self.eq(other.to_bytes())
    }
}

impl PartialOrd<[u8]> for VarName {
    #[inline]
    fn partial_cmp(&self, other: &[u8]) -> Option<core::cmp::Ordering> {
        self.as_bytes().partial_cmp(other)
    }
}

impl<const N: usize> PartialOrd<[u8; N]> for VarName {
    #[inline]
    fn partial_cmp(&self, other: &[u8; N]) -> Option<core::cmp::Ordering> {
        self.as_bytes().partial_cmp(other.as_slice())
    }
}

impl PartialOrd<CStr> for VarName {
    #[inline]
    fn partial_cmp(&self, other: &CStr) -> Option<core::cmp::Ordering> {
        self.partial_cmp(other.to_bytes())
    }
}

impl Deref for VarName {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<VarName> for VarName {
    #[inline]
    fn as_ref(&self) -> &VarName {
        self
    }
}

impl Borrow<[u8]> for VarName {
    #[inline]
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for VarName {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Clone for Box<VarName> {
    fn clone(&self) -> Self {
        unsafe { Box::from_raw(Box::into_raw(self.to_vec().into_boxed_slice()) as *mut VarName) }
    }
}

impl fmt::Debug for VarName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "b\"")?;
        for &c in &self.0 {
            if c == b'\'' {
                fmt::Display::fmt(&b'\'', f)?;
            } else {
                fmt::Display::fmt(&core::ascii::escape_default(c), f)?;
            }
        }
        write!(f, "\"")
    }
}
