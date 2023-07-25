use crate::ffi::{CStr, CString};
use alloc_crate::{boxed::Box, vec::Vec};
use core::{borrow::Borrow, fmt, hash::Hash, iter::FusedIterator, mem::MaybeUninit, ops::Deref};

#[used]
static mut ARGS: &[*const u8] = &[];
#[used]
static mut ENV: *const *const u8 = core::ptr::null();

#[allow(clippy::missing_safety_doc)]
pub unsafe fn init(argc: isize, argv: *const *const u8, envp: *const *const u8) {
    ARGS = core::slice::from_raw_parts(argv, argc as _);
    ENV = envp;
    #[cfg(target_os = "linux")]
    linux_syscalls::init_from_environ(envp);
}

pub fn args() -> &'static [*const u8] {
    unsafe { ARGS }
}

fn strip_var_name(mut s: *const u8, pref: &VarName) -> Option<*const u8> {
    unsafe {
        if !pref.is_empty() {
            let mut ptr = pref.as_ptr();
            let end = ptr.add(pref.len() - 1);

            loop {
                if *s == 0 || *s != *ptr {
                    return None;
                }

                s = s.add(1);
                if ptr == end {
                    break;
                }
                ptr = ptr.add(1);
            }
        }

        match *s {
            b'=' => Some(s.add(1)),
            0 => Some(s),
            _ => None,
        }
    }
}

pub fn var(name: &VarName) -> Option<&'static CStr> {
    unsafe {
        if ENV.is_null() {
            return None;
        }
        let mut ptr = ENV;
        while !(*ptr).is_null() {
            if let Some(var) = strip_var_name(*ptr, name) {
                return Some(CStr::from_ptr(var.cast()));
            }
            ptr = ptr.add(1);
        }
        None
    }
}

pub struct Vars(*const *const u8);

impl Iterator for Vars {
    type Item = (&'static VarName, &'static CStr);

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_null() {
            return None;
        }

        unsafe {
            if (*self.0).is_null() {
                self.0 = core::ptr::null();
                return None;
            }

            let name = *self.0;
            let mut ptr = *self.0;
            self.0 = self.0.add(1);
            loop {
                if *ptr == 0 {
                    return Some((
                        VarName::from_raw_parts(name, (ptr as usize) - (name as usize)),
                        CStr::from_ptr(ptr.cast()),
                    ));
                }

                if *ptr == b'=' {
                    return Some((
                        VarName::from_raw_parts(name, (ptr as usize) - (name as usize)),
                        CStr::from_ptr(ptr.add(1).cast()),
                    ));
                }

                ptr = ptr.add(1);
            }
        }
    }
}

impl FusedIterator for Vars {}

pub fn vars() -> Vars {
    Vars(unsafe { ENV })
}

#[cfg(target_os = "linux")]
fn getcwd(buf: &mut Vec<u8>) -> crate::io::Result<()> {
    use linux_stat::Errno;
    use linux_syscalls::{syscall, Sysno};

    if buf.capacity() == 0 {
        buf.reserve(1);
    }

    unsafe {
        buf.set_len(0);

        loop {
            match syscall!(Sysno::getcwd, buf.as_ptr(), buf.capacity()) {
                Err(Errno::ERANGE) => {
                    buf.reserve(buf.capacity().max(1) * 2);
                }
                Err(err) => return Err(err.into()),
                Ok(len) => {
                    buf.set_len(len);
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn getcwd(buf: &mut Vec<u8>) -> crate::io::Result<()> {
    use crate::unix::__errno;

    if buf.capacity() == 0 {
        buf.reserve(1);
    }

    unsafe {
        buf.set_len(0);

        while libc::getcwd(buf.as_mut_ptr().cast(), buf.capacity()).is_null() {
            let err = *__errno();

            if err != libc::ERANGE {
                return Err(crate::io::from_raw_os_error(err));
            }

            buf.reserve(buf.capacity().max(1) * 2);
        }
    }

    Ok(())
}

pub fn current_dir_in(buf: &mut Vec<u8>) -> crate::io::Result<()> {
    getcwd(buf)?;

    if buf.last().map(|&c| c != 0).unwrap_or(true) {
        buf.reserve_exact(1);
        buf.push(0);
    }

    Ok(())
}

pub fn current_dir() -> crate::io::Result<CString> {
    let mut buf = Vec::new();
    current_dir_in(&mut buf)?;
    Ok(unsafe { CString::from_vec_with_nul_unchecked(buf) })
}

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
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
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
