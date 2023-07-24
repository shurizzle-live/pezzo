mod checker;

pub use self::checker::*;
use alloc_crate::{boxed::Box, vec::Vec};
use sstd::ffi::{CStr, CString};

#[inline]
fn raw_path() -> Option<&'static [u8]> {
    unsafe { sstd::env::var(CStr::from_bytes_with_nul_unchecked(b"PATH\0")).map(CStr::to_bytes) }
}

fn canonicalize<P: AsRef<CStr>>(path: P) -> sstd::io::Result<Option<CString>> {
    match sstd::fs::normalize(path.as_ref()) {
        Err(err) if err.kind() == sstd::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
        Ok(path) => Ok(Some(path.into_owned())),
    }
}

pub fn which<T: AsRef<CStr>>(binary_name: T) -> sstd::io::Result<CString> {
    let binary_checker = build_binary_checker();
    let binary_name = binary_name.as_ref();

    if memchr::memchr(b'/', binary_name.to_bytes()).is_some() {
        let path = sstd::fs::normalize(binary_name)?;
        return if binary_checker.is_valid(&path) {
            Ok(path.into_owned())
        } else {
            Err(sstd::io::ErrorKind::NotFound.into())
        };
    } else if let Some(raw_path) = raw_path() {
        let mut buf = Vec::new();
        let mut prev = 0;
        for pos in memchr::memchr_iter(b':', raw_path) {
            let path = {
                let slice = unsafe { raw_path.get_unchecked(prev..pos) };
                if slice.is_empty() {
                    continue;
                }
                buf.clear();
                buf.extend_from_slice(slice);
                prev = pos + 1;
                buf.push(b'/');
                buf.extend_from_slice(binary_name.to_bytes_with_nul());
                unsafe { CStr::from_ptr(buf.as_ptr().cast()) }
            };

            if let Some(path) = canonicalize(path)? {
                if binary_checker.is_valid(&path) {
                    return Ok(path);
                }
            }
        }
    }

    Err(sstd::io::ErrorKind::NotFound.into())
}

fn build_binary_checker() -> CompositeChecker {
    CompositeChecker::new()
        .add_checker(Box::new(ExistedChecker::new()))
        .add_checker(Box::new(ExecutableChecker::new()))
}
