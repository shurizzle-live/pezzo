use crate::ffi::{CStr, CString};
use alloc_crate::{borrow::Cow, vec::Vec};

unsafe fn skip_slashes(mut p: *const u8) -> *mut u8 {
    while *p != 0 && *p == b'/' {
        p = p.add(1);
    }
    p as *mut u8
}

unsafe fn skip_curdir(p: *const u8) -> Result<*mut u8, *mut u8> {
    if *p == b'.' {
        let p2 = p.add(1);
        match *p2 {
            b'/' => Ok(skip_slashes(p2)),
            0 => Ok(p2 as *mut _),
            b'.' => {
                let p3 = p2.add(1);
                match *p3 {
                    b'/' => Err(skip_slashes(p2)),
                    0 => Err(p3 as *mut _),
                    _ => Ok(p as *mut _),
                }
            }
            _ => Ok(p as *mut _),
        }
    } else {
        Ok(p as *mut _)
    }
}

unsafe fn skip_updir(p: *const u8) -> *mut u8 {
    skip_curdir(p).unwrap_or_else(|i| i)
}

unsafe fn skip_invalid_non_root(mut p: *const u8) -> Result<*mut u8, *mut u8> {
    p = skip_slashes(p);
    loop {
        match skip_curdir(p) {
            Ok(next) => {
                if p == next {
                    break;
                }
                p = next;
            }
            other => return other,
        }
    }
    Ok(p as *mut u8)
}

unsafe fn skip_invalid_root(mut p: *const u8) -> *mut u8 {
    p = skip_slashes(p);
    loop {
        let next = skip_updir(p);
        if p == next {
            break;
        }
        p = next;
    }
    p as *mut u8
}

unsafe fn skip_valid_component(mut p: *const u8) -> *const u8 {
    if *p == 0 || *p == b'/' {
        return p;
    }

    let start = p;
    if *p == b'.' {
        p = p.add(1);
        if *p == 0 || *p == b'/' {
            return start;
        }
        if *p == b'.' {
            p = p.add(1);
            if *p == 0 || *p == b'/' {
                return start;
            }
        }
    }

    loop {
        if *p == 0 {
            break;
        }
        if *p == b'/' {
            p = p.add(1);
            break;
        }
        p = p.add(1);
    }

    p
}

unsafe fn skip_valid(mut p: *const u8) -> *mut u8 {
    loop {
        let next = skip_valid_component(p);
        if p == next {
            break;
        }
        p = next;
    }
    p as *mut u8
}

unsafe fn skip_while_normalized(path: &[u8]) -> Option<usize> {
    unsafe fn inner(mut start: *const u8) -> Option<*const u8> {
        start = start.add(1);

        if *start == b'/' {
            return Some(start);
        }

        let last = skip_valid(start);
        if *last == 0 {
            None
        } else {
            Some(last)
        }
    }

    let start = path.as_ptr();
    inner(start).map(|a| (a as usize) - (start as usize))
}

fn strip_slash(path: Cow<[u8]>) -> Cow<[u8]> {
    if path.len() > 2 && unsafe { *path.get_unchecked(path.len() - 2) == b'/' } {
        let mut path = path.into_owned();
        let pos = path.len() - 1;
        unsafe { path.set_len(pos) };
        let pos = pos - 1;
        unsafe { *path.get_unchecked_mut(pos) = 0 };
        Cow::Owned(path)
    } else {
        path
    }
}

unsafe fn compress(start: *mut u8, mut valid: *mut u8) -> *mut u8 {
    let mut invalid = valid;
    while *invalid != 0 {
        invalid = if (valid as usize) - (start as usize) == 1 {
            skip_invalid_root(invalid)
        } else {
            match skip_invalid_non_root(invalid) {
                Ok(p) => p,
                Err(p) => {
                    while {
                        valid = valid.sub(1);
                        *valid != b'/'
                    } {}
                    valid = valid.add(1);
                    p
                }
            }
        };

        if *invalid == 0 {
            break;
        }

        let next = skip_valid(invalid);
        let len = (next as usize) - (invalid as usize);
        core::ptr::copy(invalid, valid, len);
        invalid = next;
        valid = valid.add(len);
    }
    valid
}

#[inline(always)]
fn _normalize<F>(path: Cow<'_, CStr>, cwd: F) -> crate::io::Result<Cow<'_, CStr>>
where
    F: FnOnce() -> crate::io::Result<Vec<u8>>,
{
    let path = match path {
        Cow::Borrowed(s) => Cow::Borrowed(s.to_bytes_with_nul()),
        Cow::Owned(s) => Cow::Owned(s.into_bytes_with_nul()),
    };

    let path = if unsafe { *path.get_unchecked(0) } != b'/' {
        let mut abs = cwd()?;
        abs.reserve_exact(1 + path.len());
        abs.push(b'/');
        abs.extend_from_slice(&path);
        Cow::Owned(abs)
    } else {
        path
    };

    let path = match unsafe { skip_while_normalized(&path) } {
        Some(valid) => {
            let mut path = path.into_owned();
            unsafe {
                let valid = path.as_mut_ptr().add(valid);
                let last = compress(path.as_mut_ptr(), valid);
                *last = 0;
                path.set_len((last as usize) - (path.as_ptr() as usize) + 1);
            }
            Cow::Owned(path)
        }
        None => path,
    };
    let path = strip_slash(path);

    Ok(match path {
        Cow::Borrowed(s) => Cow::Borrowed(unsafe { CStr::from_bytes_with_nul_unchecked(s) }),
        Cow::Owned(s) => Cow::Owned(unsafe { CString::from_vec_with_nul_unchecked(s) }),
    })
}

pub fn normalize<'a, P: Into<Cow<'a, CStr>>>(path: P) -> crate::io::Result<Cow<'a, CStr>> {
    _normalize(path.into(), || Ok(crate::env::current_dir()?.into_bytes()))
}

pub fn normalize_relative<'a, P: Into<Cow<'a, CStr>>, P2: AsRef<CStr>>(
    base: P2,
    path: P,
) -> crate::io::Result<Cow<'a, CStr>> {
    _normalize(path.into(), move || {
        let base = base.as_ref();
        let base = base.to_bytes();

        if base.first().map(|&c| c != b'/').unwrap_or(true) {
            let mut buf = crate::env::current_dir()?.into_bytes();
            buf.reserve_exact(1 + base.len());
            buf.push(b'/');
            buf.extend_from_slice(base);
            Ok(buf)
        } else {
            Ok(base.to_vec())
        }
    })
}
