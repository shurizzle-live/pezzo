use crate::ffi::{CStr, CString};
use alloc_crate::vec::Vec;

#[cfg(any(target_os = "linux", target_os = "android"))]
fn is_file_accessible(file: &CStr) -> bool {
    use linux_raw_sys::general::{AT_EACCESS, F_OK};
    use linux_stat::CURRENT_DIRECTORY;
    use linux_syscalls::{syscall, Sysno};

    unsafe {
        syscall!([ro] Sysno::faccessat, CURRENT_DIRECTORY, file.as_ptr(), AT_EACCESS | F_OK).is_ok()
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn is_file_accessible(file: &CStr) -> bool {
    unsafe {
        libc::faccessat(
            libc::AT_FDCWD,
            file.as_ptr().cast(),
            libc::F_OK,
            libc::AT_EACCESS,
        ) == 0
    }
}

#[derive(Default)]
struct State {
    rname: Vec<u8>,
    extra: Vec<u8>,
    link: Vec<u8>,
}

#[cfg(target_os = "linux")]
fn read_link_in(path: &CStr, buf: &mut Vec<u8>) -> crate::io::Result<()> {
    use linux_stat::CURRENT_DIRECTORY;
    use linux_syscalls::{syscall, Sysno};

    if buf.capacity() == 0 {
        buf.reserve(1);
    }

    unsafe {
        buf.set_len(0);

        loop {
            match syscall!(
                Sysno::readlinkat,
                CURRENT_DIRECTORY,
                path.as_ptr(),
                buf.as_mut_ptr(),
                buf.capacity()
            )? {
                len if len < buf.capacity() - 1 => {
                    buf.set_len(len);
                    return Ok(());
                }
                _ => buf.reserve(buf.capacity().max(1) * 2),
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn read_link_in(path: &CStr, buf: &mut Vec<u8>) -> crate::io::Result<()> {
    if buf.capacity() == 0 {
        buf.reserve(1);
    }

    unsafe {
        buf.set_len(0);

        loop {
            match libc::readlink(
                path.as_ptr().cast(),
                buf.as_mut_ptr().cast(),
                buf.capacity(),
            ) {
                -1 => {
                    let err = crate::io::Errno::last_os_error();
                    if err != crate::io::Errno::EFAULT {
                        return Err(err.into());
                    }
                }
                len if (len as usize) < buf.capacity() - 1 => {
                    buf.set_len(len as usize);
                    return Ok(());
                }
                _ => buf.reserve(buf.capacity().max(1) * 2),
            }
        }
    }
}

pub fn read_link<P: AsRef<CStr>>(path: &CStr) -> crate::io::Result<CString> {
    let mut buf = Vec::new();
    read_link_in(path, &mut buf)?;
    Ok(unsafe { CString::from_vec_unchecked(buf) })
}

unsafe fn skip_slashes(mut ptr: *const u8) -> *const u8 {
    while *ptr == b'/' {
        ptr = ptr.add(1);
    }
    ptr
}

unsafe fn suffix_requires_dir_check(mut end: *const u8) -> bool {
    while *end == b'/' {
        while {
            end = end.add(1);
            *end == b'/'
        } {}

        match *end {
            0 => return true,
            b'.' => (),
            _ => return false,
        }
        end = end.add(1);

        if *end == 0 || (*end == b'.' && matches!(*end.add(1), 0 | b'/')) {
            return true;
        }
    }

    false
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "tvos"
)))]
unsafe fn dir_check(path: &mut Vec<u8>) -> bool {
    let old_len = path.len();
    path.extend_from_slice(b"/\0");
    let res = is_file_accessible(CStr::from_ptr(path.as_ptr().cast()));
    path.set_len(old_len);
    res
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "tvos"
))]
unsafe fn dir_check(path: &mut Vec<u8>) -> bool {
    let old_len = path.len();
    path.extend_from_slice(b"/./\0");
    let res = is_file_accessible(CStr::from_ptr(path.as_ptr().cast()));
    path.set_len(old_len);
    res
}

#[inline(always)]
fn eloop() -> crate::io::Error {
    crate::io::Errno::ELOOP.into()
}

#[inline(always)]
fn __eloop_threshold() -> usize {
    40
}

pub fn realpath<P: AsRef<CStr>>(name: P) -> crate::io::Result<CString> {
    let name = name.as_ref().to_bytes_with_nul();

    if name.len() == 1 {
        return Err(crate::io::ErrorKind::NotFound.into());
    }

    let mut state = State::default();

    if unsafe { *name.get_unchecked(0) } == b'/' {
        state.rname.push(b'/')
    } else {
        crate::env::current_dir_in(&mut state.rname)?;
        state.rname.pop();
    }
    let mut start = name.as_ptr().cast::<u8>();
    let mut extra = false;
    let mut num_links = 0usize;

    unsafe {
        while *start != 0 {
            start = skip_slashes(start);

            let mut end = start;
            while *end != 0 && *end != b'/' {
                end = end.add(1);
            }

            let startlen = (end as usize) - (start as usize);

            if startlen == 0 {
                break;
            } else if startlen == 2 && *start == b'.' && *start.add(1) == b'.' {
                if state.rname.len() > 1 {
                    let pos =
                        memchr::memrchr(b'/', state.rname.get_unchecked(..(state.rname.len() - 1)))
                            .unwrap_unchecked();
                    state.rname.set_len(pos + 1);
                }
            } else if !(startlen == 1 && *start == b'.') {
                if *state.rname.get_unchecked(state.rname.len() - 1) != b'/' {
                    state.rname.push(b'/');
                }

                state
                    .rname
                    .extend_from_slice(core::slice::from_raw_parts(start, startlen));
                {
                    state.rname.reserve_exact(1);
                    let len = state.rname.len();
                    *state.rname.get_unchecked_mut(len) = 0;
                }
                {
                    let path = CStr::from_ptr(state.rname.as_ptr().cast());
                    if let Err(err) = read_link_in(
                        path,
                        if extra {
                            &mut state.link
                        } else {
                            &mut state.extra
                        },
                    ) {
                        let error = if suffix_requires_dir_check(end) {
                            !dir_check(&mut state.rname)
                        } else {
                            if err.kind() == crate::io::ErrorKind::InvalidInput {
                                start = end;
                                continue;
                            }
                            true
                        };

                        if error {
                            return Err(err);
                        }
                    }
                }

                num_links += 1;
                if num_links > __eloop_threshold() {
                    return Err(eloop());
                }

                // concatenate read link and the rest of the path
                if extra {
                    let skip = (end as usize) - (state.extra.as_ptr() as usize);
                    let len = state.extra.len() - skip;
                    state
                        .link
                        .extend_from_slice(core::slice::from_raw_parts(end, len));
                    core::mem::swap(&mut state.link, &mut state.extra);
                    state.link.set_len(0);
                } else {
                    let skip = (end as usize) - (name.as_ptr() as usize);
                    let len = name.len() - skip;
                    state
                        .extra
                        .extend_from_slice(core::slice::from_raw_parts(end, len));
                    extra = true;
                }
                end = state.extra.as_ptr();

                if *state.extra.get_unchecked(0) == b'/' {
                    state.rname.set_len(1);
                } else if state.rname.len() > 1 {
                    let pos =
                        memchr::memrchr(b'/', state.rname.get_unchecked(..(state.rname.len() - 1)))
                            .unwrap_unchecked();
                    state.rname.set_len(pos + 1);
                }
            }

            start = end;
        }
    }

    if state.rname.last().map(|&c| c == 0).unwrap_or(false) {
        unsafe { state.rname.set_len(state.rname.len() - 1) };
    }

    Ok(unsafe { CString::from_vec_unchecked(state.rname) })
}
