use std::{
    ffi::{CStr, CString},
    path::Path,
};

use anyhow::{bail, Context, Result};

pub fn parse_box_c_str(input: &str) -> Result<Box<CStr>, &'static str> {
    match memchr::memchr(b'\0', input.as_bytes()) {
        Some(i) if i + 1 == input.len() => unsafe {
            Ok(CStr::from_ptr(input.as_bytes().as_ptr() as *const _)
                .to_owned()
                .into_boxed_c_str())
        },
        Some(_) => Err("Invalid string"),
        None => unsafe {
            Ok(CString::from_vec_unchecked(input.as_bytes().to_vec()).into_boxed_c_str())
        },
    }
}

pub fn check_file_permissions<P: AsRef<Path>>(path: P) -> Result<()> {
    #[cfg(target_os = "linux")]
    use std::os::linux::fs::MetadataExt;
    #[cfg(target_os = "macos")]
    use std::os::macos::fs::MetadataExt;
    use std::os::unix::prelude::PermissionsExt;

    let path = path.as_ref();
    match path.metadata() {
        Ok(md) => {
            if md.st_uid() != 0 || (md.permissions().mode() & 0o022) != 0 {
                bail!(
                    "Wrong permissions on file {:?}. Your system has been compromised",
                    path.display()
                );
            }
        }
        Err(_) => {
            bail!("Cannot find file {:?}", path.display());
        }
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn check_file_permissions_cstr<P: AsRef<CStr>>(path: P) -> Result<()> {
    let path = path.as_ref();

    let mut buf = std::mem::MaybeUninit::<libc::stat>::uninit();
    let md = loop {
        if unsafe { libc::stat(path.as_ptr().cast(), buf.as_mut_ptr()) == -1 } {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                bail!("Cannot stat file {:?}", path);
            }
        } else {
            break unsafe { buf.assume_init() };
        }
    };

    if md.st_uid != 0 || md.st_mode & 0o022 != 0 {
        bail!(
            "Wrong permissions on file {:?}. Your system has been compromised",
            path
        );
    }

    Ok(())
}

#[cfg(target_os = "linux")]
pub fn check_file_permissions_cstr<P: AsRef<CStr>>(path: P) -> Result<()> {
    let path = path.as_ref();

    let md = loop {
        match linux_stat::stat_cstr(path) {
            Err(linux_stat::Errno::EINTR) => (),
            Err(_) => bail!("Cannot stat file {:?}", path),
            Ok(md) => break md,
        }
    };

    if md.uid() != 0 || md.mode().as_u16() & 0o022 != 0 {
        bail!(
            "Wrong permissions on file {:?}. Your system has been compromised",
            path
        );
    }

    Ok(())
}

#[inline(always)]
fn _parse_conf<F: FnOnce() -> std::io::Result<Vec<u8>>>(f: F) -> Result<pezzo::conf::Rules> {
    let content = f().context("Cannot read configuration file")?;
    match pezzo::conf::parse(&content) {
        Ok(c) => Ok(c),
        Err(err) => {
            let buf = &content[..err.location];
            let mut line = 1;
            let mut pos = 0;
            for p in memchr::memchr_iter(b'\n', buf) {
                line += 1;
                pos = p;
            }

            let col = buf.len() - pos;
            bail!(
                "{}:{}: expected {}, got {}",
                line,
                col + 1,
                err.expected,
                content[err.location]
            );
        }
    }
}

pub fn parse_conf_cstr<P: AsRef<CStr>>(path: P) -> Result<pezzo::conf::Rules> {
    let path = path.as_ref();
    check_file_permissions_cstr(path)?;
    _parse_conf(|| pezzo::util::slurp_cstr(path))
}
