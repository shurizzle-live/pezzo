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
                    "Wrong permissions on file '{}`. Your system has been compromised",
                    path.display()
                );
            }
        }
        Err(_) => {
            bail!("Cannot find file '{}`", path.display());
        }
    }

    Ok(())
}

pub fn parse_conf<P: AsRef<Path>>(path: P) -> Result<pezzo::conf::Rules> {
    let path = path.as_ref();

    check_file_permissions(path)?;

    let content = pezzo::util::slurp(path).context("Cannot read configuration file")?;
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
