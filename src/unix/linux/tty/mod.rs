use std::{
    ffi::CStr,
    io,
    os::{
        linux::fs::MetadataExt,
        unix::prelude::{FileTypeExt, OsStrExt},
    },
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::unix::tty::TtyInfo;

const TTY_MAJOR: u32 = 4;
const PTS_MAJOR: u32 = 136;
const TTY_ACM_MAJOR: u32 = 166;
const TTY_USB_MAJOR: u32 = 188;

const VALID_TTY_MAJOR: [u32; 4] = [TTY_MAJOR, PTS_MAJOR, TTY_ACM_MAJOR, TTY_USB_MAJOR];

pub fn find_by_ttynr(ttynr: u32) -> io::Result<TtyInfo> {
    {
        let tty_major = (ttynr >> 8) & 0xFF;
        if !VALID_TTY_MAJOR.contains(&tty_major) {
            return Err(io::Error::new(io::ErrorKind::NotFound, "not a valid tty"));
        }
    }

    let ttynr = ttynr as u64;

    fn scandir_recur<P: AsRef<Path>>(path: P, ttynr: u64) -> io::Result<Option<PathBuf>> {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;

            let path = entry.path();

            if path.is_symlink() {
                continue;
            }

            let md = entry.metadata()?;
            if md.file_type().is_char_device() && md.st_rdev() == ttynr {
                return Ok(Some(path));
            }

            if md.is_dir() {
                if let Some(p) = scandir_recur(path, ttynr)? {
                    return Ok(Some(p));
                }
            }
        }
        Ok(None)
    }

    fn scandir<P: AsRef<Path>>(path: P, ttynr: u64) -> io::Result<Option<TtyInfo>> {
        let path = std::fs::canonicalize(path)?;
        match scandir_recur(&path, ttynr)? {
            Some(p) => {
                let name = unsafe {
                    CStr::from_ptr(
                        p.as_os_str()
                            .as_bytes()
                            .get_unchecked((path.as_os_str().len() + 1)..)
                            .as_ptr() as *const _,
                    )
                    .to_string_lossy()
                    .as_ref()
                    .to_string()
                };
                Ok(Some(TtyInfo {
                    path: Arc::new(p),
                    name: Arc::new(name.into_boxed_str()),
                }))
            }
            None => Ok(None),
        }
    }

    for path in ["/dev"] {
        match scandir(path, ttynr) {
            Ok(Some(info)) => return Ok(info),
            Err(err) => return Err(err),
            _ => (),
        }
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "tty not found"))
}
