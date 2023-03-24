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
const NR_CONSOLES: u32 = 64;

fn find_by_ttynr(ttynr: u32) -> io::Result<TtyInfo> {
    let guessing = match (ttynr >> 8) & 0xff {
        TTY_MAJOR => {
            let min = minor(ttynr);
            if min < NR_CONSOLES {
                format!("tty{}", min)
            } else {
                format!("ttyS{}", min - NR_CONSOLES)
            }
        }
        PTS_MAJOR => format!("pts/{}", minor(ttynr)),
        TTY_ACM_MAJOR => format!("ttyACM{}", minor(ttynr)),
        TTY_USB_MAJOR => format!("ttyUSB{}", minor(ttynr)),
        _ => return Err(io::Error::new(io::ErrorKind::NotFound, "not a valid tty")),
    };

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

    #[inline(always)]
    fn ttyinfo(parent: &Path, path: PathBuf) -> TtyInfo {
        let name = unsafe {
            CStr::from_ptr(
                path.as_os_str()
                    .as_bytes()
                    .get_unchecked((parent.as_os_str().len() + 1)..)
                    .as_ptr() as *const _,
            )
            .to_string_lossy()
            .as_ref()
            .to_string()
        };

        TtyInfo {
            path: Arc::new(path),
            name: Arc::new(name.into_boxed_str()),
        }
    }

    #[inline(always)]
    fn minor(ttynr: u32) -> u32 {
        (ttynr >> 19) | (ttynr & 0xff)
    }

    fn try_path(path: PathBuf, ttynr: u64) -> io::Result<Option<PathBuf>> {
        match path.metadata() {
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
            Ok(md) => {
                if md.file_type().is_char_device() && md.st_rdev() == ttynr {
                    Ok(Some(path))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn scandir<P: AsRef<Path>>(path: P, guessing: &str, ttynr: u64) -> io::Result<Option<TtyInfo>> {
        let path = match std::fs::canonicalize(path) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
            Ok(path) => path,
        };

        match try_path(path.join(guessing), ttynr)
            .map_or(None, |p| p)
            .map_or_else(|| scandir_recur(&path, ttynr), |p| Ok(Some(p)))?
        {
            Some(p) => Ok(Some(ttyinfo(&path, p))),
            None => Ok(None),
        }
    }

    for path in ["/dev"] {
        match scandir(path, &guessing, ttynr) {
            Ok(Some(info)) => return Ok(info),
            Err(err) => return Err(err),
            _ => (),
        }
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "tty not found"))
}

impl super::super::tty::TtyInfo {
    #[inline]
    pub fn for_ttyno(ttyno: u32) -> io::Result<Self> {
        find_by_ttynr(ttyno)
    }
}
