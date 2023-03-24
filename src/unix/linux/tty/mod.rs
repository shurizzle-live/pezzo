use std::{
    ffi::CStr,
    io::{self, Cursor, Write},
    mem::MaybeUninit,
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
    let mut guessing_buffer = MaybeUninit::<[u8; 14]>::uninit();

    let guessing_len = {
        let guessing = unsafe { guessing_buffer.assume_init_mut().as_mut_slice() };
        let mut guessing_cursor = Cursor::new(guessing);

        match (ttynr >> 8) & 0xff {
            TTY_MAJOR => {
                let min = minor(ttynr);
                if min < NR_CONSOLES {
                    let _ = write!(guessing_cursor, "tty{}", min);
                } else {
                    let _ = write!(guessing_cursor, "ttyS{}", min - NR_CONSOLES);
                }
            }
            PTS_MAJOR => {
                let _ = write!(guessing_cursor, "pts/{}", minor(ttynr));
            }
            TTY_ACM_MAJOR => {
                let _ = write!(guessing_cursor, "ttyACM{}", minor(ttynr));
            }
            TTY_USB_MAJOR => {
                let _ = write!(guessing_cursor, "ttyUSB{}", minor(ttynr));
            }
            _ => return Err(io::Error::new(io::ErrorKind::NotFound, "not a valid tty")),
        }

        guessing_cursor.position() as usize
    };
    let guessing_buffer = unsafe { guessing_buffer.assume_init() };
    let guessing =
        unsafe { std::str::from_utf8_unchecked(&guessing_buffer.as_slice()[..guessing_len]) };

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
        match scandir(path, guessing, ttynr) {
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
