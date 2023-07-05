#![allow(clippy::useless_conversion)]

use std::{
    ffi::{CString, OsStr},
    fmt,
    fs::{DirBuilder, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    mem,
    os::unix::{
        fs::DirBuilderExt,
        prelude::{OpenOptionsExt, OsStrExt},
    },
    path::PathBuf,
    slice::SliceIndex,
};
use tty_info::Dev;

use fs4::FileExt;

#[repr(packed)]
pub struct RawEntry {
    pub session_id: u32,
    #[cfg(target_os = "linux")]
    pub tty: u64,
    #[cfg(not(target_os = "linux"))]
    pub tty: u32,
    pub last_login: u64,
}

#[repr(transparent)]
pub struct BorrowedEntry;

impl BorrowedEntry {
    #[inline]
    unsafe fn inner(&self) -> *const RawEntry {
        self as *const _ as *const RawEntry
    }

    #[inline]
    unsafe fn inner_mut(&mut self) -> *mut RawEntry {
        self as *mut _ as *mut RawEntry
    }

    #[inline]
    pub fn session_id(&self) -> u32 {
        unsafe { (*self.inner()).session_id }
    }

    #[inline]
    pub fn tty(&self) -> Dev {
        unsafe { (*self.inner()).tty.into() }
    }

    #[inline]
    pub fn last_login(&self) -> u64 {
        unsafe { (*self.inner()).last_login }
    }

    #[inline]
    pub fn set_session_id(&mut self, value: u32) {
        unsafe {
            (*self.inner_mut()).session_id = value;
        }
    }

    #[inline]
    pub fn set_tty(&mut self, value: u32) {
        unsafe {
            (*self.inner_mut()).tty = value.into();
        }
    }

    #[inline]
    pub fn set_last_login(&mut self, value: u64) {
        unsafe {
            (*self.inner_mut()).last_login = value;
        }
    }
}

impl fmt::Debug for BorrowedEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("session_id", &self.session_id())
            .field("tty", &self.tty())
            .field("last_login", &self.last_login())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Entry {
    pub session_id: u32,
    pub tty: Dev,
    pub last_login: u64,
}

impl From<Entry> for RawEntry {
    #[inline]
    fn from(value: Entry) -> Self {
        Self {
            session_id: value.session_id,
            tty: value.tty.into(),
            last_login: value.last_login,
        }
    }
}

impl From<RawEntry> for Entry {
    #[inline]
    fn from(value: RawEntry) -> Self {
        Self {
            session_id: value.session_id,
            tty: value.tty.into(),
            last_login: value.last_login,
        }
    }
}

const BASE_PATH: &str = "/var/run/pezzo";

fn create_base() -> io::Result<()> {
    DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(BASE_PATH)
}

pub struct Database {
    user: CString,
    inner: Vec<RawEntry>,
}

pub struct Iter<'a> {
    inner: std::slice::Iter<'a, RawEntry>,
}

impl Database {
    #[inline]
    pub fn new<S: Into<CString>>(user: S) -> io::Result<Self> {
        let user = user.into();

        create_base()?;

        let path = PathBuf::from(BASE_PATH).join(OsStr::from_bytes(user.to_bytes()));
        let mut f = match File::open(path) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(Self {
                    user,
                    inner: Vec::new(),
                })
            }
            Err(err) => return Err(err),
            Ok(f) => f,
        };
        f.lock_shared()?;
        let len = f.seek(SeekFrom::End(0))? as usize;
        f.seek(SeekFrom::Start(0))?;

        if len % mem::size_of::<RawEntry>() != 0 {
            return Ok(Self {
                user,
                inner: Vec::new(),
            });
        }

        let mut buf = Vec::<RawEntry>::with_capacity(len / mem::size_of::<RawEntry>());
        unsafe {
            f.read_exact(std::slice::from_raw_parts_mut(
                buf.as_mut_ptr() as *mut u8,
                len,
            ))?;
            buf.set_len(len / mem::size_of::<RawEntry>());
        }

        Ok(Self { user, inner: buf })
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[inline]
    pub fn get<I: SliceIndex<[RawEntry]>>(&self, index: I) -> Option<&BorrowedEntry> {
        self.inner
            .get(index)
            .map(|e| unsafe { &*(e as *const _ as *const BorrowedEntry) })
    }

    #[inline]
    pub fn get_mut<I: SliceIndex<[RawEntry]>>(&mut self, index: I) -> Option<&mut BorrowedEntry> {
        self.inner
            .get_mut(index)
            .map(|e| unsafe { &mut *(e as *mut _ as *mut BorrowedEntry) })
    }

    /// # Safety
    #[inline]
    pub unsafe fn get_unchecked<I: SliceIndex<[RawEntry]>>(&self, index: I) -> &BorrowedEntry {
        &*(self.inner.get_unchecked(index) as *const _ as *const BorrowedEntry)
    }

    /// # Safety
    #[inline]
    pub unsafe fn get_unchecked_mut<I: SliceIndex<[RawEntry]>>(
        &mut self,
        index: I,
    ) -> &mut BorrowedEntry {
        &mut *(self.inner.get_unchecked_mut(index) as *mut _ as *mut BorrowedEntry)
    }

    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&BorrowedEntry) -> bool,
    {
        self.inner
            .retain(|raw| f(unsafe { &*(raw as *const _ as *const BorrowedEntry) }))
    }

    pub fn retain_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut BorrowedEntry) -> bool,
    {
        self.inner
            .retain_mut(|raw| f(unsafe { &mut *(raw as *mut _ as *mut BorrowedEntry) }))
    }

    #[inline]
    pub fn remove(&mut self, index: usize) -> Entry {
        self.inner.remove(index).into()
    }

    #[inline]
    pub fn push(&mut self, entry: Entry) {
        self.inner.push(entry.into());
    }

    #[inline]
    pub fn insert(&mut self, index: usize, entry: Entry) {
        self.inner.insert(index, entry.into())
    }

    pub fn save(&self) -> io::Result<()> {
        create_base()?;

        let path = PathBuf::from(BASE_PATH).join(OsStr::from_bytes(self.user.to_bytes()));
        let mut file = OpenOptions::new()
            .read(false)
            .write(true)
            .append(false)
            .truncate(false)
            .create(true)
            .create_new(false)
            .mode(0o700)
            .open(path)?;

        file.lock_exclusive()?;
        file.set_len(0)?;

        file.write_all(unsafe {
            std::slice::from_raw_parts(
                self.inner.as_ptr() as *const u8,
                self.len() * mem::size_of::<RawEntry>(),
            )
        })?;

        Ok(())
    }

    #[inline]
    pub fn iter(&self) -> Iter {
        self.into_iter()
    }

    #[inline]
    pub fn delete<S: Into<CString>>(user: S) -> io::Result<()> {
        let user = user.into();

        create_base()?;

        let path = PathBuf::from(BASE_PATH).join(OsStr::from_bytes(user.to_bytes()));
        match std::fs::remove_file(path) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a BorrowedEntry;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner
            .next()
            .map(|raw| unsafe { &*(raw as *const _ as *const BorrowedEntry) })
    }
}

impl<'a> IntoIterator for &'a Database {
    type Item = &'a BorrowedEntry;

    type IntoIter = Iter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        Iter {
            inner: self.inner.iter(),
        }
    }
}
