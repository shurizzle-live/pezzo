use crate::ffi::{CStr, CString};
use alloc_crate::vec::Vec;
use core::{cmp, iter::FusedIterator};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Component<'a> {
    Root,
    CurDir,
    ParentDir,
    Normal(&'a [u8]),
}

#[derive(Copy, Clone, PartialEq, PartialOrd, Debug)]
enum State {
    StartDir = 1,
    Body = 2,
    Done = 3,
}

#[derive(Copy, Clone, Debug)]
struct Components<'a> {
    path: &'a [u8],
    has_physical_root: bool,
    front: State,
    back: State,
}

impl<'a> Components<'a> {
    pub fn new(path: &'a [u8]) -> Self {
        let has_physical_root = path.first().map(|&c| c == b'/').unwrap_or(false);
        Self {
            path,
            has_physical_root,
            front: State::StartDir,
            back: State::Body,
        }
    }

    #[inline]
    fn finished(&self) -> bool {
        self.front == State::Done || self.back == State::Done || self.front > self.back
    }

    fn include_cur_dir(&self) -> bool {
        if self.has_physical_root {
            return false;
        }

        let mut iter = self.path.iter();
        matches!(
            (iter.next().copied(), iter.next().copied()),
            (Some(b'.'), None) | (Some(b'.'), Some(b'/'))
        )
    }

    #[inline]
    fn len_before_body(&self) -> usize {
        self.has_physical_root as usize + self.include_cur_dir() as usize
    }

    fn parse_single_component<'b>(&self, comp: &'b [u8]) -> Option<Component<'b>> {
        match comp {
            b"." => None,
            b".." => Some(Component::ParentDir),
            b"" => None,
            _ => Some(Component::Normal(comp)),
        }
    }

    fn parse_next_component(&self) -> (usize, Option<Component<'a>>) {
        debug_assert!(self.front == State::Body);
        let (extra, comp) = match memchr::memchr(b'/', self.path) {
            None => (0, self.path),
            Some(i) => (1, &self.path[..i]),
        };
        (comp.len() + extra, self.parse_single_component(comp))
    }

    fn parse_next_component_back(&self) -> (usize, Option<Component<'a>>) {
        debug_assert!(self.back == State::Body);
        let start = self.len_before_body();
        let (extra, comp) = match memchr::memrchr(b'/', &self.path[start..]) {
            None => (0, &self.path[start..]),
            Some(i) => (1, &self.path[start + i + 1..]),
        };
        (comp.len() + extra, self.parse_single_component(comp))
    }

    fn trim_left(&mut self) {
        while !self.path.is_empty() {
            let (size, comp) = self.parse_next_component();
            if comp.is_some() {
                return;
            } else {
                self.path = &self.path[size..];
            }
        }
    }

    fn trim_right(&mut self) {
        while self.path.len() > self.len_before_body() {
            let (size, comp) = self.parse_next_component_back();
            if comp.is_some() {
                return;
            } else {
                self.path = &self.path[..self.path.len() - size];
            }
        }
    }

    pub fn as_slice(&self) -> &'a [u8] {
        let mut comps = *self;
        if comps.front == State::Body {
            comps.trim_left();
        }
        if comps.back == State::Body {
            comps.trim_right();
        }
        comps.path
    }
}

impl<'a> Iterator for Components<'a> {
    type Item = Component<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.finished() {
            match self.front {
                State::StartDir => {
                    self.front = State::Body;
                    if self.has_physical_root {
                        debug_assert!(!self.path.is_empty());
                        self.path = &self.path[1..];
                        return Some(Component::Root);
                    } else if self.include_cur_dir() {
                        debug_assert!(!self.path.is_empty());
                        self.path = &self.path[1..];
                        return Some(Component::CurDir);
                    }
                }
                State::Body if !self.path.is_empty() => {
                    let (size, comp) = self.parse_next_component();
                    self.path = &self.path[size..];
                    if comp.is_some() {
                        return comp;
                    }
                }
                State::Body => {
                    self.front = State::Done;
                }
                State::Done => unreachable!(),
            }
        }
        None
    }
}

impl<'a> DoubleEndedIterator for Components<'a> {
    fn next_back(&mut self) -> Option<Component<'a>> {
        while !self.finished() {
            match self.back {
                State::Body if self.path.len() > self.len_before_body() => {
                    let (size, comp) = self.parse_next_component_back();
                    self.path = &self.path[..self.path.len() - size];
                    if comp.is_some() {
                        return comp;
                    }
                }
                State::Body => {
                    self.back = State::StartDir;
                }
                State::StartDir => {
                    self.back = State::Done;
                    if self.has_physical_root {
                        self.path = &self.path[..self.path.len() - 1];
                        return Some(Component::Root);
                    } else if self.include_cur_dir() {
                        self.path = &self.path[..self.path.len() - 1];
                        return Some(Component::CurDir);
                    }
                }
                State::Done => unreachable!(),
            }
        }
        None
    }
}

impl FusedIterator for Components<'_> {}

impl<'a> PartialEq for Components<'a> {
    #[inline]
    fn eq(&self, other: &Components<'a>) -> bool {
        let Components {
            path: _,
            front: _,
            back: _,
            has_physical_root: _,
        } = self;

        // Fast path for exact matches, e.g. for hashmap lookups.
        // Don't explicitly compare the prefix or has_physical_root fields since they'll
        // either be covered by the `path` buffer or are only relevant for `prefix_verbatim()`.
        if self.path.len() == other.path.len()
            && self.front == other.front
            && self.back == State::Body
            && other.back == State::Body
        {
            // possible future improvement: this could bail out earlier if there were a
            // reverse memcmp/bcmp comparing back to front
            if self.path == other.path {
                return true;
            }
        }

        // compare back to front since absolute paths often share long prefixes
        Iterator::eq((*self).rev(), (*other).rev())
    }
}

impl Eq for Components<'_> {}

impl<'a> PartialOrd for Components<'a> {
    #[inline]
    fn partial_cmp(&self, other: &Components<'a>) -> Option<cmp::Ordering> {
        Some(compare_components(*self, *other))
    }
}

impl Ord for Components<'_> {
    #[inline]
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        compare_components(*self, *other)
    }
}

fn compare_components(mut left: Components<'_>, mut right: Components<'_>) -> cmp::Ordering {
    if left.front == right.front {
        let first_difference = match left.path.iter().zip(right.path).position(|(&a, &b)| a != b) {
            None if left.path.len() == right.path.len() => return cmp::Ordering::Equal,
            None => left.path.len().min(right.path.len()),
            Some(diff) => diff,
        };

        if let Some(previous_sep) = memchr::memrchr(b'/', &left.path[..first_difference]) {
            let mismatched_component_start = previous_sep + 1;
            left.path = &left.path[mismatched_component_start..];
            left.front = State::Body;
            right.path = &right.path[mismatched_component_start..];
            right.front = State::Body;
        }
    }

    Iterator::cmp(left, right)
}

struct DirBuilderBuffer<'a> {
    buf: &'a mut [u8],
    sep: *mut u8,
}

impl<'a> DirBuilderBuffer<'a> {
    pub unsafe fn new_unchecked(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            sep: core::ptr::null_mut(),
        }
    }

    pub fn as_c_str(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.buf.as_ptr().cast()) }
    }

    pub fn parent(&mut self) -> Option<Self> {
        let mut comps = Components::new(self.buf);
        let comp = comps.next_back();
        if let Some(len) = comp.and_then(|p| match p {
            Component::Normal(_) | Component::CurDir | Component::ParentDir => {
                Some(comps.as_slice().len())
            }
            _ => None,
        }) {
            unsafe {
                let sep = self.buf.as_mut_ptr().add(len);
                *sep = 0;
                Some(Self::new_unchecked(core::slice::from_raw_parts_mut(
                    self.buf.as_mut_ptr(),
                    len,
                )))
            }
        } else {
            None
        }
    }
}

impl<'a> Drop for DirBuilderBuffer<'a> {
    fn drop(&mut self) {
        unsafe { *self.sep = b'/' };
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn is_dir(path: &CStr) -> bool {
    use core::mem::MaybeUninit;
    let md = unsafe {
        let mut buf = MaybeUninit::<libc::stat>::uninit();
        if { libc::stat(path.as_ptr(), buf.as_mut_ptr()) } == -1 {
            return false;
        }
        buf.assume_init()
    };

    (md.st_mode & libc::S_IFMT) == libc::S_IFDIR
}

#[cfg(target_os = "linux")]
fn is_dir(path: &CStr) -> bool {
    use linux_stat::{stat_cstr, Errno};
    loop {
        match stat_cstr(path) {
            Err(Errno::EINTR) => (),
            Err(_) => return false,
            Ok(stat) => return stat.is_dir(),
        }
    }
}

pub struct DirBuilder {
    recursive: bool,
    mode: u16,
}

impl DirBuilder {
    #[must_use]
    pub fn new() -> DirBuilder {
        DirBuilder {
            recursive: false,
            mode: 0o777,
        }
    }

    #[inline]
    pub fn recursive(&mut self, recursive: bool) -> &mut Self {
        self.recursive = recursive;
        self
    }

    #[inline]
    pub fn mode(&mut self, mode: u16) -> &mut Self {
        self.mode = mode;
        self
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    fn mkdir(&self, path: &CStr) -> crate::io::Result<()> {
        if unsafe { libc::mkdir(path.as_ptr(), self.mode.into()) } == -1 {
            Err(crate::io::last_os_error())
        } else {
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    fn mkdir(&self, path: &CStr) -> crate::io::Result<()> {
        use linux_stat::CURRENT_DIRECTORY;
        use linux_syscalls::{syscall, Errno, Sysno};

        loop {
            match unsafe {
                syscall!([ro] Sysno::mkdirat, CURRENT_DIRECTORY, path.as_ptr(), self.mode)
            } {
                Err(Errno::EINTR) => (),
                Err(err) => return Err(err.into()),
                Ok(_) => return Ok(()),
            }
        }
    }

    pub fn create<P: AsRef<CStr> + IntoBuffer>(&self, path: P) -> crate::io::Result<()> {
        if self.recursive {
            if path.as_ref().to_bytes().is_empty() {
                return Ok(());
            }

            match self.mkdir(path.as_ref()) {
                Ok(()) => return Ok(()),
                Err(ref e) if e.kind() == crate::io::ErrorKind::NotFound => (),
                Err(_) if is_dir(path.as_ref()) => return Ok(()),
                Err(e) => return Err(e),
            }

            let mut buf = path.into_buffer();
            if buf.last().map(|&c| c != 0).unwrap_or(true) {
                buf.reserve_exact(1);
                buf.push(0);
                buf.shrink_to_fit();
            }
            let buf = unsafe { DirBuilderBuffer::new_unchecked(&mut buf) };

            self.create_dir_all(buf)
        } else {
            self.mkdir(path.as_ref())
        }
    }

    fn create_dir_all(&self, mut path: DirBuilderBuffer) -> crate::io::Result<()> {
        if path.buf.is_empty() {
            return Ok(());
        }

        match path.parent() {
            Some(p) => self.create_dir_all(p)?,
            None => {
                return Err(crate::io::Error::new_static(
                    crate::io::ErrorKind::Other,
                    "failed to create whole tree",
                ));
            }
        }

        match self.mkdir(path.as_c_str()) {
            Ok(()) => Ok(()),
            Err(_) if is_dir(path.as_c_str()) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

mod __sealed {
    pub trait Sealed {}
}

pub trait IntoBuffer: __sealed::Sealed {
    fn into_buffer(self) -> Vec<u8>;
}

impl __sealed::Sealed for &CStr {}
impl __sealed::Sealed for CString {}
impl __sealed::Sealed for Vec<u8> {}
impl __sealed::Sealed for &[u8] {}

impl IntoBuffer for &CStr {
    #[inline]
    fn into_buffer(self) -> Vec<u8> {
        self.to_bytes_with_nul().to_vec()
    }
}

impl IntoBuffer for CString {
    #[inline]
    fn into_buffer(self) -> Vec<u8> {
        self.into_bytes_with_nul()
    }
}

impl IntoBuffer for Vec<u8> {
    #[inline]
    fn into_buffer(self) -> Vec<u8> {
        self
    }
}

impl IntoBuffer for &[u8] {
    #[inline]
    fn into_buffer(self) -> Vec<u8> {
        self.to_vec()
    }
}

impl Default for DirBuilder {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}
