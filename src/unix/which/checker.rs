use std::ffi::CStr;

pub trait Checker {
    fn is_valid(&self, path: &CStr) -> bool;
}

pub struct ExecutableChecker;

impl ExecutableChecker {
    #[inline(always)]
    pub fn new() -> ExecutableChecker {
        ExecutableChecker
    }
}

impl Default for ExecutableChecker {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

impl Checker for ExecutableChecker {
    #[cfg(target_os = "linux")]
    fn is_valid(&self, path: &CStr) -> bool {
        use linux_defs::AccessAtFlags;
        use linux_stat::CURRENT_DIRECTORY;
        use linux_syscalls::{syscall, Sysno};

        unsafe {
            syscall!([ro] Sysno::faccessat, CURRENT_DIRECTORY, path.as_ptr(), AccessAtFlags::EXEC.bits())
        }
        .is_ok()
    }

    #[cfg(not(target_os = "linux"))]
    fn is_valid(&self, path: &CStr) -> bool {
        unsafe { libc::access(path.as_ptr().cast(), libc::X_OK) == 0 }
    }
}

pub struct ExistedChecker;

impl ExistedChecker {
    #[inline(always)]
    pub fn new() -> ExistedChecker {
        ExistedChecker
    }
}

impl Default for ExistedChecker {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

impl Checker for ExistedChecker {
    #[cfg(target_os = "linux")]
    fn is_valid(&self, path: &CStr) -> bool {
        linux_stat::stat_cstr(path)
            .map(|md| md.is_regular())
            .unwrap_or(false)
    }

    #[cfg(not(target_os = "linux"))]
    fn is_valid(&self, path: &CStr) -> bool {
        use std::mem::MaybeUninit;

        let mut buf = MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::stat(path.as_ptr().cast(), buf.as_mut_ptr()) } == -1 {
            return false;
        }
        let stat = unsafe { buf.assume_init() };

        (stat.st_mode & libc::S_IFMT) == libc::S_IFREG
    }
}

pub struct CompositeChecker {
    checkers: Vec<Box<dyn Checker>>,
}

impl CompositeChecker {
    pub fn new() -> CompositeChecker {
        CompositeChecker {
            checkers: Vec::new(),
        }
    }

    pub fn add_checker(mut self, checker: Box<dyn Checker>) -> CompositeChecker {
        self.checkers.push(checker);
        self
    }
}

impl Default for CompositeChecker {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Checker for CompositeChecker {
    fn is_valid(&self, path: &CStr) -> bool {
        self.checkers.iter().all(|checker| checker.is_valid(path))
    }
}
