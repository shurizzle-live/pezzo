use crate::ffi::CStr;
use core::iter::FusedIterator;

#[used]
static mut ARGS: &[*const u8] = &[];
#[used]
static mut ENV: *const *const u8 = core::ptr::null();

pub unsafe fn init(argc: isize, argv: *const *const u8, envp: *const *const u8) {
    ARGS = core::slice::from_raw_parts(argv, argc as _);
    ENV = envp;
    #[cfg(target_os = "linux")]
    linux_syscalls::init_from_environ(envp);
}

pub fn args() -> &'static [*const u8] {
    unsafe { ARGS }
}

fn strip_var_name(mut s: *const u8, mut pref: *const u8) -> Option<*const u8> {
    unsafe {
        while *pref != 0 {
            if *s == b'=' || *s != *pref {
                return None;
            }
            s = s.add(1);
            pref = pref.add(1);
        }

        if *s == b'=' {
            Some(s.add(1))
        } else {
            None
        }
    }
}

pub fn var(name: &CStr) -> Option<&'static CStr> {
    unsafe {
        if ENV.is_null() {
            return None;
        }
        let mut ptr = ENV;
        let name = name.as_ptr().cast::<u8>();
        while !(*ptr).is_null() {
            if let Some(var) = strip_var_name(*ptr, name) {
                return Some(CStr::from_ptr(var.cast()));
            }
        }
        None
    }
}

pub struct Vars(*const *const u8);

impl Iterator for Vars {
    type Item = (&'static [u8], &'static CStr);

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_null() {
            return None;
        }

        unsafe {
            if (*self.0).is_null() {
                self.0 = core::ptr::null();
                return None;
            }

            let name = *self.0;
            let mut ptr = *self.0;
            self.0 = self.0.add(1);
            loop {
                if *ptr == 0 {
                    return Some((
                        core::slice::from_raw_parts(name, (ptr as usize) - (name as usize)),
                        CStr::from_ptr(ptr.cast()),
                    ));
                }

                if *ptr == b'=' {
                    return Some((
                        core::slice::from_raw_parts(name, (ptr as usize) - (name as usize)),
                        CStr::from_ptr(ptr.add(1).cast()),
                    ));
                }

                ptr = ptr.add(1);
            }
        }
    }
}

impl FusedIterator for Vars {}

pub fn vars() -> Vars {
    Vars(unsafe { ENV })
}
