use core::mem::MaybeUninit;

use alloc_crate::boxed::Box;
use linux_syscalls::{syscall, Sysno};

enum ExitFn {
    At(extern "C" fn()),
    On(Box<dyn Fn(i32)>),
}

struct FnList {
    next: *mut Self,
    map: u32,
    fns: MaybeUninit<[ExitFn; 32]>,
}

impl FnList {
    pub const fn new() -> Self {
        Self {
            next: core::ptr::null_mut(),
            map: 0,
            fns: MaybeUninit::uninit(),
        }
    }

    pub fn len(&self) -> usize {
        self.map.count_ones() as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn try_push(&mut self, f: ExitFn) -> Result<(), ExitFn> {
        {
            let x = alloc_crate::format!("{:0>32b} -> ", self.map);
            unsafe {
                linux_syscalls::raw_syscall!([ro] linux_syscalls::Sysno::write, 1, x.as_ptr(), x.len())
            };
        }

        let res = match self.map.leading_zeros() {
            0 => Err(f),
            n if n > 32 => unreachable!(),
            n => {
                let n = 31 - (n as usize - 1);
                unsafe { *self.fns.as_mut_ptr().cast::<ExitFn>().add(n) = f };
                self.map |= 1 << n;
                Ok(())
            }
        };

        {
            let x = alloc_crate::format!("{:0>32b}\n", self.map);
            unsafe {
                linux_syscalls::raw_syscall!([ro] linux_syscalls::Sysno::write, 1, x.as_ptr(), x.len())
            };
        }

        res
    }

    pub fn pop(&mut self) -> Option<ExitFn> {
        match self.map.leading_zeros() {
            32 => None,
            n if n > 32 => unreachable!(),
            n => {
                let n = 31 - n as usize;
                let res = unsafe {
                    core::ptr::read_volatile(self.fns.as_mut_ptr().cast::<ExitFn>().add(n))
                };
                self.map &= !(1 << n);
                Some(res)
            }
        }
    }
}

impl Drop for FnList {
    fn drop(&mut self) {
        while let Some(e) = self.pop() {
            drop(e);
        }
    }
}

#[used]
static mut INIT: FnList = FnList::new();
#[used]
static mut EXIT_FNS: *mut FnList = unsafe { &INIT as *const FnList as *mut FnList };
#[used]
static mut DONE: bool = false;

unsafe fn push(f: ExitFn) {
    let f = if let Err(f) = (*EXIT_FNS).try_push(f) {
        f
    } else {
        return;
    };

    let mut list: Box<MaybeUninit<FnList>> = Box::new(MaybeUninit::uninit());
    (*list.as_mut_ptr()).next = EXIT_FNS;
    (*list.as_mut_ptr()).map = 1;
    *(*list.as_mut_ptr()).fns.as_mut_ptr().cast::<ExitFn>() = f;
    EXIT_FNS = Box::into_raw(list) as *mut FnList;
}

unsafe fn pop() -> Option<ExitFn> {
    loop {
        if let Some(f) = (*EXIT_FNS).pop() {
            if (*EXIT_FNS).is_empty() && !(*EXIT_FNS).next.is_null() {
                let curr = EXIT_FNS;
                EXIT_FNS = (*EXIT_FNS).next;
                drop(Box::from_raw(curr));
            }
            return Some(f);
        }

        if (*EXIT_FNS).next.is_null() {
            return None;
        }
        let curr = EXIT_FNS;
        EXIT_FNS = (*EXIT_FNS).next;
        drop(Box::from_raw(curr));
    }
}

#[must_use]
pub fn atexit(f: extern "C" fn()) -> bool {
    unsafe { add_fn(ExitFn::At(f)) }
}

#[must_use]
pub fn on_exit<F: Fn(i32) + 'static>(f: F) -> bool {
    unsafe { add_fn(ExitFn::On(Box::new(f))) }
}

pub fn exit(code: i32) -> ! {
    unsafe {
        while let Some(e) = pop() {
            match e {
                ExitFn::At(f) => f(),
                ExitFn::On(f) => f(code),
            }
        }

        DONE = true;

        syscall!([!] Sysno::exit, code)
    }
}

unsafe fn add_fn(f: ExitFn) -> bool {
    if DONE {
        return false;
    }
    push(f);
    true
}
