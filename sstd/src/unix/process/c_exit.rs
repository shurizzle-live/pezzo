use alloc_crate::boxed::Box;

pub fn exit(code: i32) -> ! {
    unsafe { libc::exit(code) }
}

extern "C" fn trampoline<F: Fn(i32)>(code: i32, data: *mut core::ffi::c_void) {
    unsafe { (Box::<F>::from_raw(data.cast()))(code) };
}

#[must_use]
pub fn atexit(f: extern "C" fn()) -> bool {
    unsafe { libc::atexit(f) == 0 }
}

extern "C" {
    #[link_name = "on_exit"]
    fn c_on_exit(
        cb: extern "C" fn(code: i32, data: *mut core::ffi::c_void),
        data: *mut core::ffi::c_void,
    ) -> core::ffi::c_int;
}

#[must_use]
pub fn on_exit<F: Fn(i32)>(f: F) -> bool {
    let boxed = Box::into_raw(Box::new(f)) as *mut core::ffi::c_void;
    unsafe { c_on_exit(trampoline::<F>, boxed) == 0 }
}
