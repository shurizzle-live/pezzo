use std::ffi::{CStr, CString};

use crate::unix::__errno;

pub fn hostname() -> CString {
    unsafe {
        let mut buf = Vec::<u8>::with_capacity(1024);
        while {
            let res = libc::gethostname(buf.as_mut_ptr().cast(), buf.capacity());

            if res == -1 {
                if *__errno() == libc::ENAMETOOLONG {
                    buf.reserve_exact(buf.capacity() + buf.capacity() / 10);
                    true
                } else {
                    unreachable!()
                }
            } else if res == 0 {
                buf.set_len(
                    CStr::from_ptr(buf.as_ptr() as *const _)
                        .to_bytes_with_nul()
                        .len(),
                );
                buf.shrink_to_fit();
                false
            } else {
                unreachable!()
            }
        } {}

        CString::from_vec_with_nul_unchecked(buf)
    }
}
