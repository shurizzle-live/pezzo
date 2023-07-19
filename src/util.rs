cfg_if::cfg_if! {
    if #[cfg(unix)] {
        use alloc_crate::vec::Vec;

        cfg_if::cfg_if! {
            if #[cfg(target_os = "linux")] {
                pub fn slurp_cstr<P: AsRef<crate::ffi::CStr>>(path: P) -> crate::io::Result<Vec<u8>> {
                    use crate::io::{Read, AsRawFd};
                    use tty_info::Errno;

                    let mut f = crate::fs::OpenOptions::new().read(true).open_cstr(path.as_ref())?;
                    let len = 'stat: loop {
                        match unsafe { linux_stat::fstat(f.as_raw_fd()) } {
                            Err(Errno::EINTR) => (),
                            Err(err) => return Err(err.into()),
                            Ok(md) => break 'stat md.size() as usize,
                        }
                    };

                    let mut buf = Vec::<u8>::with_capacity(len);
                    unsafe {
                        f.read_exact(core::slice::from_raw_parts_mut(buf.as_mut_ptr(), len))?;
                        buf.set_len(len);
                    }

                    Ok(buf)
                }
            } else {
                pub fn slurp_cstr<P: AsRef<crate::ffi::CStr>>(path: P) -> std::io::Result<Vec<u8>> {
                    use std::io::{Read, AsRawFd};
                    use tty_info::Errno;
                    use std::mem::MaybeUninit;

                    let mut f = crate::fs::OpenOptions::new().read(true).open_cstr(path.as_ref())?;
                    let len = 'stat: loop {
                        let mut buf = MaybeUninit::<libc::stat>::uninit();
                        match unsafe {
                            if libc::fstat(f.as_raw_fd(), buf.as_mut_ptr()) == -1 {
                                Err(Errno::last_os_error())
                            } else {
                                Ok(buf.assume_init())
                            }
                        } {
                            Err(Errno::EINTR) => (),
                            Err(err) => return Err(err.into()),
                            Ok(md) => break 'stat md.st_size as usize,
                        }
                    };

                    let mut buf = Vec::<u8>::with_capacity(len);
                    unsafe {
                        f.read_exact(std::slice::from_raw_parts_mut(buf.as_mut_ptr(), len))?;
                        buf.set_len(len);
                    }

                    Ok(buf)
                }
            }
        }
    }
}
