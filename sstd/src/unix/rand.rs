#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn getrandom(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("unexpected getrandom error");
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn getrandom(buf: &mut [u8]) {
    use crate::{
        ffi::CStr,
        io::{Errno, Read},
        sync::atomic::{AtomicBool, Ordering},
    };
    use linux_raw_sys::general::{GRND_INSECURE, GRND_NONBLOCK};
    use linux_syscalls::{syscall, Sysno};

    fn real_getrandom(buf: &mut [u8]) -> Result<usize, Errno> {
        static GRND_INSECURE_AVAILABLE: AtomicBool = AtomicBool::new(true);
        if GRND_INSECURE_AVAILABLE.load(Ordering::Relaxed) {
            match unsafe { syscall!(Sysno::getrandom, buf.as_mut_ptr(), buf.len(), GRND_INSECURE) }
            {
                Err(Errno::EINVAL) => {
                    GRND_INSECURE_AVAILABLE.store(false, Ordering::Relaxed);
                }
                other => return other,
            }
        }

        unsafe { syscall!(Sysno::getrandom, buf.as_mut_ptr(), buf.len(), GRND_NONBLOCK) }
    }

    fn getrandom_fill_bytes(buf: &mut [u8]) -> bool {
        static GETRANDOM_UNAVAILABLE: AtomicBool = AtomicBool::new(false);
        if GETRANDOM_UNAVAILABLE.load(Ordering::Relaxed) {
            return false;
        }

        let mut read = 0;
        while read < buf.len() {
            match real_getrandom(buf) {
                Err(Errno::EINTR) => continue,
                Err(Errno::EPERM) | Err(Errno::ENOSYS) => {
                    GETRANDOM_UNAVAILABLE.store(true, Ordering::Relaxed);
                    return false;
                }
                Err(Errno::EAGAIN) => return false,
                Err(err) => panic!("unexpected getrandom error: {}", err),
                Ok(result) => {
                    read += result;
                }
            }
        }
        true
    }

    if getrandom_fill_bytes(buf) {
        return;
    }

    let mut file = crate::fs::OpenOptions::new()
        .read(true)
        .open_cstr(unsafe { CStr::from_bytes_with_nul_unchecked(b"/dev/urandom\0") })
        .expect("failed to open /dev/urandom");
    file.read_exact(buf).expect("failed to read /dev/urandom");
}

pub fn hashmap_random_keys() -> (u64, u64) {
    const KEY_LEN: usize = core::mem::size_of::<u64>();

    let mut v = [0u8; KEY_LEN * 2];
    getrandom(&mut v);

    let key1 = v[0..KEY_LEN].try_into().unwrap();
    let key2 = v[KEY_LEN..].try_into().unwrap();

    (u64::from_ne_bytes(key1), u64::from_ne_bytes(key2))
}
