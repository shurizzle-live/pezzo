use sstd::{
    io::{self, Errno},
    time::Instant,
};

#[inline(always)]
fn poll_read_inf(fd: io::RawFd) -> Result<(), Errno> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    const TIMEOUT: core::ffi::c_int = -1;

    loop {
        match unsafe {
            let res = libc::poll(&mut pfd as *mut libc::pollfd, 1, TIMEOUT);
            if res == -1 {
                Err(Errno::last_os_error())
            } else {
                Ok(core::mem::transmute::<i32, u32>(res))
            }
        } {
            Ok(0) => return Err(Errno::ETIMEDOUT),
            Ok(_) => return Ok(()),
            Err(Errno::EAGAIN) | Err(Errno::EINTR) => (),
            Err(err) => return Err(err),
        }
    }
}

pub fn poll_read(fd: io::RawFd, timeout: i32) -> io::Result<()> {
    let mut timeout = if timeout > 0 {
        timeout as u32 * 1000
    } else {
        return Ok(poll_read_inf(fd)?);
    };

    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };

    loop {
        let pre = Instant::now();
        match unsafe {
            let res = libc::poll(&mut pfd as *mut libc::pollfd, 1, timeout as i32);
            if res == -1 {
                Err(Errno::last_os_error())
            } else {
                Ok(core::mem::transmute::<i32, u32>(res))
            }
        } {
            Ok(0) => return Err(Errno::ETIMEDOUT.into()),
            Ok(_) => return Ok(()),
            Err(Errno::EAGAIN) | Err(Errno::EINTR) => {
                timeout = pre
                    .elapsed()
                    .as_millis()
                    .try_into()
                    .ok()
                    .and_then(|elapsed| timeout.checked_sub(elapsed))
                    .and_then(|t| if t == 0 { None } else { Some(t) })
                    .map_or(Err(Errno::ETIMEDOUT), Ok)?;
            }
            Err(err) => return Err(err.into()),
        }
    }
}
