use alloc_crate::rc::Rc;
use core::{cell::RefCell, mem};
use sstd::{
    ffi::CStr,
    io::{self, Write},
};

pub use pam::Pam as Authenticator;
pub use pam::*;

use super::tty::{TtyIn, TtyOut};

pub struct LinesIterator<'a> {
    slice: Option<&'a [u8]>,
}

impl<'a> LinesIterator<'a> {
    #[inline]
    pub fn new(slice: &'a [u8]) -> Self {
        Self { slice: Some(slice) }
    }
}

impl<'a> Iterator for LinesIterator<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let s = self.slice.take()?;
        if let Some(pos) = memchr::memchr2(b'\r', b'\n', s) {
            let end = match unsafe { s.get_unchecked(pos) } {
                b'\n' if matches!(s.get(pos + 1), Some(b'\r')) => pos + 2,
                b'\r' if matches!(s.get(pos + 1), Some(b'\n')) => pos + 2,
                _ => pos + 1,
            };

            self.slice = s.get(end..);
            s.get(..pos)
        } else {
            Some(s)
        }
    }
}

pub struct PezzoConversation<'a> {
    name: &'a CStr,
    timedout: bool,
    timeout: u32,
    tty_in: Rc<RefCell<TtyIn>>,
    tty_out: Rc<RefCell<TtyOut>>,
    bell: bool,
}

impl<'a> PezzoConversation<'a> {
    #[inline]
    pub fn new(ctx: &'a super::Context) -> Self {
        Self::from_values(
            ctx.prompt_timeout(),
            ctx.tty_in(),
            ctx.tty_out(),
            ctx.original_user().name(),
            ctx.bell(),
        )
    }

    #[inline]
    pub fn from_values(
        timeout: u32,
        tty_in: Rc<RefCell<TtyIn>>,
        tty_out: Rc<RefCell<TtyOut>>,
        name: &'a CStr,
        bell: bool,
    ) -> Self {
        Self {
            timeout,
            timedout: false,
            tty_in,
            tty_out,
            name,
            bell,
        }
    }

    fn _prompt(&mut self, prompt: &CStr, echo: bool) -> ConvResult<secure_read::CBuffer> {
        fn base_prompt_is_password(prompt: &CStr, name: &CStr) -> bool {
            if let Some(rest) = prompt.to_bytes().strip_prefix(b"Password:") {
                return rest.is_empty() || rest == b" ";
            } else if let Some(rest) = prompt.to_bytes().get(name.to_bytes().len()..) {
                if let Some(rest) = rest.strip_prefix(b"'s Password:") {
                    return rest.is_empty() || rest == b" ";
                }
            }

            false
        }

        #[cfg(not(target_os = "linux"))]
        #[inline(always)]
        fn prompt_is_password(prompt: &CStr, name: &CStr) -> bool {
            base_prompt_is_password(prompt, name)
        }

        #[cfg(target_os = "linux")]
        #[inline(always)]
        fn prompt_is_password(prompt: &CStr, name: &CStr) -> bool {
            extern "C" {
                fn dgettext(domainname: *const i8, msgid: *const i8) -> *const i8;
            }
            const DOMAIN: *const i8 = b"Linux-PAM\0".as_ptr() as *const i8;

            unsafe {
                libc::strcmp(
                    prompt.as_ptr(),
                    dgettext(DOMAIN, "Password:".as_ptr().cast()).cast(),
                ) == 0
                    || libc::strcmp(
                        prompt.as_ptr(),
                        dgettext(DOMAIN, "Password: ".as_ptr().cast()).cast(),
                    ) == 0
                    || base_prompt_is_password(prompt, name)
            }
        }

        if prompt_is_password(prompt, self.name) {
            self.print_prompt_password()?;
        } else {
            let mut out = self.tty_out.borrow_mut();
            let mut it = LinesIterator::new(prompt.to_bytes());
            if let Some(mut prev) = it.next() {
                for mut line in it {
                    mem::swap(&mut line, &mut prev);

                    out.write_all(line).map_err(|_| ConvError::Generic)?;
                    out.write_all(b"\r\n").map_err(|_| ConvError::Generic)?;
                }
                let line = prev;
                if !line.is_empty() {
                    out.write_all(line).map_err(|_| ConvError::Generic)?;
                    if unsafe { *line.get_unchecked(line.len() - 1) } != b' ' {
                        out.write_all(b" ").map_err(|_| ConvError::Generic)?;
                    }
                }
            }

            if self.bell {
                out.write_all(b"\x07").map_err(|_| ConvError::Generic)?;
            }

            out.flush().map_err(|_| ConvError::Generic)?;
        }

        let timeout = self.prompt_timeout();
        let buf = {
            let mut inp = self.tty_in.borrow_mut();
            let line_res = if echo {
                inp.c_readline(timeout)
            } else {
                inp.c_readline_noecho(timeout)
            };
            match line_res {
                Err(err) => {
                    {
                        let mut out = self.tty_out.borrow_mut();
                        _ = out.write_all(b"\n");
                        _ = out.flush();

                        if err.kind() == io::ErrorKind::TimedOut {
                            self.timedout = true;
                            _ = out.write_all(b"pezzo: timed out reading password\n");
                            _ = out.flush();
                        }
                    }
                    Err(ConvError::Generic)
                }
                Ok(mut buf) => {
                    if buf.as_slice().last().map_or(false, |&c| c == b'\n') {
                        if let Some(l) = buf.len().checked_sub(1) {
                            buf.truncate(l)
                        }
                    } else {
                        let mut out = self.tty_out.borrow_mut();
                        _ = out.write_all(b"\n");
                        _ = out.flush();
                    }
                    Ok(buf)
                }
            }?
        };

        Ok(buf)
    }

    fn print_message(&mut self, message: &[u8]) -> ConvResult<()> {
        let mut out = self.tty_out.borrow_mut();
        let mut it = LinesIterator::new(message);
        if let Some(mut prev) = it.next() {
            for mut line in it {
                mem::swap(&mut line, &mut prev);

                out.write_all(line).map_err(|_| ConvError::Generic)?;
                out.write_all(b"\r\n").map_err(|_| ConvError::Generic)?;
            }
            let line = prev;
            if !line.is_empty() {
                out.write_all(line).map_err(|_| ConvError::Generic)?;
                out.write_all(b"\r\n").map_err(|_| ConvError::Generic)?;
            }
        }
        out.flush().map_err(|_| ConvError::Generic)
    }

    pub fn print_prompt_password(&mut self) -> ConvResult<()> {
        let mut out = self.tty_out.borrow_mut();
        out.write_all(b"[pezzo] Password for ")
            .map_err(|_| ConvError::Generic)?;
        out.write_all(self.name.to_bytes())
            .map_err(|_| ConvError::Generic)?;
        out.write_all(b": ").map_err(|_| ConvError::Generic)?;
        if self.bell {
            out.write_all(b"\x07").map_err(|_| ConvError::Generic)?;
        }
        out.flush().map_err(|_| ConvError::Generic)
    }

    #[inline]
    pub fn prompt_timeout(&self) -> u32 {
        self.timeout
    }

    #[inline]
    pub fn is_timedout(&self) -> bool {
        self.timedout
    }
}

impl<'a> Conversation for PezzoConversation<'a> {
    type Buffer = secure_read::CBuffer;

    fn preflight(&mut self) {
        self.timedout = false;
    }

    #[inline]
    fn prompt(&mut self, prompt: &CStr) -> ConvResult<secure_read::CBuffer> {
        self._prompt(prompt, true)
    }

    #[inline]
    fn prompt_noecho(&mut self, prompt: &CStr) -> ConvResult<secure_read::CBuffer> {
        self._prompt(prompt, false)
    }

    fn info(&mut self, message: &CStr) -> ConvResult<()> {
        self.print_message(message.to_bytes())
    }

    fn error(&mut self, message: &CStr) -> ConvResult<()> {
        self.print_message(message.to_bytes())
    }
}
