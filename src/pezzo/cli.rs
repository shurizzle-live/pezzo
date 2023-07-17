use core::{
    cell::{OnceCell, RefCell},
    fmt,
    mem::ManuallyDrop,
};
use std::{
    ffi::{CStr, CString},
    io::{BufReader, BufWriter, Write},
};

pub struct Rest<I> {
    first: Option<*const u8>,
    inner: Option<I>,
}

impl<I: Iterator<Item = *const u8>> Rest<I> {
    #[inline]
    const fn new(inner: I) -> Self {
        Self {
            first: None,
            inner: Some(inner),
        }
    }

    #[inline]
    const fn with_first(first: *const u8, inner: I) -> Self {
        Self {
            first: Some(first),
            inner: Some(inner),
        }
    }

    #[inline]
    const fn empty() -> Self {
        Self {
            first: None,
            inner: None,
        }
    }
}

impl<I: Iterator<Item = *const u8>> Iterator for Rest<I> {
    type Item = &'static CStr;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(next) = self.first.take() {
            return Some(unsafe { CStr::from_ptr(next.cast()) });
        }
        self.inner
            .as_mut()
            .and_then(Iterator::next)
            .map(|ptr| unsafe { CStr::from_ptr(ptr.cast()) })
    }
}

pub enum Parser<I> {
    Empty(I),
    Short(*const u8, I),
    Rest(Rest<I>),
    End,
}

#[derive(Debug)]
pub enum RawFlag {
    Short(u8),
    Long(&'static [u8]),
    LongWithValue(&'static [u8], &'static CStr),
}

impl<I: Iterator<Item = *const u8>> Parser<I> {
    pub fn next_flag(&mut self) -> Option<RawFlag> {
        unsafe {
            loop {
                let (res, next_state) = match self {
                    Self::End | Self::Rest(_) => return None,
                    Self::Short(current, it) => {
                        let current = *current;
                        let it = ManuallyDrop::new(core::ptr::read(it as *const I));

                        if *current == 0 {
                            (None, Self::Empty(ManuallyDrop::into_inner(it)))
                        } else {
                            (
                                Some(RawFlag::Short(*current)),
                                Self::Short(current.add(1), ManuallyDrop::into_inner(it)),
                            )
                        }
                    }
                    Self::Empty(it) => 'next: {
                        let mut it = ManuallyDrop::new(core::ptr::read(it as *const I));

                        let mut current = if let Some(current) = it.next() {
                            current
                        } else {
                            break 'next (None, Self::End);
                        };

                        // if string starts with '-' is a flag else switch to rest state
                        if *current == b'-' {
                            current = current.add(1);
                        } else {
                            break 'next (
                                None,
                                Parser::Rest(Rest::with_first(
                                    current,
                                    ManuallyDrop::into_inner(it),
                                )),
                            );
                        }

                        // if the second char isn't '-' we are facing a short flag sequence
                        if *current != b'-' {
                            let flag = *current;
                            current = current.add(1);

                            break 'next (
                                Some(RawFlag::Short(flag)),
                                Self::Short(current, ManuallyDrop::into_inner(it)),
                            );
                        }
                        current = current.add(1);

                        // in this case string was '--' so we stop parsing elements
                        if *current == 0 {
                            break 'next (
                                None,
                                Self::Rest(Rest::new(ManuallyDrop::into_inner(it))),
                            );
                        }

                        let start = current;
                        loop {
                            let c = *current;

                            // --name=value case
                            if c == b'=' {
                                let name = core::slice::from_raw_parts(
                                    start,
                                    (current as usize) - (start as usize),
                                );
                                let value = CStr::from_ptr(current.add(1).cast());

                                break 'next (
                                    Some(RawFlag::LongWithValue(name, value)),
                                    Self::Empty(ManuallyDrop::into_inner(it)),
                                );
                            }

                            // --name case
                            if c == 0 {
                                let flag = RawFlag::Long(core::slice::from_raw_parts(
                                    start,
                                    (current as usize) - (start as usize),
                                ));

                                break 'next (
                                    Some(flag),
                                    Self::Empty(ManuallyDrop::into_inner(it)),
                                );
                            }

                            current = current.add(1);
                        }
                    }
                };
                core::ptr::write(self, next_state);
                if let Some(res) = res {
                    return Some(res);
                }
            }
        }
    }

    pub fn pop(&mut self) -> Option<&'static CStr> {
        unsafe {
            let (res, next_state) = match self {
                Self::Empty(it) => match it.next() {
                    Some(next) => {
                        if *next == 0 || *next != b'-' {
                            return Some(CStr::from_ptr(next.cast()));
                        }

                        let ptr = next.add(1);
                        if *ptr == 0 || *ptr != b'-' {
                            return Some(CStr::from_ptr(next.cast()));
                        }

                        let ptr = ptr.add(1);
                        if *ptr != 0 {
                            return Some(CStr::from_ptr(next.cast()));
                        }

                        (None, Self::Rest(Rest::new(core::ptr::read(it as *const I))))
                    }
                    None => (None, Self::End),
                },
                Self::Short(current, it) => {
                    let current = *current;
                    let mut it = ManuallyDrop::new(core::ptr::read(it as *const I));

                    if *current == 0 {
                        (
                            it.next().map(|ptr| CStr::from_ptr(ptr.cast())),
                            Self::Empty(ManuallyDrop::into_inner(it)),
                        )
                    } else {
                        (
                            Some(CStr::from_ptr(current.cast())),
                            Self::Empty(ManuallyDrop::into_inner(it)),
                        )
                    }
                }
                _ => return None,
            };
            core::ptr::write(self, next_state);
            res
        }
    }

    pub fn rest(self) -> Rest<I> {
        match self {
            Self::End => Rest::empty(),
            Self::Rest(rest) => rest,
            _ => unreachable!(),
        }
    }
}

// -h --help !
// -V --version !
// -v --validate
// -K --remove-timestamp !
// -k --reset-timestamp !
// -B --bell
// -u --user USER
// -g --group GROUP

fn help() -> ! {
    std::process::exit(0);
}

const VERSION: &str = env!("CARGO_PKG_VERSION");
const NAME: &str = env!("CARGO_BIN_NAME");
fn version() -> ! {
    println!("{} {}", NAME, VERSION);
    std::process::exit(0);
}

pub enum FlagDesc<O> {
    Short(u8, &'static str, fn() -> O),
    Long(&'static str, &'static str, fn() -> O),
    ShortLong(u8, &'static str, &'static str, fn() -> O),
    ShortArg(u8, &'static str, &'static str, fn(&'static CStr) -> O),
    LongArg(
        &'static str,
        &'static str,
        &'static str,
        fn(&'static CStr) -> O,
    ),
    ShortLongArg(
        u8,
        &'static str,
        &'static str,
        &'static str,
        fn(&'static CStr) -> O,
    ),
}

#[derive(Debug)]
pub enum Error {
    UnexpectedValue(RawFlag),
    UnknownFlag(RawFlag),
    ArgumentRequired(RawFlag),
}

pub struct RawFormatter<'a> {
    buf: &'a mut dyn Write,
}

impl RawFormatter<'_> {
    pub fn write(&mut self, buf: &[u8]) -> fmt::Result {
        self.buf.write_all(buf).map_err(|_| fmt::Error)
    }
}

pub trait RawDisplay {
    fn fmt(&self, f: &mut RawFormatter<'_>) -> fmt::Result;
}

impl RawDisplay for Error {
    fn fmt(&self, f: &mut RawFormatter<'_>) -> fmt::Result {
        enum FlagName<'a> {
            Long(&'a [u8]),
            Short(u8),
        }

        impl<'a> RawDisplay for FlagName<'a> {
            fn fmt(&self, f: &mut RawFormatter<'_>) -> fmt::Result {
                match self {
                    Self::Long(n) => {
                        f.write(b"--")?;
                        f.write(n)
                    }
                    Self::Short(c) => f.write(&[b'-', *c]),
                }
            }
        }

        fn name(f: &RawFlag) -> FlagName {
            match f {
                RawFlag::Long(n) | RawFlag::LongWithValue(n, _) => FlagName::Long(n),
                RawFlag::Short(c) => FlagName::Short(*c),
            }
        }

        f.write(NAME.as_bytes())?;
        f.write(b": ")?;

        match self {
            Self::ArgumentRequired(flag) => {
                f.write(b"option '")?;
                RawDisplay::fmt(&name(flag), f)?;
                f.write(b"' requires an argument")
            }
            Self::UnknownFlag(flag) => {
                f.write(b"option '")?;
                RawDisplay::fmt(&name(flag), f)?;
                f.write(b"' doesn't allow an argument")
            }
            Self::UnexpectedValue(flag) => {
                f.write(b"invalid option '")?;
                RawDisplay::fmt(&name(flag), f)?;
                f.write(b"'")
            }
        }
    }
}

const FLAGS: &[FlagDesc<Flag>] = &[
    FlagDesc::ShortLong(b'h', "help", "", || Flag::Help),
    FlagDesc::ShortLong(b'V', "version", "", || Flag::Version),
    FlagDesc::ShortLong(b'v', "validate", "", || Flag::Validate),
    FlagDesc::ShortLong(b'K', "remove-timestamp", "", || Flag::RemoveTimestamp),
    FlagDesc::ShortLong(b'k', "reset-timestamp", "", || Flag::ResetTimestamp),
    FlagDesc::ShortLong(b'B', "bell", "", || Flag::Bell),
    FlagDesc::ShortLongArg(b'u', "user", "USER", "", Flag::User),
    FlagDesc::ShortLongArg(b'g', "group", "GROUP", "", Flag::Group),
];

pub struct FlagIterator<I> {
    parser: Parser<I>,
    flags: &'static [FlagDesc<Flag>],
}

pub enum Flag {
    Help,
    Version,
    Validate,
    RemoveTimestamp,
    ResetTimestamp,
    Bell,
    User(&'static CStr),
    Group(&'static CStr),
}

impl<I: Iterator<Item = *const u8>> FlagIterator<I> {
    pub fn rest(self) -> Rest<I> {
        self.parser.rest()
    }
}

impl<I: Iterator<Item = *const u8>> Iterator for FlagIterator<I> {
    type Item = Result<Flag, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        #[inline(always)]
        fn parse<O, I: Iterator<Item = *const u8>>(
            f: RawFlag,
            parser: &mut Parser<I>,
            flags: &[FlagDesc<O>],
        ) -> Result<O, Error> {
            match f {
                RawFlag::Short(c) => {
                    for flag in flags {
                        match flag {
                            FlagDesc::Short(c2, _, mk) | FlagDesc::ShortLong(c2, _, _, mk)
                                if c == *c2 =>
                            {
                                return Ok(mk());
                            }
                            FlagDesc::ShortArg(c2, _, _, mk)
                            | FlagDesc::ShortLongArg(c2, _, _, _, mk)
                                if c == *c2 =>
                            {
                                return if let Some(val) = parser.pop() {
                                    Ok(mk(val))
                                } else {
                                    Err(Error::ArgumentRequired(f))
                                };
                            }
                            _ => (),
                        }
                    }
                }
                RawFlag::Long(name) => {
                    for flag in flags {
                        match flag {
                            FlagDesc::Long(name2, _, mk) | FlagDesc::ShortLong(_, name2, _, mk)
                                if name == name2.as_bytes() =>
                            {
                                return Ok(mk());
                            }
                            FlagDesc::LongArg(name2, _, _, mk)
                            | FlagDesc::ShortLongArg(_, name2, _, _, mk)
                                if name == name2.as_bytes() =>
                            {
                                return if let Some(val) = parser.pop() {
                                    Ok(mk(val))
                                } else {
                                    Err(Error::ArgumentRequired(f))
                                };
                            }
                            _ => (),
                        }
                    }
                }
                RawFlag::LongWithValue(name, val) => {
                    for flag in flags {
                        match flag {
                            FlagDesc::Long(name2, _, _) | FlagDesc::ShortLong(_, name2, _, _)
                                if name == name2.as_bytes() =>
                            {
                                return Err(Error::UnexpectedValue(f));
                            }
                            FlagDesc::LongArg(name2, _, _, mk)
                            | FlagDesc::ShortLongArg(_, name2, _, _, mk)
                                if name == name2.as_bytes() =>
                            {
                                return Ok(mk(val));
                            }
                            _ => (),
                        }
                    }
                }
            }

            Err(Error::UnknownFlag(f))
        }

        Some(parse(
            self.parser.next_flag()?,
            &mut self.parser,
            self.flags,
        ))
    }
}

pub enum Cli {
    RemoveTimestamp,
    ResetTimestamp,
    Validate {
        reset_timestamp: bool,
        bell: bool,
        user: Option<CString>,
        group: Option<CString>,
        command: Option<&'static CStr>,
    },
    Run {
        bell: bool,
        user: Option<CString>,
        group: Option<CString>,
        command: Vec<&'static CStr>,
    },
}

#[non_exhaustive]
struct StderrInner;

impl std::io::Write for StderrInner {
    #[cfg(target_os = "linux")]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use linux_syscalls::{syscall, Errno, Sysno};

        loop {
            match unsafe { syscall!([ro] Sysno::write, 2, buf.as_ptr(), buf.len()) } {
                Err(Errno::EINTR) => (),
                Err(err) => return Err(err.into()),
                Ok(len) => return Ok(len),
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        loop {
            unsafe {
                let rc = libc::write(2, buf.as_ptr().cast(), buf.len() as _);
                if rc == -1 {
                    if *pezzo::__errno() != libc::EINTR {
                        return Err(std::io::Error::last_os_error());
                    }
                } else {
                    return Ok(rc as usize);
                }
            }
        }
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct Stderr(&'static RefCell<BufWriter<StderrInner>>);

impl std::io::Write for Stderr {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.borrow_mut().flush()
    }
}

static mut STDERR: OnceCell<RefCell<BufWriter<StderrInner>>> = OnceCell::new();
#[allow(clippy::cast_ref_to_mut)]
pub fn stderr() -> Stderr {
    Stderr(unsafe { STDERR.get_or_init(|| RefCell::new(BufWriter::new(StderrInner))) })
}

impl Cli {
    pub fn parse<I: Iterator<Item = *const u8>>(args: I) -> Self {
        let mut parser = FlagIterator {
            parser: Parser::Empty(args),
            flags: FLAGS,
        };

        let mut validate = false;
        let mut remove_timestamp = false;
        let mut reset_timestamp = false;
        let mut bell = false;
        let mut user: Option<&'static CStr> = None;
        let mut group: Option<&'static CStr> = None;

        for flag in parser.by_ref() {
            let flag = match flag {
                Err(err) => {
                    <Error as RawDisplay>::fmt(&err, &mut RawFormatter { buf: &mut stderr() })
                        .unwrap();
                    std::process::exit(1);
                }
                Ok(f) => f,
            };

            match flag {
                Flag::RemoveTimestamp => todo!(),
                Flag::ResetTimestamp => todo!(),
                Flag::Validate => todo!(),
                Flag::Bell => todo!(),
                Flag::User(_) => todo!(),
                Flag::Group(_) => todo!(),
                _ => unreachable!(),
            }
        }

        if remove_timestamp {
            return Cli::RemoveTimestamp;
        }

        let mut rest = parser.rest();
        let command = rest.next();

        if reset_timestamp && !validate && !bell && user.is_none() && group.is_none() {
            if command.is_some() {
                unreachable!()
            }
            return Cli::ResetTimestamp;
        }

        if validate {
            unimplemented!("validate")
        }

        let mut command = if let Some(command) = command {
            vec![command]
        } else {
            unreachable!();
        };
        command.extend(rest);

        Cli::Run {
            bell,
            user: user.map(CString::from),
            group: group.map(CString::from),
            command,
        }
    }
}
