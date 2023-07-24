mod parser;

use core::fmt;

pub use self::parser::{Env, Origin, Rule, Target};
pub use globset::GlobSet;
use nom::AsBytes;

use alloc_crate::vec::Vec;

use self::parser::LocatedError;

#[derive(Debug)]
pub struct Rules(Vec<Rule>);

impl Rules {
    #[inline]
    pub fn rules(&self) -> &[Rule] {
        &self.0
    }
}

pub enum Error {
    InvalidCharacter(usize, usize),
    InvalidGlob(usize, usize),
    InvalidExePattern(usize, usize),
    RedefinedRule(&'static str, usize, usize, usize, usize),
    InvalidRule(usize, usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;

        match self {
            InvalidCharacter(l, c) => write!(f, "invalid character at {}:{}", l, c),
            InvalidGlob(l, c) => write!(f, "invalid glob at {}:{}", l, c),
            InvalidExePattern(l, c) => write!(f, "invalid exe pattern at {}:{}", l, c),
            RedefinedRule(name, l1, c1, l2, c2) => write!(
                f,
                "invalid {:?} rule redefinition at {}:{}, previously defined at {}:{}",
                name, l1, c1, l2, c2
            ),
            InvalidRule(l, c) => write!(f, "invalid rule at {}:{}", l, c),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCharacter(l, c) => write!(f, "InvalidCharacter(\"{}:{}\")", l, c),
            Self::InvalidGlob(l, c) => write!(f, "InvalidGlob(\"{}:{}\")", l, c),
            Self::InvalidExePattern(l, c) => write!(f, "InvalidExePattern(\"{}:{}\")", l, c),
            Self::RedefinedRule(name, l1, c1, l2, c2) => write!(
                f,
                "RedefinedRule({:?}, \"{}:{}\", \"{}:{}\")",
                name, l1, c1, l2, c2
            ),
            Self::InvalidRule(l, c) => write!(f, "InvalidRule(\"{}:{}\")", l, c),
        }
    }
}

impl<T, E> From<parser::Error<T, E>> for Error
where
    T: AsBytes,
    E: LocatedError<T>,
{
    fn from(value: parser::Error<T, E>) -> Self {
        use parser::Error::*;

        match value {
            Generic(i) => Self::InvalidCharacter(i.location_line() as usize, i.column()),
            InvalidGlob(i) => Self::InvalidGlob(i.location_line() as usize, i.get_column()),
            InvalidExePattern(i) => {
                Self::InvalidExePattern(i.location_line() as usize, i.get_column())
            }
            RedefinedRule(name, i1, i2) => Self::RedefinedRule(
                name,
                i1.location_line() as usize,
                i1.get_column(),
                i2.location_line() as usize,
                i2.get_column(),
            ),
            InvalidRule(i) => Self::InvalidRule(i.location_line() as usize, i.get_column()),
        }
    }
}

impl sstd::error::Error for Error {}

#[inline]
pub fn parse<B: AsRef<[u8]>>(buf: B) -> core::result::Result<Rules, Error> {
    let buf = buf.as_ref();
    Ok(Rules(parser::parse(buf)?))
}
