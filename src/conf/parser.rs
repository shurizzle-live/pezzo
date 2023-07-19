use core::{
    fmt,
    ops::{Range, RangeFrom, RangeTo},
};

use crate::ffi::{CStr, CString};
use alloc_crate::{boxed::Box, rc::Rc, vec::Vec};
use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};
use nom::{
    branch::alt,
    combinator::{all_consuming, cut, map, opt},
    error::{ErrorKind, ParseError},
    multi::{many0, separated_list0, separated_list1},
    sequence::{delimited, pair, preceded, terminated},
    AsBytes, Err, IResult, InputIter, InputLength, Offset, Parser, Slice,
};
use nom_locate::LocatedSpan;

#[derive(Debug, Clone)]
pub enum Origin {
    User(Vec<CString>),
    Group(Vec<CString>),
}

#[derive(Debug, Clone)]
pub enum Target {
    User(Vec<CString>),
    UserGroup(Vec<CString>, Vec<CString>),
}

#[derive(Debug, Clone)]
pub enum EnvTemplatePart {
    Var(Box<CStr>),
    Str(Box<CStr>),
}

#[derive(Debug, Clone)]
pub struct EnvTemplate(Rc<Box<[EnvTemplatePart]>>);

impl EnvTemplate {
    pub fn format(&self) -> Box<CStr> {
        let mut buf = Vec::new();

        for p in &**self.0 {
            match p {
                EnvTemplatePart::Var(ref name) => {
                    if let Some(txt) = crate::env::var(name) {
                        buf.extend_from_slice(txt.to_bytes());
                    }
                }
                EnvTemplatePart::Str(ref txt) => {
                    buf.extend_from_slice(txt.to_bytes());
                }
            }
        }

        unsafe { CString::from_vec_unchecked(buf).into_boxed_c_str() }
    }
}

#[derive(Debug, Clone)]
pub enum Env {
    Unset(Rc<Box<CStr>>),
    Copy(Rc<Box<CStr>>),
    Set(Rc<Box<CStr>>, EnvTemplate),
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub origin: Vec<Origin>,
    pub target: Option<Vec<Target>>,
    pub timeout: Option<u64>,
    pub askpass: Option<bool>,
    pub exe: Option<GlobSet>,
    pub keepenv: Option<bool>,
    pub setenv: Option<Box<[Env]>>,
}

pub trait LocatedError<T: AsBytes>: ParseError<LocatedSpan<T>> {
    fn location_line(&self) -> u32;
    fn column(&self) -> usize;
}

impl<T: AsBytes> LocatedError<T> for nom::error::Error<LocatedSpan<T>> {
    fn location_line(&self) -> u32 {
        self.input.location_line()
    }

    fn column(&self) -> usize {
        self.input.get_column()
    }
}

pub enum Error<T: AsBytes, E: LocatedError<T> = nom::error::Error<LocatedSpan<T>>> {
    Generic(E),
    InvalidGlob(LocatedSpan<T>),
    InvalidExePattern(LocatedSpan<T>),
    RedefinedRule(&'static str, LocatedSpan<T>, LocatedSpan<T>),
    InvalidRule(LocatedSpan<T>),
}

impl<T, E> From<E> for Error<T, E>
where
    T: AsBytes,
    E: LocatedError<T>,
{
    #[inline]
    fn from(value: E) -> Self {
        Error::Generic(value)
    }
}

impl<T: AsBytes> ParseError<LocatedSpan<T>> for Error<T> {
    fn from_error_kind(input: LocatedSpan<T>, kind: ErrorKind) -> Self {
        nom::error::Error::from_error_kind(input, kind).into()
    }

    fn append(_input: LocatedSpan<T>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<T, E> fmt::Debug for Error<T, E>
where
    T: AsBytes,
    E: LocatedError<T> + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Generic(arg0) => f.debug_tuple("Generic").field(arg0).finish(),
            Self::InvalidGlob(_) => f.debug_tuple("InvalidGlob").finish(),
            Self::InvalidExePattern(_) => f.debug_tuple("InvalidExePattern").finish(),
            Self::RedefinedRule(_, _, _) => f.debug_tuple("RedefinedRule").finish(),
            Self::InvalidRule(_) => f.debug_tuple("InvalidRule").finish(),
        }
    }
}

impl<T, E> fmt::Display for Error<T, E>
where
    T: AsBytes,
    E: LocatedError<T>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Generic(e) => write!(
                f,
                "invalid character at {}:{}",
                e.location_line(),
                e.column()
            ),
            Self::InvalidGlob(i) => write!(
                f,
                "invalid glob at {}:{}",
                i.location_line(),
                i.get_column()
            ),
            Self::InvalidExePattern(i) => write!(
                f,
                "invalid exe pattern at {}:{}",
                i.location_line(),
                i.get_column()
            ),
            Self::RedefinedRule(name, previous, current) => write!(
                f,
                "invalid {:?} rule redefinition at {}:{}, previously defined at {}:{}",
                name,
                current.location_line(),
                current.get_column(),
                previous.location_line(),
                previous.get_column()
            ),
            Self::InvalidRule(i) => write!(
                f,
                "invalid rule at {}:{}",
                i.location_line(),
                i.get_column()
            ),
        }
    }
}

impl<T, E> no_std_io::error::Error for Error<T, E>
where
    T: AsBytes,
    E: LocatedError<T> + fmt::Debug,
{
}

fn char<I, E>(c: u8) -> impl Fn(I) -> IResult<I, u8, E>
where
    I: Slice<RangeFrom<usize>> + InputIter<Item = u8>,
    E: ParseError<I>,
{
    move |i: I| match (i).iter_elements().next().map(|t| {
        let b = t == c;
        (&c, b)
    }) {
        Some((c, true)) => Ok((i.slice(1..), *c)),
        _ => Err(Err::Error(E::from_error_kind(i, ErrorKind::Char))),
    }
}

fn is_whitespace(c: u8) -> bool {
    matches!(c, b' ' | b'\n' | b'\t' | b'\r')
}

fn ws0<I, E>(input: I) -> IResult<I, (), E>
where
    I: Slice<Range<usize>> + Slice<RangeFrom<usize>> + InputIter<Item = u8> + InputLength,
    E: ParseError<I>,
{
    for (i, c) in input.iter_indices() {
        if !is_whitespace(c) {
            return Ok((input.slice(i..), ()));
        }
    }
    Ok((input.slice(input.input_len()..), ()))
}

fn comment<I, E>(input: I) -> IResult<I, (), E>
where
    I: Slice<RangeFrom<usize>> + InputIter<Item = u8> + InputLength,
    E: ParseError<I>,
{
    let (input, _) = char(b'#')(input)?;
    for (i, c) in input.iter_indices() {
        if c == b'\n' {
            return Ok((input.slice((i + 1)..), ()));
        }
    }
    Ok((input.slice(input.input_len()..), ()))
}

fn ignored<I, E>(mut input: I) -> IResult<I, (), E>
where
    I: Clone + Slice<Range<usize>> + Slice<RangeFrom<usize>> + InputIter<Item = u8> + InputLength,
    E: ParseError<I>,
{
    let mut prev = 0;

    loop {
        let curr = input.input_len();
        if curr == 0 || curr == prev {
            return Ok((input, ()));
        }

        (input, ()) = ws0::<I, E>(input)
            .map_err(|_| ())
            .expect("ws0 returned an expected error");

        if let Ok((i, ())) = comment::<I, E>(input.clone()) {
            input = i;
        } else {
            return Ok((input, ()));
        }
        prev = curr;
    }
}

fn wrap_ignored<I, O, E, F>(mut f: F) -> impl FnMut(I) -> IResult<I, O, E>
where
    I: Clone + Slice<Range<usize>> + Slice<RangeFrom<usize>> + InputIter<Item = u8> + InputLength,
    E: ParseError<I>,
    F: Parser<I, O, E>,
{
    move |input: I| {
        let (input, ()) = ignored(input)?;
        let (input, res) = f.parse(input)?;
        let (input, ()) = ignored(input)?;
        Ok((input, res))
    }
}

fn fold_separated_list1<I, O, E, F, G, H, R, O2, M>(
    mut sep: M,
    mut f: F,
    mut init: H,
    mut g: G,
) -> impl FnMut(I) -> IResult<I, R, E>
where
    I: Clone + InputLength,
    F: Parser<I, O, E>,
    G: FnMut(R, O) -> R,
    H: FnMut() -> R,
    M: Parser<I, O2, E>,
    E: ParseError<I>,
{
    move |mut i: I| {
        let mut res = init();

        // Parse the first element
        match f.parse(i.clone()) {
            Err(e) => return Err(e),
            Ok((i1, o)) => {
                res = g(res, o);
                i = i1;
            }
        }

        loop {
            let len = i.input_len();
            match sep.parse(i.clone()) {
                Err(Err::Error(_)) => return Ok((i, res)),
                Err(e) => return Err(e),
                Ok((i1, _)) => {
                    // infinite loop check: the parser must always consume
                    if i1.input_len() == len {
                        return Err(Err::Error(E::from_error_kind(i1, ErrorKind::SeparatedList)));
                    }

                    match f.parse(i1.clone()) {
                        Err(Err::Error(_)) => return Ok((i, res)),
                        Err(e) => return Err(e),
                        Ok((i2, o)) => {
                            res = g(res, o);
                            i = i2;
                        }
                    }
                }
            }
        }
    }
}

fn _or_expr<I, O, E, F, G, H, R>(f: F, init: H, g: G) -> impl FnMut(I) -> IResult<I, R, E>
where
    I: Clone
        + InputLength
        + Slice<RangeFrom<usize>>
        + Slice<Range<usize>>
        + Slice<RangeTo<usize>>
        + InputIter<Item = u8>,
    F: Parser<I, O, E>,
    E: ParseError<I>,
    G: FnMut(R, O) -> R,
    H: FnMut() -> R,
{
    fold_separated_list1(wrap_ignored(char(b'|')), f, init, g)
}

fn _or_expr_list<I, O, E, F>(f: F) -> impl FnMut(I) -> IResult<I, Vec<O>, E>
where
    I: Clone
        + InputLength
        + Slice<RangeFrom<usize>>
        + Slice<Range<usize>>
        + Slice<RangeTo<usize>>
        + InputIter<Item = u8>,
    F: Parser<I, O, E>,
    E: ParseError<I>,
{
    _or_expr(f, Vec::new, |mut v, o| {
        v.push(o);
        v
    })
}

fn inner_or_list<I, O, E, F>(mut f: F) -> impl FnMut(I) -> IResult<I, Vec<O>, E>
where
    I: Clone
        + InputLength
        + Slice<RangeFrom<usize>>
        + Slice<Range<usize>>
        + Slice<RangeTo<usize>>
        + InputIter<Item = u8>,
    F: Parser<I, O, E>,
    E: ParseError<I>,
{
    move |input: I| {
        if let Ok((input, _)) = char::<I, E>(b'(')(input.clone()) {
            let (input, res) = wrap_ignored(_or_expr_list(|i| f.parse(i)))(input)?;
            let (input, _) = char(b')')(input)?;
            Ok((input, res))
        } else {
            #[allow(clippy::vec_init_then_push)]
            f.parse(input).map(|(i, o)| {
                let mut v = Vec::with_capacity(1);
                v.push(o);
                (i, v)
            })
        }
    }
}

fn outer_or<I, O, E, F, G, H, R>(
    mut f: F,
    mut init: H,
    mut g: G,
) -> impl FnMut(I) -> IResult<I, R, E>
where
    I: Clone
        + InputLength
        + Slice<RangeFrom<usize>>
        + Slice<Range<usize>>
        + Slice<RangeTo<usize>>
        + InputIter<Item = u8>,
    F: Parser<I, O, E>,
    E: ParseError<I>,
    G: FnMut(R, O) -> R,
    H: FnMut() -> R,
{
    move |input: I| {
        if let Ok((input, _)) = char::<I, E>(b'(')(input.clone()) {
            let (input, res) = wrap_ignored(_or_expr(|i| f.parse(i), &mut init, &mut g))(input)?;
            let (input, _) = char(b')')(input)?;
            Ok((input, res))
        } else {
            _or_expr(|i| f.parse(i), &mut init, &mut g)(input)
        }
    }
}

fn outer_or_list<I, O, E, F>(f: F) -> impl FnMut(I) -> IResult<I, Vec<O>, E>
where
    I: Clone
        + InputLength
        + Slice<RangeFrom<usize>>
        + Slice<Range<usize>>
        + Slice<RangeTo<usize>>
        + InputIter<Item = u8>,
    F: Parser<I, O, E>,
    E: ParseError<I>,
{
    outer_or(f, Vec::new, |mut v, o| {
        v.push(o);
        v
    })
}

fn name<I, E>(input: I) -> IResult<I, CString, E>
where
    I: Slice<RangeFrom<usize>>
        + Slice<RangeTo<usize>>
        + InputIter<Item = u8>
        + InputLength
        + AsBytes,
    E: ParseError<I>,
{
    fn cstr<I: AsBytes>(b: I) -> CString {
        unsafe { CString::from_vec_unchecked(b.as_bytes().to_vec()) }
    }

    let mut it = input.iter_indices();
    match it.next() {
        Some((_, c)) if matches!(c, b'a'..=b'z' | b'A'..=b'Z' | b'_') => (),
        _ => return Err(Err::Error(E::from_error_kind(input, ErrorKind::Char))),
    }

    for (i, c) in it {
        if !matches!(c, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_') {
            return Ok((input.slice(i..), cstr(input.slice(..i))));
        }
    }
    Ok((input.slice(input.input_len()..), cstr(input)))
}

use {name as group, name as user};

fn u64<I, E>(input: I) -> IResult<I, u64, E>
where
    I: InputIter<Item = u8> + Slice<RangeFrom<usize>> + InputLength,
    E: ParseError<I>,
{
    if input.input_len() == 0 {
        return Err(Err::Error(E::from_error_kind(input, ErrorKind::Digit)));
    }

    #[inline(always)]
    fn to_digit(c: u8) -> Option<u64> {
        match c {
            b'0'..=b'9' => Some((c - b'0') as u64),
            _ => None,
        }
    }

    let mut value: u64 = 0;

    for (pos, c) in input.iter_indices() {
        match to_digit(c) {
            None => {
                if pos == 0 {
                    return Err(Err::Error(E::from_error_kind(input, ErrorKind::Digit)));
                } else {
                    return Ok((input.slice(pos..), value));
                }
            }
            Some(d) => match value.checked_mul(10).and_then(|v| v.checked_add(d)) {
                None => return Err(Err::Error(E::from_error_kind(input, ErrorKind::Digit))),
                Some(v) => value = v,
            },
        }
    }

    Ok((input.slice(input.input_len()..), value))
}

fn tag<T: AsRef<[u8]>, I, E>(needle: T) -> impl FnMut(I) -> IResult<I, (), E>
where
    I: InputIter<Item = u8> + Slice<RangeFrom<usize>>,
    E: ParseError<I>,
{
    move |input: I| {
        let needle = needle.as_ref();
        let mut it = input.iter_elements();
        for c in needle.iter().copied() {
            match it.next() {
                Some(c2) if c == c2 => (),
                _ => return Err(Err::Error(E::from_error_kind(input, ErrorKind::Tag))),
            }
        }

        Ok((input.slice(needle.len()..), ()))
    }
}

fn bool<I, E>(input: I) -> IResult<I, bool, E>
where
    I: Clone + InputIter<Item = u8> + Slice<RangeFrom<usize>>,
    E: ParseError<I>,
{
    alt((
        map(tag::<&'static [u8], I, E>(b"true"), |_| true),
        map(tag::<&'static [u8], I, E>(b"false"), |_| false),
    ))(input)
}

fn origin_value<I, E>(input: I) -> IResult<I, Vec<Origin>, E>
where
    I: Slice<RangeFrom<usize>>
        + Slice<Range<usize>>
        + Slice<RangeTo<usize>>
        + InputIter<Item = u8>
        + InputLength
        + Clone
        + AsBytes,
    E: ParseError<I>,
{
    fn origin_comp<I, E>(input: I) -> IResult<I, Origin, E>
    where
        I: Slice<RangeFrom<usize>>
            + Slice<Range<usize>>
            + Slice<RangeTo<usize>>
            + InputIter<Item = u8>
            + InputLength
            + Clone
            + AsBytes,
        E: ParseError<I>,
    {
        match char::<I, E>(b':')(input.clone()) {
            Ok((input, _)) => {
                let (input, _) = ignored(input)?;
                map(inner_or_list(group), Origin::Group)(input)
            }
            Err(_) => map(inner_or_list(user), Origin::User)(input),
        }
    }

    outer_or_list(origin_comp)(input)
}

fn target_value<I, E>(input: I) -> IResult<I, Vec<Target>, E>
where
    I: Slice<RangeFrom<usize>>
        + Slice<Range<usize>>
        + Slice<RangeTo<usize>>
        + InputIter<Item = u8>
        + InputLength
        + Clone
        + AsBytes,
    E: ParseError<I>,
{
    fn target_comp<I, E>(input: I) -> IResult<I, Target, E>
    where
        I: Slice<RangeFrom<usize>>
            + Slice<Range<usize>>
            + Slice<RangeTo<usize>>
            + InputIter<Item = u8>
            + InputLength
            + Clone
            + AsBytes,
        E: ParseError<I>,
    {
        let (input, users) = inner_or_list(user)(input)?;

        match wrap_ignored(char::<I, E>(b':'))(input.clone()) {
            Ok((input, _)) => {
                let (input, groups) = inner_or_list(group)(input)?;
                Ok((input, Target::UserGroup(users, groups)))
            }
            Err(_) => Ok((input, Target::User(users))),
        }
    }

    outer_or_list(target_comp)(input)
}

fn env_value<I, E>(input: I) -> IResult<I, Box<[Env]>, E>
where
    I: Slice<Range<usize>>
        + Slice<RangeFrom<usize>>
        + Slice<RangeTo<usize>>
        + InputIter<Item = u8>
        + InputLength
        + AsBytes
        + Clone,
    E: ParseError<I>,
{
    use name as env_name;

    fn env_template<I, E>(input: I) -> IResult<I, EnvTemplate, E>
    where
        I: Slice<RangeFrom<usize>>
            + Slice<RangeTo<usize>>
            + InputIter<Item = u8>
            + InputLength
            + Clone
            + AsBytes,
        E: ParseError<I>,
    {
        fn template_part_str<I, E>(input: I) -> IResult<I, EnvTemplatePart, E>
        where
            I: Slice<RangeFrom<usize>> + InputIter<Item = u8> + InputLength,
            E: ParseError<I>,
        {
            let mut buf = Vec::new();
            let mut escaped = false;

            for (i, c) in input.iter_indices() {
                if escaped {
                    match c {
                        b'\\' | b'$' | b'"' => {
                            buf.push(c);
                        }
                        _ => {
                            return Err(Err::Error(E::from_error_kind(
                                input.slice(i..),
                                ErrorKind::Char,
                            )))
                        }
                    }
                } else {
                    match c {
                        b'\\' => {
                            escaped = true;
                        }
                        b'$' | b'"' => {
                            return if buf.is_empty() {
                                Err(Err::Error(E::from_error_kind(
                                    input.slice(i..),
                                    ErrorKind::Char,
                                )))
                            } else {
                                let res = EnvTemplatePart::Str(unsafe {
                                    CString::from_vec_unchecked(buf).into_boxed_c_str()
                                });
                                Ok((input.slice(i..), res))
                            };
                        }
                        b'\0' => {
                            return Err(Err::Error(E::from_error_kind(
                                input.slice(i..),
                                ErrorKind::Char,
                            )));
                        }
                        _ => {
                            buf.push(c);
                        }
                    }
                }
            }

            let input = input.slice(input.input_len()..);
            if escaped || buf.is_empty() {
                Err(Err::Error(E::from_error_kind(input, ErrorKind::Char)))
            } else {
                let res = EnvTemplatePart::Str(unsafe {
                    CString::from_vec_unchecked(buf).into_boxed_c_str()
                });
                Ok((input, res))
            }
        }

        fn template_part_var<I, E>(input: I) -> IResult<I, EnvTemplatePart, E>
        where
            I: Slice<RangeFrom<usize>>
                + Slice<RangeTo<usize>>
                + InputIter<Item = u8>
                + InputLength
                + AsBytes
                + Clone,
            E: ParseError<I>,
        {
            let (input, _) = char::<I, E>(b'$')(input)?;
            let (input, braced) = match char::<I, E>(b'{')(input.clone()) {
                Ok((input, _)) => (input, true),
                Err(_) => (input, false),
            };

            let (input, name) = name(input)?;

            let input = if braced {
                char::<I, E>(b'}')(input)?.0
            } else {
                input
            };

            Ok((input, EnvTemplatePart::Var(name.into_boxed_c_str())))
        }

        let (input, parts) = delimited(
            char::<I, E>(b'"'),
            many0(alt((template_part_str, template_part_var))),
            char::<I, E>(b'"'),
        )(input)?;
        let res = EnvTemplate(Rc::new(parts.into_boxed_slice()));

        Ok((input, res))
    }

    fn env<I, E>(input: I) -> IResult<I, Env, E>
    where
        I: Slice<RangeFrom<usize>>
            + Slice<RangeTo<usize>>
            + InputIter<Item = u8>
            + InputLength
            + AsBytes
            + Clone,
        E: ParseError<I>,
    {
        alt((
            map(preceded(char(b'-'), env_name), |name| {
                Env::Unset(Rc::new(name.into_boxed_c_str()))
            }),
            map(
                pair(terminated(env_name, char(b'=')), env_template),
                |(name, val)| Env::Set(Rc::new(name.into_boxed_c_str()), val),
            ),
            map(env_name, |name| Env::Copy(Rc::new(name.into_boxed_c_str()))),
        ))(input)
    }

    let (input, _) = char(b'{')(input)?;
    let (input, ()) = ignored(input)?;

    let (input, res) = separated_list1(wrap_ignored(char(b',')), env)(input)?;

    let (input, _) = wrap_ignored(opt(char(b',')))(input)?;
    let (input, _) = char(b'}')(input)?;

    Ok((input, res.into_boxed_slice()))
}

fn exe_value<I>(input: LocatedSpan<I>) -> IResult<LocatedSpan<I>, GlobSet, Error<I>>
where
    I: Slice<Range<usize>>
        + Slice<RangeFrom<usize>>
        + Slice<RangeTo<usize>>
        + InputIter<Item = u8>
        + InputLength
        + Offset
        + AsBytes
        + Clone,
{
    fn glob<I>(input: LocatedSpan<I>) -> IResult<LocatedSpan<I>, Glob, Error<I>>
    where
        I: Slice<Range<usize>>
            + Slice<RangeFrom<usize>>
            + Slice<RangeTo<usize>>
            + InputIter<Item = u8>
            + InputLength
            + Offset
            + AsBytes
            + Clone,
    {
        fn make<I: AsBytes>(
            start: LocatedSpan<I>,
            current: LocatedSpan<I>,
            buf: Vec<u8>,
        ) -> IResult<LocatedSpan<I>, Glob, Error<I>> {
            let s = match core::str::from_utf8(buf.as_slice()) {
                Ok(s) => s,
                Err(_) => return Err(Err::Error(Error::InvalidGlob(start))),
            };
            match GlobBuilder::new(s).literal_separator(true).build() {
                Ok(g) => Ok((current, g)),
                Err(_) => Err(Err::Error(Error::InvalidGlob(start))),
            }
        }

        let start = input.clone();
        let mut buf = Vec::new();
        let mut escaped = false;

        for (i, c) in input.iter_indices() {
            if escaped {
                match c {
                    b'\\' | b' ' | b'|' | b';' | b':' => {
                        buf.push(c);
                    }
                    _ => {
                        return Err(Err::Error(Error::from_error_kind(
                            input.slice(i..),
                            ErrorKind::Char,
                        )));
                    }
                }
            } else {
                match c {
                    b'\\' => {
                        escaped = true;
                    }
                    b' ' | b'|' | b';' | b':' => {
                        return if buf.is_empty() {
                            Err(Err::Error(Error::from_error_kind(
                                input.slice(i..),
                                ErrorKind::Char,
                            )))
                        } else {
                            make(start, input.slice(i..), buf)
                        };
                    }
                    b'\0' => {
                        return Err(Err::Error(Error::from_error_kind(
                            input.slice(i..),
                            ErrorKind::Char,
                        )));
                    }
                    _ => {
                        buf.push(c);
                    }
                }
            }
        }

        let input = input.slice(input.input_len()..);
        if escaped || buf.is_empty() {
            Err(Err::Error(Error::from_error_kind(input, ErrorKind::Char)))
        } else {
            make(start, input, buf)
        }
    }

    let start = input.clone();
    let (input, builder) = outer_or(glob, GlobSetBuilder::new, |mut b, o| {
        b.add(o);
        b
    })(input)?;
    match builder.build() {
        Ok(set) => Ok((input, set)),
        Err(_) => Err(Err::Error(Error::InvalidExePattern(start))),
    }
}

pub struct RuleBuilder<I> {
    start: LocatedSpan<I>,
    origin: Option<(LocatedSpan<I>, Vec<Origin>)>,
    target: Option<(LocatedSpan<I>, Vec<Target>)>,
    exe: Option<(LocatedSpan<I>, GlobSet)>,
    timeout: Option<(LocatedSpan<I>, u64)>,
    askpass: Option<(LocatedSpan<I>, bool)>,
    keepenv: Option<(LocatedSpan<I>, bool)>,
    setenv: Option<(LocatedSpan<I>, Box<[Env]>)>,
}

impl<I: AsBytes> RuleBuilder<I> {
    pub fn new(start: LocatedSpan<I>) -> Self {
        Self {
            start,
            origin: None,
            target: None,
            exe: None,
            timeout: None,
            askpass: None,
            keepenv: None,
            setenv: None,
        }
    }

    pub fn origin(mut self, span: LocatedSpan<I>, origin: Vec<Origin>) -> Result<Self, Error<I>> {
        if let Some((previous, _)) = self.origin.take() {
            Err(Error::RedefinedRule("origin", previous, span))
        } else {
            self.origin = Some((span, origin));
            Ok(self)
        }
    }

    pub fn target(mut self, span: LocatedSpan<I>, target: Vec<Target>) -> Result<Self, Error<I>> {
        if let Some((previous, _)) = self.target.take() {
            Err(Error::RedefinedRule("target", previous, span))
        } else {
            self.target = Some((span, target));
            Ok(self)
        }
    }

    pub fn exe(mut self, span: LocatedSpan<I>, exe: GlobSet) -> Result<Self, Error<I>> {
        if let Some((previous, _)) = self.exe.take() {
            Err(Error::RedefinedRule("exe", previous, span))
        } else {
            self.exe = Some((span, exe));
            Ok(self)
        }
    }

    pub fn timeout(mut self, span: LocatedSpan<I>, timeout: u64) -> Result<Self, Error<I>> {
        if let Some((previous, _)) = self.timeout.take() {
            Err(Error::RedefinedRule("timeout", previous, span))
        } else {
            self.timeout = Some((span, timeout));
            Ok(self)
        }
    }

    pub fn askpass(mut self, span: LocatedSpan<I>, askpass: bool) -> Result<Self, Error<I>> {
        if let Some((previous, _)) = self.askpass.take() {
            Err(Error::RedefinedRule("askpass", previous, span))
        } else {
            self.askpass = Some((span, askpass));
            Ok(self)
        }
    }

    pub fn keepenv(mut self, span: LocatedSpan<I>, keepenv: bool) -> Result<Self, Error<I>> {
        if let Some((previous, _)) = self.keepenv.take() {
            Err(Error::RedefinedRule("keepenv", previous, span))
        } else {
            self.keepenv = Some((span, keepenv));
            Ok(self)
        }
    }

    pub fn setenv(mut self, span: LocatedSpan<I>, setenv: Box<[Env]>) -> Result<Self, Error<I>> {
        if let Some((previous, _)) = self.setenv.take() {
            Err(Error::RedefinedRule("setenv", previous, span))
        } else {
            self.setenv = Some((span, setenv));
            Ok(self)
        }
    }

    pub fn build(self) -> Result<Rule, Err<Error<I>>> {
        let Self {
            start,
            origin,
            target,
            exe,
            timeout,
            askpass,
            keepenv,
            setenv,
        } = self;
        if let Some((_, origin)) = origin {
            Ok(Rule {
                origin,
                target: target.map(|(_, x)| x),
                exe: exe.map(|(_, x)| x),
                timeout: timeout.map(|(_, x)| x),
                askpass: askpass.map(|(_, x)| x),
                keepenv: keepenv.map(|(_, x)| x),
                setenv: setenv.map(|(_, x)| x),
            })
        } else {
            Err(Err::Failure(Error::InvalidRule(start)))
        }
    }
}

fn statement<I, O, E, F>(name: &'static str, mut f: F) -> impl FnMut(I) -> IResult<I, O, E>
where
    I: InputLength + Slice<RangeFrom<usize>> + Slice<Range<usize>> + InputIter<Item = u8> + Clone,
    F: Parser<I, O, E>,
    E: ParseError<I>,
{
    let name = name.as_bytes();
    move |mut input: I| {
        input = tag(name)(input)?.0;

        (input, _) = wrap_ignored(char::<I, E>(b'='))(input)?;

        let (input, res) = cut(|i| f.parse(i))(input)?;

        let (input, _) = cut(ignored)(input)?;
        let (input, _) = cut(char::<I, E>(b';'))(input)?;

        Ok((input, res))
    }
}

fn rule<I>(mut input: LocatedSpan<I>) -> IResult<LocatedSpan<I>, Rule, Error<I>>
where
    I: InputLength
        + Slice<RangeTo<usize>>
        + Slice<RangeFrom<usize>>
        + Slice<Range<usize>>
        + InputIter<Item = u8>
        + AsBytes
        + Offset
        + Clone,
{
    enum E<I: AsBytes> {
        Failure(Error<I>),
        Error(LocatedSpan<I>, RuleBuilder<I>, Error<I>),
    }

    fn parse_statement<I>(
        builder: RuleBuilder<I>,
        input: LocatedSpan<I>,
    ) -> Result<(LocatedSpan<I>, RuleBuilder<I>), E<I>>
    where
        I: InputLength
            + Slice<RangeTo<usize>>
            + Slice<RangeFrom<usize>>
            + Slice<Range<usize>>
            + InputIter<Item = u8>
            + AsBytes
            + Offset
            + Clone,
    {
        macro_rules! try_parse {
            ($name:ident, $parser:expr) => {
                match statement(stringify!($name), $parser)(input.clone()) {
                    Err(Err::Error(_)) => (),
                    Err(Err::Incomplete(_)) => {
                        return Err(E::Failure(Error::from_error_kind(input, ErrorKind::Eof)));
                    }
                    Err(Err::Failure(err)) => return Err(E::Failure(err)),
                    Ok((i, value)) => {
                        return match builder.$name(input, value) {
                            Err(err) => Err(E::Failure(err)),
                            Ok(builder) => Ok((i, builder)),
                        };
                    }
                }
            };
        }

        try_parse!(target, target_value);
        try_parse!(origin, origin_value);
        try_parse!(exe, exe_value);
        try_parse!(timeout, u64);
        try_parse!(askpass, bool);
        try_parse!(keepenv, bool);
        try_parse!(setenv, env_value);

        Err(E::Error(input.clone(), builder, Error::InvalidRule(input)))
    }

    let start = input.clone();
    input = tag("rule")(input)?.0;
    input = wrap_ignored(char::<LocatedSpan<I>, Error<I>>(b'{'))(input)?.0;

    let (mut input, mut builder) = match parse_statement(RuleBuilder::new(start), input) {
        Err(E::Error(_, _, err)) => return Err(Err::Failure(err)),
        Err(E::Failure(err)) => return Err(Err::Failure(err)),
        Ok((i, b)) => (i, b),
    };

    loop {
        input = cut(ignored::<LocatedSpan<I>, Error<I>>)(input)?.0;
        match parse_statement(builder, input) {
            Err(E::Error(i, b, _)) => {
                input = i;
                builder = b;
                break;
            }
            Err(E::Failure(err)) => return Err(Err::Failure(err)),
            Ok((i, b)) => {
                input = i;
                builder = b;
            }
        }
    }

    let rule = builder.build()?;

    let (input, ()) = ignored(input)?;
    let (input, _) = char::<LocatedSpan<I>, Error<I>>(b'}')(input)?;

    Ok((input, rule))
}

fn body<I>(input: LocatedSpan<I>) -> IResult<LocatedSpan<I>, Vec<Rule>, Error<I>>
where
    I: InputLength
        + Slice<RangeTo<usize>>
        + Slice<RangeFrom<usize>>
        + Slice<Range<usize>>
        + InputIter<Item = u8>
        + AsBytes
        + Offset
        + Clone,
{
    wrap_ignored(separated_list0(ignored, rule))(input)
}

pub fn parse(input: &[u8]) -> Result<Vec<Rule>, Error<&[u8]>> {
    let input = LocatedSpan::new(input);
    match all_consuming(body)(input) {
        Err(Err::Error(err)) => Err(err),
        Err(Err::Failure(err)) => Err(err),
        Err(Err::Incomplete(_)) => Err(Error::from_error_kind(input, ErrorKind::Eof)),
        Ok((_, res)) => Ok(res),
    }
}
