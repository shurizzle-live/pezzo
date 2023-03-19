#![allow(dead_code)]

use core::{borrow::Borrow, fmt, mem::MaybeUninit, ops::Deref};

const ITOA64: &[u8; 64] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

#[repr(transparent)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rounds(u32);

impl Rounds {
    pub const fn new(value: u32) -> Option<Self> {
        if value >= 1_000 && value <= 9_999_999 {
            Some(Self(value))
        } else {
            None
        }
    }

    /// # Safety
    /// Value is not validated, it cannot be safe.
    #[inline]
    pub const unsafe fn new_unchecked(value: u32) -> Self {
        Self(value)
    }

    #[inline]
    pub fn is_default(&self) -> bool {
        self.0 == 5_000
    }

    fn write(&self, buf: &mut [u8]) -> usize {
        #[inline(always)]
        fn divisor(n: u32) -> u32 {
            const MAXDIGITS: [u8; 33] = [
                1, 1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 9,
                9, 9, 10, 10, 10,
            ];

            const POWERS: [u32; 11] = [
                0, 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000,
            ];

            if n == 0 {
                return 1;
            }
            let bits = u32::BITS - n.leading_zeros();
            unsafe {
                let digits = *MAXDIGITS.get_unchecked(bits as usize);
                *POWERS.get_unchecked(
                    (digits - (n < *POWERS.get_unchecked(digits as usize)) as u8) as usize,
                )
            }
        }

        if self.is_default() {
            return 0;
        }

        let mut n = **self % (9_999_999 + 1);

        buf[0] = b'r';
        buf[1] = b'o';
        buf[2] = b'u';
        buf[3] = b'n';
        buf[4] = b'd';
        buf[5] = b's';
        buf[6] = b'=';
        let mut div = divisor(n);
        let mut len = 7;
        while div != 0 {
            let value = n / div;
            n %= div;
            buf[len] = b"0123456789"[value as usize];
            len += 1;
            div /= 10;
        }
        buf[len] = b'$';

        len + 1
    }
}

impl Default for Rounds {
    #[inline]
    fn default() -> Self {
        Self(5_000)
    }
}

impl Deref for Rounds {
    type Target = u32;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<u32> for Rounds {
    #[inline]
    fn as_ref(&self) -> &u32 {
        self
    }
}

impl Borrow<u32> for Rounds {
    #[inline]
    fn borrow(&self) -> &u32 {
        self
    }
}

impl fmt::Display for Rounds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rounds={}", self.0)
    }
}

#[cfg(not(feature = "generate"))]
pub struct Salt<'a>(&'a [u8]);

#[cfg(feature = "generate")]
pub struct Salt<'a>(Result<&'a [u8], [u8; 16]>);

#[cfg(not(feature = "generate"))]
impl<'a> Salt<'a> {
    pub fn new(value: &'a [u8]) -> Option<Self> {
        if value.len() <= 16 && value.iter().all(|c| ITOA64.contains(c)) {
            Some(Self(value))
        } else {
            None
        }
    }

    /// # Safety
    /// Value is not validated, it cannot be safe.
    #[inline]
    pub const unsafe fn new_unchecked(value: &'a [u8]) -> Self {
        Self(value)
    }
}

#[cfg(feature = "generate")]
impl<'a> Salt<'a> {
    pub const fn new(value: &'a [u8]) -> Option<Self> {
        if value.len() > 16 {
            None
        } else {
            Some(Self(Ok(value)))
        }
    }

    /// # Safety
    /// Value is not validated, it cannot be safe.
    #[inline]
    pub const unsafe fn new_unchecked(value: &'a [u8]) -> Self {
        Self(Ok(value))
    }
}

#[cfg(feature = "generate")]
impl Salt<'static> {
    pub fn generate() -> Self {
        use core::mem::MaybeUninit;
        use rand::{rngs::OsRng, RngCore};

        let mut rng = unsafe {
            let mut x = MaybeUninit::<[u8; 16]>::uninit();
            OsRng.fill_bytes(x.assume_init_mut().as_mut_slice());
            x.assume_init()
        };

        for e in &mut rng {
            *e = ITOA64[(*e as usize) % ITOA64.len()];
        }

        Self(Err(rng))
    }
}

#[cfg(not(feature = "generate"))]
impl<'a> Deref for Salt<'a> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[cfg(feature = "generate")]
impl<'a> Deref for Salt<'a> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        match self.0 {
            Ok(s) => s,
            Err(ref a) => a.as_slice(),
        }
    }
}

impl<'a> AsRef<[u8]> for Salt<'a> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl<'a> Borrow<[u8]> for Salt<'a> {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self
    }
}

pub struct Key<'a>(&'a [u8]);

impl<'a> Key<'a> {
    pub const fn new(value: &'a [u8]) -> Option<Self> {
        if value.len() > 256 {
            None
        } else {
            Some(Self(value))
        }
    }

    /// # Safety
    /// Value is not validated, it cannot be safe.
    #[inline]
    pub const unsafe fn new_unchecked(value: &'a [u8]) -> Self {
        Self(value)
    }
}

impl<'a> Deref for Key<'a> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> AsRef<[u8]> for Key<'a> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl<'a> Borrow<[u8]> for Key<'a> {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self
    }
}

mod __private {
    pub trait ShaBuilder {
        type Output;

        fn build(&self, rounds: super::Rounds, salt: super::Salt, key: super::Key) -> Self::Output;
    }
}
use __private::ShaBuilder;

pub struct Sha256BuilderImpl {}

pub struct Sha512BuilderImpl {}

pub struct Builder<B: ShaBuilder> {
    inner: B,
}

pub struct BuilderWithRounds<B: ShaBuilder> {
    inner: B,
    rounds: Rounds,
}

pub struct BuilderWithSalt<'a, B: ShaBuilder> {
    inner: B,
    salt: Salt<'a>,
}

pub struct BuilderWithRoundSalt<'a, B: ShaBuilder> {
    inner: B,
    rounds: Rounds,
    salt: Salt<'a>,
}

pub type Sha256Builder = Builder<Sha256BuilderImpl>;

pub type Sha512Builder = Builder<Sha512BuilderImpl>;

pub struct Sha256Output(
    [u8; 3 /* $5$ */ + 17 /* rounds */ + 17 /* salt */ + 43],
    usize,
);

pub struct Sha512Output(
    [u8; 3 /* $6$ */ + 17 /* rounds */ + 17 /* salt */ + 86],
    usize,
);

impl ShaBuilder for Sha256BuilderImpl {
    type Output = Sha256Output;

    fn build(&self, rounds: Rounds, salt: Salt, key: Key) -> Self::Output {
        unsafe {
            let mut res = MaybeUninit::<[u8; 80]>::uninit();
            let mut buf = res.assume_init_mut().as_mut_slice();
            buf[0] = b'$';
            buf[1] = b'5';
            buf[2] = b'$';
            buf = buf.get_unchecked_mut(3..);
            let mut len = 3;

            {
                let l = rounds.write(buf);
                len += l;
                buf = buf.get_unchecked_mut(l..);
            }

            {
                core::ptr::copy_nonoverlapping(salt.as_ptr(), buf.as_mut_ptr(), salt.len());
                buf[salt.len()] = b'$';
                let l = salt.len() + 1;
                buf = buf.get_unchecked_mut(l..);
                len += l;
            }

            core::ptr::copy_nonoverlapping(
                crate::sha256::crypt(rounds, salt, key).as_ptr(),
                buf.as_mut_ptr(),
                43,
            );
            len += 43;
            Sha256Output(res.assume_init(), len)
        }
    }
}

impl ShaBuilder for Sha512BuilderImpl {
    type Output = Sha512Output;

    fn build(&self, rounds: self::Rounds, salt: self::Salt, key: self::Key) -> Self::Output {
        unsafe {
            let mut res = MaybeUninit::<[u8; 123]>::uninit();
            let mut buf = res.assume_init_mut().as_mut_slice();
            buf[0] = b'$';
            buf[1] = b'6';
            buf[2] = b'$';
            buf = buf.get_unchecked_mut(3..);
            let mut len = 3;

            {
                let l = rounds.write(buf);
                len += l;
                buf = buf.get_unchecked_mut(l..);
            }

            {
                let mut l = salt.len();
                core::ptr::copy_nonoverlapping(salt.as_ptr(), buf.as_mut_ptr(), l);
                buf[l] = b'$';
                l += 1;
                buf = buf.get_unchecked_mut(l..);
                len += l;
            }

            core::ptr::copy_nonoverlapping(
                crate::sha512::crypt(rounds, salt, key).as_ptr(),
                buf.as_mut_ptr(),
                86,
            );
            len += 86;
            Sha512Output(res.assume_init(), len)
        }
    }
}

impl Builder<Sha256BuilderImpl> {
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: Sha256BuilderImpl {},
        }
    }
}

impl Builder<Sha512BuilderImpl> {
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: Sha512BuilderImpl {},
        }
    }
}

impl Default for Builder<Sha256BuilderImpl> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Builder<Sha512BuilderImpl> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<B: ShaBuilder> Builder<B> {
    #[inline]
    pub fn with_rounds(self, rounds: Rounds) -> BuilderWithRounds<B> {
        BuilderWithRounds {
            inner: self.inner,
            rounds,
        }
    }

    #[inline]
    pub fn with_salt(self, salt: Salt) -> BuilderWithSalt<B> {
        BuilderWithSalt {
            inner: self.inner,
            salt,
        }
    }

    #[cfg(feature = "generate")]
    #[inline]
    pub fn build(self, key: Key) -> B::Output {
        BuilderWithRoundSalt {
            inner: self.inner,
            rounds: Default::default(),
            salt: Salt::generate(),
        }
        .build(key)
    }
}

impl<B: ShaBuilder> BuilderWithRounds<B> {
    #[inline]
    pub fn with_salt(self, salt: Salt) -> BuilderWithRoundSalt<B> {
        BuilderWithRoundSalt {
            inner: self.inner,
            rounds: self.rounds,
            salt,
        }
    }

    #[cfg(feature = "generate")]
    #[inline]
    pub fn build(self, key: Key) -> B::Output {
        BuilderWithRoundSalt {
            inner: self.inner,
            rounds: self.rounds,
            salt: Salt::generate(),
        }
        .build(key)
    }
}

impl<'a, B: ShaBuilder> BuilderWithSalt<'a, B> {
    #[inline]
    pub fn with_rounds(self, rounds: Rounds) -> BuilderWithRoundSalt<'a, B> {
        BuilderWithRoundSalt {
            inner: self.inner,
            rounds,
            salt: self.salt,
        }
    }

    #[inline]
    pub fn build(self, key: Key) -> B::Output {
        BuilderWithRoundSalt {
            inner: self.inner,
            rounds: Rounds::default(),
            salt: self.salt,
        }
        .build(key)
    }
}

impl<'a, B: ShaBuilder> BuilderWithRoundSalt<'a, B> {
    #[inline]
    pub fn build(self, key: Key) -> B::Output {
        self.inner.build(self.rounds, self.salt, key)
    }
}

impl Sha256Output {
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0[..self.1]
    }
}

impl Sha512Output {
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0[..self.1]
    }
}

impl Deref for Sha256Output {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl AsRef<[u8]> for Sha256Output {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl Borrow<[u8]> for Sha256Output {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self
    }
}

impl Deref for Sha512Output {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl AsRef<[u8]> for Sha512Output {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl Borrow<[u8]> for Sha512Output {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self
    }
}
