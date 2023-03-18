#![allow(dead_code)]

use core::{borrow::Borrow, fmt, ops::Deref};

#[repr(transparent)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rounds(usize);

impl Rounds {
    pub const fn new(value: usize) -> Option<Self> {
        if value >= 1_000 && value <= 9_999_999 {
            Some(Self(value))
        } else {
            None
        }
    }

    /// # Safety
    /// Value is not validated, it cannot be safe.
    #[inline]
    pub const unsafe fn new_unchecked(value: usize) -> Self {
        Self(value)
    }

    #[inline]
    pub fn is_default(&self) -> bool {
        self.0 == 5_000
    }
}

impl Default for Rounds {
    #[inline]
    fn default() -> Self {
        Self(5_000)
    }
}

impl Deref for Rounds {
    type Target = usize;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<usize> for Rounds {
    #[inline]
    fn as_ref(&self) -> &usize {
        self
    }
}

impl Borrow<usize> for Rounds {
    #[inline]
    fn borrow(&self) -> &usize {
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
    pub const fn new(value: &'a [u8]) -> Option<Self> {
        if value.len() > 16 {
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

        const ITOA64: &[u8; 64] =
            b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

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
    pub trait ShaBuilder {}
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

pub struct BuilderComplete<'a, 'b, B: ShaBuilder> {
    inner: B,
    rounds: Rounds,
    salt: Salt<'a>,
    key: Key<'b>,
}

pub type Sha256Builder = Builder<Sha256BuilderImpl>;

pub type Sha512Builder = Builder<Sha512BuilderImpl>;

impl ShaBuilder for Sha256BuilderImpl {}

impl ShaBuilder for Sha512BuilderImpl {}

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
    pub fn build(self, key: Key) -> BuilderComplete<B> {
        BuilderComplete {
            inner: self.inner,
            rounds: Default::default(),
            salt: Salt::generate(),
            key,
        }
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
    pub fn build(self, key: Key) -> BuilderComplete<B> {
        BuilderComplete {
            inner: self.inner,
            rounds: self.rounds,
            salt: Salt::generate(),
            key,
        }
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
    pub fn build<'b>(self, key: Key<'b>) -> BuilderComplete<'a, 'b, B> {
        BuilderComplete {
            inner: self.inner,
            rounds: Default::default(),
            salt: self.salt,
            key,
        }
    }
}

impl<'a, B: ShaBuilder> BuilderWithRoundSalt<'a, B> {
    #[inline]
    pub fn build<'b>(self, key: Key<'b>) -> BuilderComplete<'a, 'b, B> {
        BuilderComplete {
            inner: self.inner,
            rounds: self.rounds,
            salt: self.salt,
            key,
        }
    }
}

impl<'a, 'b, B: ShaBuilder> BuilderComplete<'a, 'b, B> {
    // TODO:
}
