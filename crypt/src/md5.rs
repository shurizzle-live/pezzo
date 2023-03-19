use core::{borrow::Borrow, mem::MaybeUninit, ops::Deref};

use crate::util::to_64;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Salt<'a>(&'a [u8]);

impl<'a> Salt<'a> {
    pub const fn new(value: &'a [u8]) -> Option<Self> {
        if value.len() > 8 {
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

impl<'a> Deref for Salt<'a> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.0
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

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key<'a>(&'a [u8]);

impl<'a> Key<'a> {
    pub const fn new(value: &'a [u8]) -> Option<Self> {
        if value.len() > 3_000 {
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

pub fn crypt(salt: Salt, key: Key) -> [u8; 22] {
    let md = {
        let mut ctx = md5::Context::new();
        ctx.consume(&*key);
        ctx.consume(salt.0);
        ctx.consume(&*key);
        ctx.compute().0
    };

    let mut md = {
        let mut ctx = md5::Context::new();
        ctx.consume(&*key);
        ctx.consume(b"$1$");
        ctx.consume(salt.0);
        let (div, rem) = (key.len() / 16, key.len() % 16);
        for _ in 0..div {
            ctx.consume(md.as_slice());
        }
        ctx.consume(&md[..rem]);

        let (zero, k, mut i) = ([0].as_slice(), &key[..1], key.len());
        while i != 0 {
            ctx.consume(if (i & 1) != 0 { zero } else { k });
            i >>= 1;
        }

        ctx.compute().0
    };

    for i in 0..1_000 {
        let mut ctx = md5::Context::new();
        let odd = i % 2 != 0;

        ctx.consume(if odd { &*key } else { md.as_slice() });
        if i % 3 != 0 {
            ctx.consume(salt.0);
        }
        if i % 7 != 0 {
            ctx.consume(&*key);
        }
        ctx.consume(if odd { md.as_slice() } else { &*key });

        md = ctx.compute().0;
    }

    let mut res = MaybeUninit::<[u8; 22]>::uninit();
    let mut buf = unsafe { core::slice::from_raw_parts_mut(res.as_mut_ptr() as *mut u8, 24) };
    const PERM: [[usize; 3]; 5] = [[0, 6, 12], [1, 7, 13], [2, 8, 14], [3, 9, 15], [4, 10, 5]];
    for perm in &PERM {
        buf = to_64(
            buf,
            ((md[perm[0]] as usize) << 16) | ((md[perm[1]] as usize) << 8) | (md[perm[2]] as usize),
            4,
        );
    }
    to_64(buf, md[11] as usize, 2);
    unsafe { res.assume_init() }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test() {
        assert_eq!(
            &super::crypt(
                unsafe { super::Salt::new_unchecked(b"abcd0123") },
                super::Key(b"Xy01@#\x01\x02\x80\x7f\xff\r\n\x81\t !")
            ),
            b"9Qcg8DyviekV3tDGMZynJ1"
        );
    }
}
