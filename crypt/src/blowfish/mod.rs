mod data;

use core::mem::MaybeUninit;
use core::{borrow::Borrow, fmt, ops::Deref};

use data::*;

#[repr(u8)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum Flags {
    A = 2,
    B = 4,
    X = 1,
    Y = 8,
}

impl Flags {
    #[inline]
    pub fn bug(self) -> usize {
        (self as usize) & 1
    }

    #[inline]
    pub fn safety(self) -> u32 {
        ((self as u32) & 2) << 15
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rounds(usize);

impl Rounds {
    pub const fn new(value: usize) -> Option<Self> {
        if value.count_ones() == 1 && value >= 16 && value <= (1 << 19) {
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

    pub fn serialize(&self) -> [u8; 2] {
        let x = self.0.trailing_zeros() as u8;
        [(x / 10) & 1, x % 10]
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
        fmt::Display::fmt(&self.0, f)
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Salt([u8; 22]);

impl Salt {
    #[inline]
    pub fn new<T, E>(value: T) -> Option<Self>
    where
        T: TryInto<Self, Error = E>,
    {
        value.try_into().ok()
    }

    /// # Safety
    /// Value is not validated, it cannot be safe.
    #[inline]
    pub const unsafe fn new_unchecked(value: [u8; 22]) -> Self {
        Self(value)
    }

    pub fn into_words(self) -> [u32; 4] {
        #[inline(always)]
        fn atoi64(src: u8) -> u8 {
            BF_ATOI64[(src - 0x20) as usize]
        }

        let mut src = self
            .0
            .chunks(4)
            .flat_map(|src| {
                let mut buf = [0u8; 3];
                let mut len = 0;
                if let Some(c) = src.first() {
                    let c = atoi64(*c);
                    buf[0] = c << 2;
                    len = 1;

                    if let Some(c) = src.get(1) {
                        let c = atoi64(*c);
                        buf[0] |= (c & 0x30) >> 4;
                        buf[1] = (c & 0x0f) << 4;
                        len = 2;

                        if let Some(c) = src.get(2) {
                            let c = atoi64(*c);
                            buf[1] |= (c & 0x3c) >> 2;
                            buf[2] = c << 6;
                            len = 3;

                            if let Some(c) = src.get(3) {
                                buf[2] |= atoi64(*c);
                            }
                        }
                    }
                }

                buf.into_iter().take(len)
            })
            .take(16);

        let mut dst = MaybeUninit::<[u32; 4]>::uninit();
        let mut i = 0;
        while let (Some(a), Some(b), Some(c), Some(d)) =
            (src.next(), src.next(), src.next(), src.next())
        {
            unsafe {
                dst.assume_init_mut()[i] =
                    ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32)
            };
            i += 1;
        }
        unsafe { dst.assume_init() }
    }
}

impl TryFrom<[u8; 22]> for Salt {
    type Error = ();

    fn try_from(value: [u8; 22]) -> Result<Self, Self::Error> {
        if value.iter().all(|c| BF_ITOA64.contains(c)) {
            Ok(Self(value))
        } else {
            Err(())
        }
    }
}

impl<'a> TryFrom<&'a [u8; 22]> for Salt {
    type Error = ();

    fn try_from(value: &'a [u8; 22]) -> Result<Self, Self::Error> {
        if value.iter().all(|c| BF_ITOA64.contains(c)) {
            Ok(Self(*value))
        } else {
            Err(())
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for Salt {
    type Error = ();

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() == 22 && value.iter().all(|c| BF_ITOA64.contains(c)) {
            let buf = unsafe {
                let mut buf = MaybeUninit::<[u8; 22]>::uninit();
                core::ptr::copy_nonoverlapping(value.as_ptr(), buf.as_mut_ptr() as *mut u8, 22);
                buf.assume_init()
            };
            Ok(Self(buf))
        } else {
            Err(())
        }
    }
}

impl<'a> TryFrom<&'a str> for Salt {
    type Error = ();

    #[inline]
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        value.as_bytes().try_into()
    }
}

// TODO: this code sucks.
fn bf_encode(mut dst: &mut [u8], mut src: &[u8]) {
    #[inline(always)]
    fn pop(x: &mut &[u8]) -> u8 {
        let res = (*x)[0];
        *x = unsafe { (*x).get_unchecked(1..) };
        res
    }

    #[inline(always)]
    fn push(x: &mut &mut [u8], value: u8) {
        (*x)[0] = value;
        *x = unsafe { core::slice::from_raw_parts_mut((*x).as_mut_ptr().add(1), x.len() - 1) };
    }

    while !src.is_empty() {
        let c1 = pop(&mut src);
        push(&mut dst, BF_ITOA64[(c1 >> 2) as usize]);
        let c1 = (c1 & 0x03) << 4;
        if src.is_empty() {
            push(&mut dst, BF_ITOA64[c1 as usize]);
            break;
        }

        let c2 = pop(&mut src);
        let c1 = c1 | (c2 >> 4);
        push(&mut dst, BF_ITOA64[c1 as usize]);
        let c1 = (c2 & 0x0f) << 2;
        if src.is_empty() {
            push(&mut dst, BF_ITOA64[c1 as usize]);
            break;
        }

        let c2 = pop(&mut src);
        let c1 = c1 | (c2 >> 6);
        push(&mut dst, BF_ITOA64[c1 as usize]);
        push(&mut dst, BF_ITOA64[(c2 & 0x3f) as usize])
    }
}

#[inline(always)]
unsafe fn bf_round(ctx: &BFCtx, l: u32, mut r: u32, n: usize) -> u32 {
    let mut tmp1 = l & 0xff;
    let mut tmp2 = (l >> 8) & 0xff;
    let mut tmp3 = (l >> 16) & 0xff;
    let tmp4 = l >> 24;
    tmp1 = ctx.s.S[3][tmp1 as usize];
    tmp2 = ctx.s.S[2][tmp2 as usize];
    tmp3 = ctx.s.S[1][tmp3 as usize];
    tmp3 = tmp3.wrapping_add(ctx.s.S[0][tmp4 as usize]);
    tmp3 ^= tmp2;
    r ^= ctx.s.P[n + 1];
    tmp3 = tmp3.wrapping_add(tmp1);
    r ^ tmp3
}

fn bf_encrypt(ctx: &BFCtx, mut l: u32, mut r: u32, mut buf: &mut [u32]) -> u32 {
    while buf.len() >= 2 {
        unsafe {
            l ^= ctx.s.P[0];

            for i in (0..16).step_by(2) {
                r = bf_round(ctx, l, r, i);
                l = bf_round(ctx, r, l, i + 1);
            }

            let tmp = r;
            r = l;
            l = tmp ^ ctx.s.P[BF_N + 1];
            buf[0] = l;
            buf[1] = r;
            buf = buf.get_unchecked_mut(2..);
        }
    }
    l
}

fn bf_set_key(key: &[u8], expanded: &mut BFKey, initial: &mut BFKey, flags: Flags) {
    let mut ptr = key;
    let (mut sign, mut diff) = (0, 0);

    for i in 0..(BF_N + 2) {
        let mut tmp: [u32; 2] = [0; 2];
        for j in 0..4 {
            let n = ptr.first().copied().unwrap_or(0);
            tmp[0] <<= 8;
            tmp[0] |= n as u32;
            tmp[1] <<= 8;
            tmp[1] |= unsafe { core::mem::transmute::<u8, i8>(n) } as u32;
            if j != 0 {
                sign |= tmp[1] & 0x80;
            }

            if ptr.is_empty() {
                ptr = key;
            } else {
                ptr = unsafe { ptr.get_unchecked(1..) };
            }
        }
        diff |= tmp[0] ^ tmp[1];
        expanded[i] = tmp[flags.bug()];
        initial[i] = unsafe { BF_INIT_STATE.s.P[i] ^ tmp[flags.bug()] };
    }

    diff |= diff >> 16;
    diff &= 0xffff;
    diff += 0xffff;
    sign <<= 9;
    sign &= !diff & flags.safety();
    initial[0] ^= sign;
}

pub fn crypt(flags: Flags, rounds: Rounds, salt: Salt, key: &[u8]) -> [u8; 32] {
    let last_salt_char = *salt.0.last().unwrap();
    let salt = salt.into_words();

    let (mut ctx, expanded_key) = unsafe {
        let mut ctx = MaybeUninit::<BFCtx>::uninit();
        let mut expanded_key = MaybeUninit::<BFKey>::uninit();

        bf_set_key(
            key,
            &mut *expanded_key.as_mut_ptr(),
            &mut (*ctx.as_mut_ptr()).s.P,
            flags,
        );

        core::ptr::copy_nonoverlapping(&BF_INIT_STATE.s.S, &mut (*ctx.as_mut_ptr()).s.S, 1);

        (ctx.assume_init(), expanded_key.assume_init())
    };

    {
        let (mut l, mut r): (u32, u32) = (0, 0);
        let mut state = false;
        for chunk in unsafe { core::slice::from_raw_parts_mut(ctx.PS.as_mut_ptr(), ctx.PS.len()) }
            .chunks_mut(2)
        {
            let offset = (state as usize) << 1;
            state = !state;
            l = bf_encrypt(&ctx, l ^ salt[offset], r ^ salt[offset + 1], chunk);
            r = chunk[1];
        }
    }

    for _ in 0..*rounds {
        #[allow(clippy::needless_range_loop)]
        for i in 0..(BF_N + 2) {
            unsafe { ctx.s.P[i] ^= expanded_key[i] };
        }

        unsafe {
            {
                let tmp = core::slice::from_raw_parts_mut(ctx.PS.as_mut_ptr(), ctx.PS.len());
                bf_encrypt(&ctx, 0, 0, tmp);
            }

            for i in (0..BF_N).step_by(4) {
                ctx.s.P[i] ^= salt[0];
                ctx.s.P[i + 1] ^= salt[1];
                ctx.s.P[i + 2] ^= salt[2];
                ctx.s.P[i + 3] ^= salt[3];
            }
            ctx.s.P[16] ^= salt[0];
            ctx.s.P[17] ^= salt[1];

            {
                let tmp = core::slice::from_raw_parts_mut(ctx.PS.as_mut_ptr(), ctx.PS.len());
                bf_encrypt(&ctx, 0, 0, tmp);
            }
        }
    }

    let mut output = [0; 6];
    for i in (0..6).step_by(2) {
        let mut l = BF_MAGIC_W[i];
        let mut lr = [0, BF_MAGIC_W[i + 1]];

        for _ in 0..64 {
            l = bf_encrypt(&ctx, l, lr[1], &mut lr);
        }

        output[i] = u32::from_be(l);
        output[i + 1] = u32::from_be(lr[1]);
    }

    let mut res = MaybeUninit::<[u8; 32]>::uninit();

    unsafe {
        res.assume_init_mut()[0] =
            BF_ITOA64[(BF_ATOI64[(last_salt_char - 0x20) as usize] & 0x30) as usize];
        bf_encode(
            res.assume_init_mut().get_unchecked_mut(1..),
            core::slice::from_raw_parts(output.as_ptr() as *const u8, 23),
        );
        res.assume_init()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounds() {
        assert_eq!(Rounds::new(2), None);
        assert_eq!(Rounds::new(4), None);
        assert_eq!(Rounds::new(8), None);
        assert_eq!(Rounds::new(16), Some(Rounds(16)));
        assert_eq!(Rounds::new(1024).unwrap().serialize(), [1, 0]);
    }

    #[test]
    fn key() {
        const K: &[u8; 11] = b"\xff\xa334\xff\xff\xff\xa3345";
        let (mut ae, mut ai, mut ye, mut yi): (BFKey, BFKey, BFKey, BFKey) = Default::default();
        bf_set_key(K, &mut ae, &mut ai, Flags::A);
        bf_set_key(K, &mut ye, &mut yi, Flags::B);
        ai[0] ^= 0x10000;
        assert_eq!(ai[0], 0xdb9c59bc);
        assert_eq!(ye[17], 0x33343500);
        assert_eq!(ae, ye);
        assert_eq!(ai, yi);
    }

    #[test]
    fn decode_salt() {
        let salt = Salt::new(b"abcdefghijklmnopqrstuu").unwrap();
        assert_eq!(
            salt.into_words(),
            [1909956482, 413373017, 2812451499, 3000741827]
        );
    }

    #[test]
    fn _crypt() {
        const COUNT: Rounds = unsafe { Rounds::new_unchecked(1) };
        const KEY: &[u8] = b"8b \xd0\xc1\xd2\xcf\xcc\xd8".as_slice();
        const SALT: Salt = unsafe { Salt::new_unchecked(*b"abcdefghijklmnopqrstuu") };

        assert_eq!(
            &crypt(Flags::A, COUNT, SALT, KEY)[1..],
            b"i1D709vfamulimlGcq0qq3UvuUasvEa"
        );
        assert_eq!(
            &crypt(Flags::B, COUNT, SALT, KEY)[1..],
            b"i1D709vfamulimlGcq0qq3UvuUasvEa"
        );
        assert_eq!(
            &crypt(Flags::X, COUNT, SALT, KEY)[1..],
            b"VUrPmXD6q/nVSSp7pNDhCR9071IfIRe"
        );
        assert_eq!(
            &crypt(Flags::Y, COUNT, SALT, KEY)[1..],
            b"i1D709vfamulimlGcq0qq3UvuUasvEa"
        );
    }
}
