use core::mem::MaybeUninit;

use sha2::{digest::Output, Digest, Sha512};

use crate::{sha::Key, util::to_64};

pub use crate::{md5::Salt, sha::Rounds};

fn hashmd(ctx: &mut Sha512, md: &Output<Sha512>, n: usize) {
    let (div, rem) = (n / 64, n % 64);
    for _ in 0..div {
        ctx.update(md.as_slice());
    }
    ctx.update(&md[..rem]);
}

pub fn crypt(rounds: Rounds, salt: Salt, key: Key) -> [u8; 86] {
    let key = key.as_ref();

    let md = {
        let mut ctx = Sha512::new();
        ctx.update(key);
        ctx.update(&*salt);
        ctx.update(key);
        ctx.finalize()
    };

    let mut md = {
        let mut ctx = Sha512::new();
        ctx.update(key);
        ctx.update(&*salt);
        hashmd(&mut ctx, &md, key.len());

        let mut i = key.len();
        while i != 0 {
            ctx.update(if (i & 1) != 0 { &*md } else { key });
            i >>= 1;
        }
        ctx.finalize()
    };

    let kmd = {
        let mut ctx = Sha512::new();
        for _ in 0..key.len() {
            ctx.update(key);
        }
        ctx.finalize()
    };

    let smd = {
        let mut ctx = Sha512::new();
        for _ in 0..(16 + md[0]) {
            ctx.update(&*salt);
        }
        ctx.finalize()
    };

    for i in 0..*rounds {
        let mut ctx = Sha512::new();
        let odd = i % 2 != 0;

        if odd {
            hashmd(&mut ctx, &kmd, key.len());
        } else {
            ctx.update(md);
        }
        if i % 3 != 0 {
            ctx.update(&smd[..salt.len()]);
        }
        if i % 7 != 0 {
            hashmd(&mut ctx, &kmd, key.len());
        }
        if odd {
            ctx.update(md);
        } else {
            hashmd(&mut ctx, &kmd, key.len());
        }
        md = ctx.finalize();
    }

    let mut res = MaybeUninit::<[u8; 86]>::uninit();
    let mut buf = unsafe { core::slice::from_raw_parts_mut(res.as_mut_ptr() as *mut u8, 86) };
    const PERM: [[usize; 3]; 21] = [
        [0, 21, 42],
        [22, 43, 1],
        [44, 2, 23],
        [3, 24, 45],
        [25, 46, 4],
        [47, 5, 26],
        [6, 27, 48],
        [28, 49, 7],
        [50, 8, 29],
        [9, 30, 51],
        [31, 52, 10],
        [53, 11, 32],
        [12, 33, 54],
        [34, 55, 13],
        [56, 14, 35],
        [15, 36, 57],
        [37, 58, 16],
        [59, 17, 38],
        [18, 39, 60],
        [40, 61, 19],
        [62, 20, 41],
    ];
    for perm in &PERM {
        buf = to_64(
            buf,
            ((md[perm[0]] as usize) << 16) | ((md[perm[1]] as usize) << 8) | (md[perm[2]] as usize),
            4,
        );
    }
    to_64(buf, md[63] as usize, 2);
    unsafe { res.assume_init() }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test() {
        assert_eq!(
            &crypt(
                unsafe { Rounds::new_unchecked(1234) },
                unsafe { Salt::new_unchecked(b"abc0123456789") },
                unsafe { Key::new_unchecked(b"Xy01@#\x01\x02\x80\x7f\xff\r\n\x81\t !") }
            ),
            b"BCpt8zLrc/RcyuXmCDOE1ALqMXB2MH6n1g891HhFj8.w7LxGv.FTkqq6Vxc/km3Y0jE0j24jY5PIv/oOu6reg1"
        );
    }
}
