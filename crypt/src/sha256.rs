use core::mem::MaybeUninit;

use sha2::{digest::Output, Digest, Sha256};

use crate::{sha::Key, util::to_64};

pub use crate::{md5::Salt, sha::Rounds};

fn hashmd(ctx: &mut Sha256, md: &Output<Sha256>, n: usize) {
    let (div, rem) = (n / 32, n % 32);
    for _ in 0..div {
        ctx.update(md.as_slice());
    }
    ctx.update(&md[..rem]);
}

pub fn crypt(rounds: Rounds, salt: Salt, key: Key) -> [u8; 43] {
    let key = key.as_ref();

    let md = {
        let mut ctx = Sha256::new();
        ctx.update(key);
        ctx.update(&*salt);
        ctx.update(key);
        ctx.finalize()
    };

    let mut md = {
        let mut ctx = Sha256::new();
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
        let mut ctx = Sha256::new();
        for _ in 0..key.len() {
            ctx.update(key);
        }
        ctx.finalize()
    };

    let smd = {
        let mut ctx = Sha256::new();
        for _ in 0..(16 + md[0]) {
            ctx.update(&*salt);
        }
        ctx.finalize()
    };

    for i in 0..*rounds {
        let mut ctx = Sha256::new();
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

    let mut res = MaybeUninit::<[u8; 43]>::uninit();
    let mut buf = unsafe { core::slice::from_raw_parts_mut(res.as_mut_ptr() as *mut u8, 43) };
    const PERM: [[usize; 3]; 10] = [
        [0, 10, 20],
        [21, 1, 11],
        [12, 22, 2],
        [3, 13, 23],
        [24, 4, 14],
        [15, 25, 5],
        [6, 16, 26],
        [27, 7, 17],
        [18, 28, 8],
        [9, 19, 29],
    ];
    for perm in &PERM {
        buf = to_64(
            buf,
            ((md[perm[0]] as usize) << 16) | ((md[perm[1]] as usize) << 8) | (md[perm[2]] as usize),
            4,
        );
    }
    to_64(buf, ((md[31] as usize) << 8) | (md[30] as usize), 3);
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
            b"3VfDjPt05VHFn47C/ojFZ6KRPYrOjj1lLbH.dkF3bZ6"
        );
    }
}
