pub fn verify<B1: AsRef<[u8]>, B2: AsRef<[u8]>>(hash: B1, key: B2) -> bool {
    _verify(hash, key).unwrap_or(false)
}

#[inline(always)]
fn _verify<B1: AsRef<[u8]>, B2: AsRef<[u8]>>(hash: B1, key: B2) -> Option<bool> {
    fn parse_sha(hash: &[u8]) -> Option<(Option<u32>, &[u8], &[u8])> {
        let hash = hash.strip_prefix(b"$")?;

        let (rounds, hash) = if let Some(hash) = hash.strip_prefix(b"rounds=") {
            use atoi::FromRadix10;

            let (rounds, len) = u32::from_radix_10(hash);
            if len == 0 {
                return None;
            }
            let hash = unsafe { hash.get_unchecked(len..) }.strip_prefix(b"$")?;

            (Some(rounds), hash)
        } else {
            (None, hash)
        };
        let i = memchr::memchr(b'$', hash)?;
        let salt = hash.get(..i)?;
        let hash = hash.get((i + 1)..)?;
        Some((rounds, salt, hash))
    }

    let hash = hash.as_ref();

    let hash = hash.strip_prefix(b"$")?;

    let (c, hash) = hash.split_at(1);
    match c.first()? {
        b'1' => {
            let hash = hash.strip_prefix(b"$")?;
            let i = memchr::memchr(b'$', hash)?;
            let salt = crate::md5::Salt::new(hash.get(..i)?)?;
            let hash = hash.get((i + 1)..)?;
            let key = crate::md5::Key::new(key.as_ref())?;
            Some(crate::md5::crypt(salt, key).as_slice() == hash)
        }
        b'2' => {
            let (c, hash) = hash.split_at(1);
            let flags = match c.first()? {
                b'a' => crate::blowfish::Flags::A,
                b'b' => crate::blowfish::Flags::B,
                b'x' => crate::blowfish::Flags::X,
                b'y' => crate::blowfish::Flags::Y,
                _ => return None,
            };
            let hash = hash.strip_prefix(b"$")?;
            let (rounds, hash) = {
                let (rounds, hash) = hash.split_at(2);
                let hash = hash.strip_prefix(b"$")?;
                let (r0, r1) = (
                    rounds.first()?.checked_sub(b'0')?,
                    rounds.get(1)?.checked_sub(b'0')?,
                );
                if r0 > 1 || r1 > 9 {
                    return None;
                }
                let rounds = 1 << (r0 * 10 + r1);
                (crate::blowfish::Rounds::new(rounds)?, hash)
            };
            let salt = crate::blowfish::Salt::new(hash.get(..22)?)?;
            let hash = hash.get(21..)?;
            let key = key.as_ref();

            Some(crate::blowfish::crypt(flags, rounds, salt, key).as_slice() == hash)
        }
        b'5' => {
            let (rounds, salt, hash) = parse_sha(hash)?;
            let rounds = rounds
                .and_then(crate::sha256::Rounds::new)
                .unwrap_or(crate::sha256::Rounds::default());
            let salt = crate::sha256::Salt::new(salt)?;
            let key = crate::sha256::Key::new(key.as_ref())?;

            Some(crate::sha256::crypt(rounds, salt, key).as_slice() == hash)
        }
        b'6' => {
            let (rounds, salt, hash) = parse_sha(hash)?;
            let rounds = rounds
                .and_then(crate::sha512::Rounds::new)
                .unwrap_or(crate::sha512::Rounds::default());
            let salt = crate::sha512::Salt::new(salt)?;
            let key = crate::sha512::Key::new(key.as_ref())?;

            Some(crate::sha512::crypt(rounds, salt, key).as_slice() == hash)
        }
        _ => Some(false),
    }
}
