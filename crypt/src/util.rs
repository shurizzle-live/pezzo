const B64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

pub fn to_64(mut buf: &mut [u8], mut u: usize, n: usize) -> &mut [u8] {
    for _ in 0..n {
        buf[0] = B64[u % 64];
        buf = &mut buf[1..];
        u /= 64;
    }
    buf
}
