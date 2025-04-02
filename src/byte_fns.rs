use crate::Q;
use crate::{Z,S};

pub(crate) fn compress(d:u8, u:&[Z;256]) -> [Z;256] {
    let m:u32 = 1<<d;
    let q = Q as u32;
    // round(i/j) = floor((i+floor(j/2))/j)
    // compute round((2^d *x)/q)
    core::array::from_fn(|i| Z((((m*(u[i].0 as u32)+q/2)/q)%m) as u16))
}

pub(crate) fn decompress(d:u8, u:&[Z;256]) -> [Z;256] {
    let m: u32 = 1<<d;
    // round(i/j) = floor((i+floor(j/2))/j)
    // compute round((q*y)/2^d) -> round((Q*u[i])/m)
    core::array::from_fn(|i| Z((((Q as u32)*(u[i].0 as u32)+m/2)/m) as u16))
}

pub(crate) fn byte_encode<const D_32:usize>(d:u8, f:&[Z;256]) -> [S;D_32] {
    let mut b = core::array::from_fn(|_| S(0));
    let mut byte_idx: usize = 0;
    let mut bit_idx: u8 = 0;
    for e in f {
        let mut a:&Z = e;
        let mut a1:Z;
        for _ in 0..d {
            // we convert the result directly to bytes
            // no need to call bits_to_bytes
            b[byte_idx] |= ((a.clone().rem(2)))<<bit_idx;
            a1 = (a-&(a.clone().rem(2)))/2;
            a = &a1;

            bit_idx += 1;
            if bit_idx == 8 {bit_idx = 0; byte_idx += 1;}
        }
    }
    b
}

pub(crate) fn byte_decode(d:u8, b:&[S]) -> [Z;256] {
    // compute m
    let m: u16 = {if d==12 {Q} else {1<<d}};
    
    let mut byte_idx: usize = 0;
    let mut bit_idx: u8 = 0;
    core::array::from_fn(|_| {
        let mut acc = Z(0);
        for j in 0..d {
            // retrieve bit value directly from the byte array b
            acc = &acc + &Z(((&b[byte_idx]>>bit_idx)&1).0 as u16 * (1<<j));

            bit_idx += 1;
            if bit_idx == 8 {bit_idx = 0; byte_idx += 1;}
        }
        acc.rem(m)
    })
}