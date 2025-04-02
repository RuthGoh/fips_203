use sha3::digest::XofReader;
use zeroize::Zeroize;
use crate::Q;
use crate::crypto_fns::xof;
use crate::{Z,S};

pub(crate) fn sample_ntt(b:&[u8;34]) -> [Z;256] {
    let mut a_: [Z;256] = core::array::from_fn(|_| Z(0));
    let mut reader = xof(&b);
    let mut j = 0;
    let mut buf: [u8;3] = [0;3];
    while j < 256 {
        reader.read(&mut buf);
        let d1 = buf[0] as u16 + 256*(buf[1] as u16 %16);
        let d2 = buf[1] as u16/16 + 16*buf[2] as u16;
        if d1 < Q {
            a_[j] = Z(d1);
            j += 1;
        }
        if d2 < Q && j < 256 {
            a_[j] = Z(d2);
            j += 1;
        }
    }
    buf.zeroize();
    a_
}

// b length = 64*eta
pub(crate) fn sample_poly_cbd(eta:u8, b:&[S]) -> [Z;256] {
    let bitsum = |i:&mut usize| {
        let mut acc = S(0);
        for _ in 0..eta {
            acc += (&b[*i/8]>>(*i%8))&1;
            *i += 1;
        }
        Z(acc.0 as u16)
    };
    
    let mut bit_idx:usize = 0;
    core::array::from_fn(|_|
        &bitsum(&mut bit_idx) - // x
        &bitsum(&mut bit_idx) // y
    )
}