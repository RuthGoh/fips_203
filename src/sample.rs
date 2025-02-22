use sha3::digest::XofReader;
use crate::Q;
use crate::crypto_fns::xof;

pub(crate) fn sample_ntt(b:&[u8;34]) -> [u16;256] {
    let mut a_: [u16;256] = [0;256];
    let mut reader = xof(b);
    let mut j = 0;
    let mut buf: [u8;3] = [0;3];
    while j < 256 {
        reader.read(&mut buf);
        let d1 = buf[0] as u16 + 256*(buf[1] as u16 %16);
        let d2 = buf[1] as u16/16 + 16*buf[2] as u16;
        if d1 < Q {
            a_[j] = d1;
            j += 1;
        }
        if d2 < Q && j < 256 {
            a_[j] = d2;
            j += 1;
        }
    }
    a_
}

// Q=3329
// b length = 64*eta
pub(crate) fn sample_poly_cbd(eta:u8, b:&[u8]) -> [u16;256] {
    let bitsum = |i:&mut usize| {
        let mut acc:u8 = 0;
        for _ in 0..eta {
            acc += (b[*i/8]>>(*i%8))&1;
            *i += 1;
        }
        acc as i16
    };
    
    let mut bit_idx:usize = 0;
    core::array::from_fn(|_| 
        ((
            bitsum(&mut bit_idx) - // x
            bitsum(&mut bit_idx) // y
        ).rem_euclid(Q as i16)) as u16
    )
}