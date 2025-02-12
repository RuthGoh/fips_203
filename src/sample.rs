use sha3::digest::XofReader;
use crate::Q;
use crate::crypto_funcs::xof;

pub fn sample_ntt(b:&[u8;34]) -> [u16;256] {
    let mut a_: [u16;256] = [0;256];
    let mut reader = xof(b);
    let mut j = 0;
    while j < 256 {
        let mut buf: [u8;3] = [0;3];
        reader.read(&mut buf);
        let d1 = (buf[0] + 256*(buf[1] %16)) as u16;
        let d2 = (buf[1]/16 + 16*buf[2]) as u16;
        if d1 < Q {
            a_[j] = d1;
            j += 1;
        }
        if d2  < Q && j < 256 {
            a_[j] = d2;
            j += 1;
        }
    }
    a_
}

// Q=3329
// b length = 64*eta
pub fn sample_poly_cbd(eta:u8, b:&[u8]) -> [u16;256] {
    let mut bit_idx:usize = 0;
    core::array::from_fn(|_| 
        ((
            bitsum(&b[bit_idx/8..bit_idx/8+2], &mut bit_idx, eta) - // x
            bitsum(&b[bit_idx/8..bit_idx/8+2], &mut bit_idx, eta) // y
        )%(Q as i16)) as u16
    )
}
fn bitsum(b:&[u8], i:&mut usize, eta:u8) -> i16 {
    let mut acc:u8 = 0;
    for _ in 0..eta {
        acc += b[*i/8]>>(*i%8);
        *i += 1;
    }
    acc as i16
}