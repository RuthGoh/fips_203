use sha3::{digest::{ExtendableOutput, Update, XofReader}, Shake128};
use crate::convert_compress::bytes_to_bits;
use crate::Q;

pub fn sample_NTT(seed_vec:&[u8]) -> Vec<u16> {
    let mut NTT_vec: Vec<u16> = Vec::with_capacity(256);
    let mut hasher = Shake128::default();
    hasher.update(seed_vec);
    let mut reader = hasher.finalize_xof();
    let mut j = 0;
    while j < 256 {
        let mut buf: Vec<u8> = vec![0;3];
        reader.read(&mut buf);
        let d1 = (buf[0] + 256*(buf[1] %16)) as u16;
        let d2 = (buf[1]/16 + 16*buf[2]) as u16;
        if d1 < crate::Q {
            NTT_vec.push(d1);
            j += 1;
        }
        if d2  < crate::Q && j < 256 {
            NTT_vec.push(d2);
            j += 1;
        }
    }
    NTT_vec
}

// Q=3329
pub fn sample_poly_CBD(eta:u8, b:&[u8]) -> Vec<u16> {
    let eta = eta as usize;
    let mut sample_vec: Vec<u16> = Vec::with_capacity(256);

    let bit_vec = bytes_to_bits(b);
    for i in 0..256 {
        let slice_i = 2*i*eta+eta;
        let x = bit_vec[slice_i-eta..slice_i].iter().map(|e| *e as i16).sum::<i16>();
        let y = bit_vec[slice_i..slice_i+eta].iter().map(|e| *e as i16).sum::<i16>();
        sample_vec.push(((x - y) % Q as i16) as u16)
    }
    sample_vec
}