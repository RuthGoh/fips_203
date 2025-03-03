use crate::Q;

pub(crate) fn compress(d:u8, u:&[u16;256]) -> [u16;256] {
    let q = Q as u32;
    let m: u32 = 1<<d;
    // round(i/j) = floor((i+floor(j/2))/j)
    // compute round((2^d *x)/q)
    core::array::from_fn(|i| (((m*(u[i] as u32)+q/2)/q)%m) as u16)
}

pub(crate) fn decompress(d:u8, u:&[u16;256]) -> [u16;256] {
    let m: u32 = 1<<d;
    // round(i/j) = floor((i+floor(j/2))/j)
    // compute round((q*y)/2^d) -> round((Q*u[i])/m)
    core::array::from_fn(|i| (((Q as u32)*(u[i] as u32)+m/2)/m) as u16)
}

pub(crate) fn byte_encode<const D_32:usize>(d:u8, f:&[u16;256]) -> [u8;D_32] {
    let mut b = [0u8;D_32];
    let mut byte_idx: usize = 0;
    let mut bit_idx: u8 = 0;
    for e in f {
        let mut a: u16 = *e;
        for _ in 0..d {
            // we convert the result directly to bytes
            // no need to call bits_to_bytes
            b[byte_idx] |= ((a%2) as u8)<<bit_idx;
            a = (a-(a%2))/2;
            
            bit_idx += 1;
            if bit_idx == 8 {bit_idx = 0; byte_idx += 1;}
        }
    }
    b
}

pub(crate) fn byte_decode(d:u8, b:&[u8]) -> [u16;256] {
    // compute m
    let m: u16 = {if d==12 {Q} else {1<<d}};
    
    let mut byte_idx: usize = 0;
    let mut bit_idx: u8 = 0;
    core::array::from_fn(|_| {
        let mut acc: u16 = 0;
        for j in 0..d {
            // retrieve bit value directly from the byte array b
            acc += ((b[byte_idx]>>bit_idx)&1) as u16*(1<<j);

            bit_idx += 1;
            if bit_idx == 8 {bit_idx = 0; byte_idx += 1;}
        }
        acc%m
    })
}