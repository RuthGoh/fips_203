// bit vec
use crate::Q;

fn bits_to_bytes(bit_vec:&[u8]) -> Vec<u8> {
    let mut byte_vec: Vec<u8> = vec![0;bit_vec.len()/8];
    for i in 0..bit_vec.len() {byte_vec[i/8] |= bit_vec[i]<<(i%8)}
    byte_vec
}

pub fn bytes_to_bits(byte_vec:&[u8]) -> Vec<u8> {
    let mut bit_vec: Vec<u8> = Vec::with_capacity(byte_vec.len()*8);
    byte_vec.iter().for_each(
        |e| {(0..8).for_each(|i| bit_vec.push(e>>i & 1))}
    );
    bit_vec
}

// Q=3329
pub fn compress(d:u8, vec:&mut [u16]) {
    let modulus: u32 = 2<<(d-1);
    for e in vec.iter_mut() {
        *e = (((*e as u32*modulus + Q/2)/Q)%modulus) as u16;
        // round(x/y) = floor((x+floor(y/2))/y) ?
    }
}

// Q=3329
pub fn decompress(d:u8, vec:&[u16]) -> Vec<u16> {
    let modulus: u32 = 2<<(d-1);
    let mut decomp_vec: Vec<u16> = Vec::with_capacity(vec.len());
    for e in vec.iter() {
        decomp_vec.push(((*e as u32*Q + modulus/2)/modulus) as u16);
    }
    decomp_vec
}

// m=2^d if d<12, m=q if d=12
// N=256
pub fn byte_encode(d:u8, int_vec:&[u16]) -> Vec<u8> {
    let d: usize = d as usize;
    let mut bit_vec: Vec<u8> = Vec::with_capacity(32*d);
    int_vec.iter().for_each(
        |e| {(0..d).for_each(|j| bit_vec.push((e>>j) as u8 & 1))}
    );
    bits_to_bytes(&bit_vec)
}

// Q=3329
// only need to modulus if mod_exp = 12?
pub fn byte_decode(d:u8, byte_vec:&[u8]) -> Vec<u16> {
    let modulus: u16;
    if d == 12 {modulus = Q}
    else {modulus = 1<<d}
    let mod_exp: usize = d as usize;
    
    let mut int_vec: Vec<u16> = vec![0;256];
    let bit_vec = bytes_to_bits(byte_vec);
    for i in 0..bit_vec.len() {
        int_vec[i/mod_exp] += (bit_vec[i] as u16)<<(i%mod_exp)
    }
    for e in int_vec.iter_mut() {*e = *e%modulus}
    int_vec
}