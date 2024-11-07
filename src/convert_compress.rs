// bit vec

fn bits_to_bytes(bit_vec:&Vec<u8>) -> Vec<u8> {
    let mut byte_vec: Vec<u8> = Vec::with_capacity(bit_vec.len()/8);
    byte_vec.extend(bit_vec.chunks_exact(8).map(
        |chunk: &[u8]| -> u8 {chunk.iter().enumerate().map(|(i,e)| e<<i).sum()}
    ));
    byte_vec
}

pub fn bytes_to_bits(byte_vec:&Vec<u8>) -> Vec<u8> {
    let mut bit_vec: Vec<u8> = Vec::with_capacity(byte_vec.len()*8);
    byte_vec.iter().for_each(
        |e| {(0..8).for_each(|i| bit_vec.push(e>>i & 1))}
    );
    bit_vec
}

// q=3329
fn compress(mod_exp:&u8, vec:&mut Vec<u16>) {
    let modulus: u32 = 2<<mod_exp-1;
    for e in vec.iter_mut() {
        *e = ((*e as u32*modulus + 3329/2)/3329) as u16;
    }
}

// q=3329
fn decompress(mod_exp:&u8, vec:&mut Vec<u16>) {
    let modulus: u32 = 2<<mod_exp-1;
    for e in vec.iter_mut() {
        *e = ((*e as u32*3329 + modulus/2)/modulus) as u16;
    }
}

// m=2^d if d<12, m=q if d=12
// n=256
fn byte_encode(mod_exp:u8, int_vec:&Vec<u16>) -> Vec<u8> {
    let mod_exp: usize = mod_exp as usize;
    let mut bit_vec: Vec<u8> = Vec::with_capacity(32*mod_exp);
    int_vec.iter().for_each(
        |e| {(0..mod_exp).for_each(|j| bit_vec.push((e>>j) as u8 & 1))}
    );
    bits_to_bytes(&bit_vec)
}

// n=256, q=3329
fn byte_decode(mod_exp:u8, byte_vec:&Vec<u8>) -> Vec<u16> {
    let modulus: u16;
    if mod_exp == 12 {modulus = 3329;}
    else {modulus = 1<<mod_exp;}
    
    let mut int_vec: Vec<u16> = Vec::with_capacity(256);
    int_vec.extend(bytes_to_bits(byte_vec).chunks_exact(mod_exp as usize).map(
        |chunk| -> u16 {chunk.iter().enumerate().map(
            |(i,e)| (*e as u16)<<i
        ).sum()}
    ).map(|e| e%modulus));
    int_vec
}