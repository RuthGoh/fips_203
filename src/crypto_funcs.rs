use sha3::{digest::{ExtendableOutput, Update, XofReader}, Shake256};//, Shake128};
use sha3::{Digest, Sha3_512, Sha3_256};

/* pub fn xof() -> {
    let mut NTT_vec: Vec<u16> = Vec::with_capacity(256);
    let mut hasher = Shake128::default();
    hasher.update(seed_vec);
    let mut reader = hasher.finalize_xof();
} */

pub fn j(s:&[u8]) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(s);
    let mut reader = hasher.finalize_xof();
    let mut buf: Vec<u8> = vec![0;8*32];
    reader.read(&mut buf);
    buf
}

pub fn prf(eta:usize, v:&[u8]) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(v);
    let mut reader = hasher.finalize_xof();
    let mut buf: Vec<u8> = vec![0;8*64*eta];
    reader.read(&mut buf);
    buf
}

pub fn g(c:&[u8]) -> Vec<u8> {
    let mut hasher = Sha3_512::new();
    Digest::update(&mut hasher,c);
    hasher.finalize().to_vec()
}

pub fn h(s:&[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    Digest::update(& mut hasher,s);
    hasher.finalize().to_vec()
}