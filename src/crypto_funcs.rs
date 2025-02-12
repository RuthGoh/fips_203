use sha3::{digest::{ExtendableOutput, Update, XofReader}, Shake256, Shake128};
use sha3::{Digest, Sha3_512, Sha3_256};

pub fn xof(b:&[u8;34]) -> sha3::digest::core_api::XofReaderCoreWrapper<sha3::Shake128ReaderCore> {
    let mut hasher = Shake128::default();
    hasher.update(b);
    hasher.finalize_xof()
}

pub fn j(s:&[u8]) -> [u8;32] {
    let mut hasher = Shake256::default();
    hasher.update(s);
    let mut reader = hasher.finalize_xof();
    let mut buf: [u8;32] = [0;32];
    reader.read(&mut buf);
    buf
}

pub fn prf<const LEN:usize>(v:&[u8;33]) -> [u8;LEN] {
    let mut hasher = Shake256::default();
    hasher.update(v);
    let mut reader = hasher.finalize_xof();
    let mut buf: [u8;LEN] = [0;LEN];
    reader.read(&mut buf);
    buf
}

pub fn g(c:&[u8]) -> ([u8;32],[u8;32]) {
    let mut hasher = Sha3_512::new();
    Digest::update(&mut hasher,c);
    let hash = hasher.finalize();
    let a:[u8;32] = core::array::from_fn(|i| hash[i]);
    let b:[u8;32] = core::array::from_fn(|i| hash[i+32]);
    (a,b)
}

pub fn h(s:&[u8]) -> [u8;32] {
    let mut hasher = Sha3_256::new();
    Digest::update(& mut hasher,s);
    let hash = hasher.finalize();
    core::array::from_fn(|i| hash[i])
}