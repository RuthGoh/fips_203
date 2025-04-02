use sha3::{digest::{ExtendableOutput, Update, XofReader, core_api::XofReaderCoreWrapper}, Shake256, Shake128, Shake128ReaderCore};
use sha3::{Digest, Sha3_512, Sha3_256};
use zeroize::Zeroize;
use crate::{S,types::{ss_to_bytes,bytes_to_ss}};

pub(crate) fn xof(b:&[u8;34]) -> XofReaderCoreWrapper<Shake128ReaderCore> {
    let mut hasher = Shake128::default();
    hasher.update(b);
    hasher.finalize_xof()
}

pub(crate) fn j<const S_LEN:usize>(s:&[S]) -> [S;32] {
    let mut hasher = Shake256::default();
    let mut s_b  = ss_to_bytes::<S_LEN>(s);
    hasher.update(&s_b);
    s_b.zeroize();
    let mut reader = hasher.finalize_xof();
    let mut buf: [u8;32] = [0;32];
    reader.read(&mut buf);
    let ret = bytes_to_ss(&buf);
    buf.zeroize();
    ret
}

pub(crate) fn prf<const LEN:usize>(v:&[S;33]) -> [S;LEN] {
    let mut hasher = Shake256::default();
    let mut v_b = ss_to_bytes::<33>(v);
    hasher.update(&v_b);
    v_b.zeroize();
    let mut reader = hasher.finalize_xof();
    let mut buf: [u8;LEN] = [0;LEN];
    reader.read(&mut buf);
    let ret = bytes_to_ss(&buf);
    buf.zeroize();
    ret
}

pub(crate) fn g<const C_LEN:usize>(c:&[S]) -> ([u8;32],[S;32]) {
    let mut hasher = Sha3_512::new();
    let mut c_b = ss_to_bytes::<C_LEN>(c);
    Digest::update(&mut hasher,&c_b);
    c_b.zeroize();
    let mut hash = hasher.finalize();
    let a:[u8;32] = core::array::from_fn(|i| hash[i]);
    let b:[S;32] = core::array::from_fn(|i| S(hash[i+32]));
    hash.zeroize();
    (a,b)
}

pub(crate) fn h<const S_LEN:usize>(s:&[S]) -> [S;32] {
    let mut hasher = Sha3_256::new();
    let mut s_b = ss_to_bytes::<S_LEN>(s);
    Digest::update(& mut hasher,&s_b);
    s_b.zeroize();
    let mut hash = hasher.finalize();
    let ret = core::array::from_fn(|i| S(hash[i]));
    hash.zeroize();
    ret
}