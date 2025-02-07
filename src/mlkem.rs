use crate::{kpke, PARAMS};
use crate::crypto_funcs::{g, h, j};
use rand_chacha::ChaCha20Rng;
use rand_core::{SeedableRng, RngCore};
use crate::convert_compress::{byte_decode, byte_encode};

fn keygen_internal(d:&[u8], z:&[u8]) -> (Vec<u8>,Vec<u8>) {
    let mut k_tup = kpke::keygen(d.to_vec());
    k_tup.1 = [k_tup.1,k_tup.0.clone(),h(&k_tup.0),z.to_vec()].concat();
    k_tup
}

fn encaps_internal(ek:&[u8], m:&[u8]) -> (Vec<u8>,Vec<u8>) {
    let res = g(&[m,&h(ek)].concat());
    let c = kpke::encrypt(ek, m, res[32..].to_vec());
    (res[0..32].to_vec(),c)
}

fn decaps_internal(dk:&[u8], c:&[u8]) -> Vec<u8> {
    let m = kpke::decrypt(&dk[0..384*PARAMS[0]], c);
    let kr = g(&[&m,&dk[768*PARAMS[0]+32..768*PARAMS[0]+64]].concat());
    let kr: Vec<&[u8]> = kr.chunks_exact(32).collect(); // K' = kr[0], r' = kr[1]
    let k_ = j(&[&dk[768*PARAMS[0]+64..768*PARAMS[0]+96],c].concat());
    let c_ = kpke::encrypt(&dk[384*PARAMS[0]..768*PARAMS[0]+32], &m, kr[1].to_vec());
    if c != c_ {panic!("Decapsulation failure.")}
    k_
}

fn keygen() -> (Vec<u8>,Vec<u8>) {
    let mut rng = match ChaCha20Rng::try_from_os_rng() {
        Ok(x) => x,
        Err(_) => panic!("Failed to generate random numbers."),
    };
    let mut d = vec![0;32];
    RngCore::fill_bytes(&mut rng,&mut d);
    let mut z = vec![0;32];
    RngCore::fill_bytes(&mut rng,&mut z);
    keygen_internal(&d, &z)
}

fn encaps(ek:&[u8]) -> (Vec<u8>,Vec<u8>) {
    // check input
    let kc1 = ek.len() == 384*PARAMS[0]+32;
    let kc2 = ek[0..384*PARAMS[0]] == byte_encode(12, &byte_decode(12, &ek[0..384*PARAMS[0]]));
    if !(kc1 && kc2) {panic!("Invalid encapsulation key.")}

    let mut rng = match ChaCha20Rng::try_from_os_rng() {
        Ok(x) => x,
        Err(_) => panic!("Failed to generate random numbers."),
    };
    let mut m = vec![0;32];
    RngCore::fill_bytes(&mut rng,&mut m);
    encaps_internal(ek, &m)
}

fn decaps(dk:&[u8], c:&[u8]) -> Vec<u8> {
    // check input
    let kc1 = c.len() == 32*(PARAMS[3]*PARAMS[0]+PARAMS[4]);
    let kc2 = dk.len() == 786*PARAMS[0]+96;
    let kc3 = h(&dk[384*PARAMS[0]..768*PARAMS[0]+32]) == dk[768*PARAMS[0]+32..768*PARAMS[0]+64];
    if !(kc1 && kc2 && kc3) {panic!("Invalid decapsulation key.")}

    decaps_internal(dk, c)
}