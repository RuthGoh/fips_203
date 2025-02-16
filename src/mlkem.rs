use crate::kpke;
//use crate::{K, DU, DV};
use crate::crypto_fns::{g, h, j};
use crate::byte_fns::{byte_decode, byte_encode};
use crate::{Error, Rng};

//TODO: rng.fill errors, check chacha error type, nostd rng

fn keygen_internal(d:&[u8;32], z:&[u8;32]) -> ([u8;384*K+32],[u8;768*K+96]) {
    let (ek,dk_pke) = kpke::keygen(d);
    let mut dk:[u8;768*K+96] = [0;768*K+96];
    dk[..384*K].clone_from_slice(&dk_pke);
    dk[384*K..384*K*2+32].clone_from_slice(&ek);
    dk[384*K*2+32..384*K*2+64].clone_from_slice(&h(&ek));
    dk[384*K*2+64..].clone_from_slice(z);
    (ek, dk)
}

fn encaps_internal(ek:&[u8;384*K+32], m:&[u8;32]) -> ([u8;32],[u8;32*(DU*K+DV)]) {
    let mut m_h:[u8;64] = [0;64];
    m_h[..32].clone_from_slice(m);
    m_h[32..].clone_from_slice(&h(ek));
    let (k,r) = g(&m_h);
    let c = kpke::encrypt(ek, m, &r);
    (k,c)
}

fn decaps_internal(dk:&[u8;768*K+96], c:&[u8;32*(DU*K+DV)]) -> Result<[u8;32],Error> {
    let mut dk_pke = [0u8;384*K];
    dk_pke.clone_from_slice(&dk[0..384*K]);
    let m: [u8;32] = kpke::decrypt(&dk_pke, c);

    let mut m_h = [0u8;64];
    m_h[..32].clone_from_slice(&m);
    m_h[32..].clone_from_slice(&dk[768*K+32..768*K+64]);
    let (k1,r) = g(&m_h);
    
    let mut z_c = [0u8;32+32*(DU*K+DV)];
    z_c[..32].clone_from_slice(&dk[768*K+64..768*K+96]);
    z_c[32..].clone_from_slice(c);
    let k2 = j(c);

    let mut ek_pke = [0u8;384*K+32];
    ek_pke.clone_from_slice(&dk[384*K..768*K+32]);
    let c_: [u8;32*(DU*K+DV)] = kpke::encrypt(&ek_pke, &m, &r);

    if *c == c_ {Ok(k1)} else {Err(Error::DecapsulationFailure)} // Decapsulation failure
}

pub(crate) fn keygen<T>(rng:&mut Rng<T>) -> ([u8;384*K+32],[u8;768*K+96]) {
    let mut d = [0u8;32];
    (rng.f)(&mut rng.rng, &mut d);
    let mut z = [0u8;32];
    (rng.f)(&mut rng.rng, &mut z);
    keygen_internal(&d, &z)
}

//TODO?:key pair check for 3rd party keys

pub(crate) fn encaps<T>(ek:&[u8;384*K+32], rng:&mut Rng<T>) -> Result<([u8;32],[u8;32*(DU*K+DV)]),Error> {
    // check input
    let kc1 = ek.len() == 384*K+32;
    let mut kc2 = true;
    for i in 0..K {
        let tmp = byte_encode::<{32*12}>(12, &byte_decode(12, &ek[i*384..i*384+384]));
        kc2 &= ek[i*384..i*384+384] == tmp;
    }
    if !(kc1 && kc2) {return Err(Error::InvalidKey)} //Invalid encapsulation key

    let mut m = [0u8;32];
    (rng.f)(&mut rng.rng, &mut m);
    Ok(encaps_internal(ek, &m))
}

pub(crate) fn decaps(dk:&[u8;768*K+96], c:&[u8;32*(DU*K+DV)]) -> Result<[u8;32], Error> {
    // check input
    let kc1 = c.len() == 32*(DU*K+DV);
    let kc2 = dk.len() == 768*K+96;
    let kc3 = h(&dk[384*K..768*K+32]) == dk[768*K+32..768*K+64];

    if !(kc1 && kc2 && kc3) {Err(Error::InvalidKey)} // Invalid decapsulation key
    else {decaps_internal(dk, c)}
}