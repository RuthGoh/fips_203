use crate::sample::{sample_ntt, sample_poly_cbd};
use crate::crypto_fns::{g, prf};
use crate::ntt::{ntt, ntt_inv, multiply_ntts};
use crate::byte_fns::{byte_encode, byte_decode, compress, decompress};
//use crate::{Q, K, ETA1, ETA2, DU, DV};

fn mul_mats(a:&[[[u16;256];K];K], u:&[[u16;256];K], t:bool) -> [[u16;256];K] {
    core::array::from_fn(|i| {
        let mut acc:[u16;256] = [0;256];
        for j in 0..K {
            let tmp = multiply_ntts(&{if t {a[j][i]} else {a[i][j]}}, &u[j]);
            for i in 0..256 {acc[i] = (acc[i]+tmp[i])%Q}
        }
        acc
    })
}
fn add_mats(u:&[[u16;256];K], v:&[[u16;256];K]) -> [[u16;256];K] {
    core::array::from_fn(|i| {add_vecs(&u[i], &v[i])})
}
fn dot_prod(u:&[[u16;256];K], v:&[[u16;256];K]) -> [u16;256] {
    let mut acc:[u16;256] = [0;256];
    for j in 0..K {
        let tmp = multiply_ntts(&u[j], &v[j]);
        for i in 0..256 {acc[i] = (acc[i]+tmp[i])%Q}
    }
    acc
}
pub(crate) fn add_vecs(u:&[u16;256], v:&[u16;256]) -> [u16;256] {
    core::array::from_fn(|i| (u[i] + v[i])%Q)
}

pub(crate) fn keygen(d:&[u8;32]) -> ([u8;384*K+32],[u8;384*K]) {
    let k = K as u8;

    let mut d_k = [k;33];
    d_k[..32].clone_from_slice(d);
    let (roe,sigma) = g(&d_k);

    // create new array r <- roe||j||i
    let mut roe_ji: [u8;34] = [0;34];
    roe_ji[..32].clone_from_slice(&roe);
    let a_: [[[u16;256];K];K] = core::array::from_fn(|i|
        core::array::from_fn(|j| {
            // assign i and j to r
            // return the array from sample_ntt
            // a[i][j] <- sample_ntt(&r)
            roe_ji[32] = j as u8; roe_ji[33] = i as u8;
            sample_ntt(&roe_ji)
        })
    );

    let mut sigma_n: [u8;33] = [0;33]; // the last element keeps count of N
    sigma_n[..32].clone_from_slice(&sigma);
    let s_:[[u16;256];K] = core::array::from_fn(|_| {
        let x = ntt(&sample_poly_cbd(ETA1, &prf::<{ETA1*64}>(&sigma_n)));
        sigma_n[32] += 1;
        x
    });
    let e_:[[u16;256];K] = core::array::from_fn(|_| {
        let x = ntt(&sample_poly_cbd(ETA1, &prf::<{ETA1*64}>(&sigma_n)));
        sigma_n[32] += 1;
        x
    });

    let t_:[[u16; 256]; K] = add_mats(&mul_mats(&a_, &s_, false), &e_);
    let mut ek:[u8;384*K+32] = [0;384*K+32];
    for i in 0..K {
        ek[i*384..i*384+384].clone_from_slice(&byte_encode::<{32*12}>(12, &t_[i]));
    }
    ek[384*K..384*K+32].clone_from_slice(&roe);
    let mut dk:[u8;384*K] = [0;384*K];
    for i in 0..K {
        dk[i*384..i*384+384].clone_from_slice(&byte_encode::<{32*12}>(12, &s_[i]));
    }
    (ek,dk)
}

pub(crate) fn encrypt(ek:&[u8;384*K+32], m:&[u8;32], r:&[u8;32]) -> [u8;32*(DU*K+DV)] {
    let t_:[[u16;256];K] = core::array::from_fn(|i| byte_decode(12, &ek[384*i..i*384+384]));

    // roe_ji <- roe||j||i
    let mut roe_ji:[u8;34] = [0;34];
    roe_ji[..32].clone_from_slice(&ek[384*K..]);
    let a_: [[[u16;256];K];K] = core::array::from_fn(|i|
        core::array::from_fn(|j| {
            // assign i and j to r
            // return the array from sample_ntt
            // a[i][j] <- sample_ntt(&r)
            roe_ji[32] = j as u8; roe_ji[33] = i as u8;
            sample_ntt(&roe_ji)
        })
    );

    let mut r_n: [u8;33] = [0;33]; // the last element keeps count of N
    r_n[..32].clone_from_slice(r);
    let y_:[[u16;256];K] = core::array::from_fn(|_| {
        let x = ntt(&sample_poly_cbd(ETA1, &prf::<{ETA1*64}>(&r_n)));
        r_n[32] += 1;
        x
    });
    let e1:[[u16;256];K] = core::array::from_fn(|_| {
        let x = sample_poly_cbd(ETA2, &prf::<{ETA2*64}>(&r_n));
        r_n[32] += 1;
        x
    });

    let e2: [u16; 256] = sample_poly_cbd(ETA2, &prf::<{ETA2*64}>(&r_n));
    
    let tmp1 = mul_mats(&a_, &y_, true);
    let tmp2:[[u16;256];K] = core::array::from_fn(|i| ntt_inv(&tmp1[i]));
    let u: [[u16; 256]; K] = add_mats(&tmp2, &e1);
    
    let mu:[u16;256] = decompress(1, &byte_decode(1, m));
    let tmp = add_vecs(&ntt_inv(&dot_prod(&t_, &y_)), &e2);
    let v: [u16; 256] = add_vecs(&tmp, &mu);

    let mut c = [0u8;32*(DU*K+DV)];
    // c1
    for i in 0..K {
        c[i*32*DU..i*32*DU+32*DU].clone_from_slice(&byte_encode::<{32*DU}>(DU as u8,&compress(DU, &u[i])));
    }
    // c2
    c[32*DU*K..].clone_from_slice(&byte_encode::<{32*DV}>(DV as u8,&compress(DV, &v)));
    c
}

pub(crate) fn decrypt(dk:&[u8;384*K], c:&[u8;32*(DU*K+DV)]) -> [u8;32] {
    let u: [[u16;256];K] = core::array::from_fn(|i| decompress(DU, &byte_decode(DU, &c[i*32*DU..i*32*DU+32*DU])));
    let v: [u16;256] = decompress(DV, &byte_decode(DV, &c[32*DU*K..]));
    let s_: [[u16;256];K] = core::array::from_fn(|i| byte_decode(12, &dk[i*384..i*384+384]));

    let tmp = ntt_inv(&dot_prod(&s_, &core::array::from_fn(|i| ntt(&u[i]))));
    let w:[u16;256] = core::array::from_fn(|i| (v[i] as i16 - tmp[i] as i16).rem_euclid(Q as i16) as u16);
    let m = byte_encode::<32>(1, &compress(1, &w));
    m
}