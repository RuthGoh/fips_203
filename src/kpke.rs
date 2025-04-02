use crate::sample::{sample_ntt, sample_poly_cbd};
use crate::crypto_fns::{g, prf};
use crate::ntt::{ntt, ntt_inv, multiply_ntts};
use crate::byte_fns::{byte_encode, byte_decode, compress, decompress};
use crate::{Z,S,types::ss_to_bytes};

fn mul_mats<const K:usize>(a:&[[[Z;256];K];K], u:&[[Z;256];K], t:bool) -> [[Z;256];K] {
    core::array::from_fn(|i| {
        let mut acc:[Z;256] = core::array::from_fn(|_| Z(0));
        for j in 0..K {
            let tmp = multiply_ntts(if t {&a[j][i]} else {&a[i][j]}, &u[j]);
            for i in 0..256 {acc[i] = &acc[i]+&tmp[i]}
        }
        acc
    })
}
fn add_mats<const K:usize>(u:&[[Z;256];K], v:&[[Z;256];K]) -> [[Z;256];K] {
    core::array::from_fn(|i| {add_vecs(&u[i], &v[i])})
}
fn dot_prod<const K:usize>(u:&[[Z;256];K], v:&[[Z;256];K]) -> [Z;256] {
    let mut acc:[Z;256] = core::array::from_fn(|_| Z(0));
    for j in 0..K {
        let tmp = multiply_ntts(&u[j], &v[j]);
        for i in 0..256 {acc[i] = &acc[i]+&tmp[i]}
    }
    acc
}
fn add_vecs(u:&[Z;256], v:&[Z;256]) -> [Z;256] {
    core::array::from_fn(|i| &u[i] + &v[i])
}
fn gen_a<const K:usize>(rho:&[u8;32]) -> [[[Z;256];K];K] {
    // create new array r <- rho||j||i
    let mut it = rho.iter().chain([0,0].iter());
    let mut rho_ji: [u8;34] = core::array::from_fn(|_| it.next().expect("Some error occured.").clone());
    core::array::from_fn(|_| {
        rho_ji[32] = 0;
        let ret = core::array::from_fn(|_| {
            // assign i and j to rho_ji
            // return the array from sample_ntt
            // a[i][j] <- sample_ntt(&rho_ji)
            let ret = sample_ntt(&rho_ji);
            rho_ji[32] += 1;
            ret
        });
        rho_ji[33] += 1;
        ret
        }
    )
}

pub(crate) fn keygen<const K:usize, const ETA1_64:usize>(d:&[S], ek:&mut [u8], dk:&mut [u8]) {
    let eta1 = ETA1_64 as u8/64;

    let binding = [S(K as u8)];
    let mut it = d.iter().chain(binding.iter());
    let d_k:[S;33] = core::array::from_fn(|_| it.next().expect("Some error occured.").clone());
    let (rho,sigma) = g::<33>(&d_k);

    let a_ = gen_a(&rho);

    let binding = [S(0)];
    let mut it = sigma.iter().chain(binding.iter());
    let mut sigma_n: [S;33] = core::array::from_fn(|_| it.next().expect("Some error occured.").clone()); // the last element keeps count of N
    let s_:[[Z;256];K] = core::array::from_fn(|_| {
        let x = ntt(sample_poly_cbd(eta1, &prf::<ETA1_64>(&sigma_n)));
        sigma_n[32] += 1;
        x
    });
    let e_:[[Z;256];K] = core::array::from_fn(|_| {
        let x = ntt(sample_poly_cbd(eta1, &prf::<ETA1_64>(&sigma_n)));
        sigma_n[32] += 1;
        x
    });

    let t_:[[Z; 256]; K] = add_mats(&mul_mats(&a_, &s_, false), &e_);
    for i in 0..K {
        ek[i*384..i*384+384].clone_from_slice(&ss_to_bytes::<384>(&byte_encode::<{32*12}>(12, &t_[i])));
    }
    ek[384*K..384*K+32].clone_from_slice(&rho);
    for i in 0..K {
        dk[i*384..i*384+384].clone_from_slice(&ss_to_bytes::<384>(&byte_encode::<{32*12}>(12, &s_[i])));
    }
}

pub(crate) fn encrypt
<const K:usize, const ETA1_64:usize, const ETA2_64:usize, const DU_32:usize, const DV_32:usize>
(ek:&[S], m:&[S;32], r:&[S;32], c:&mut [S], du:u8, dv:u8) {
    let eta2 = ETA2_64 as u8/64;
    
    let t_:[[Z;256];K] = core::array::from_fn(|i| byte_decode(12, &ek[384*i..i*384+384]));

    let a_ = gen_a(&ss_to_bytes::<32>(&ek[384*K..]));

    let binding = [S(0)];
    let mut it = r.iter().chain(binding.iter());
    let mut r_n: [S;33] = core::array::from_fn(|_| it.next().expect("Some error occured.").clone());
    let y_:[[Z;256];K] = core::array::from_fn(|_| {
        let x = ntt(sample_poly_cbd(ETA1_64 as u8/64, &prf::<ETA1_64>(&r_n)));
        r_n[32] += 1;
        x
    });
    let e1:[[Z;256];K] = core::array::from_fn(|_| {
        let x = sample_poly_cbd(eta2, &prf::<ETA2_64>(&r_n));
        r_n[32] += 1;
        x
    });

    let e2: [Z; 256] = sample_poly_cbd(eta2, &prf::<ETA2_64>(&r_n));

    let tmp = mul_mats(&a_, &y_, true);
    let u: [[Z; 256]; K] = add_mats(&core::array::from_fn(|i| ntt_inv(tmp[i].clone())), &e1);
    
    let mu:[Z;256] = decompress(1, &byte_decode(1, m));
    let tmp = add_vecs(&ntt_inv(dot_prod(&t_, &y_)), &e2);
    let v: [Z; 256] = add_vecs(&tmp, &mu);

    // c1
    for i in 0..K {
        c[i*DU_32..i*DU_32+DU_32].clone_from_slice(&byte_encode::<DU_32>(du,&compress(du, &u[i])));
    }
    // c2
    c[DU_32*K..].clone_from_slice(&byte_encode::<DV_32>(dv,&compress(dv, &v)));
}

pub(crate) fn decrypt<const K:usize>(dk:&[S], c:&[S], du:u8, dv:u8) -> [S;32] {
    let u: [[Z;256];K] = core::array::from_fn(|i: usize| decompress(du, &byte_decode(du, &c[i*32*(du as usize)..(i+1)*32*(du as usize)])));
    let v: [Z;256] = decompress(dv, &byte_decode(dv, &c[32*(du as usize)*K..]));
    let s_: [[Z;256];K] = core::array::from_fn(|i| byte_decode(12, &dk[i*384..i*384+384]));

    let tmp = ntt_inv(dot_prod(&s_, &core::array::from_fn(|i| ntt(u[i].clone()))));
    let w:[Z;256] = core::array::from_fn(|i| &v[i]-&tmp[i]);
    byte_encode::<32>(1, &compress(1, &w))
}