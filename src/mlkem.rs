use crate::kpke;
use crate::crypto_fns::{g, h, j};
use crate::byte_fns::{byte_decode, byte_encode};
use crate::{Error, Fips203Rng};

pub(crate) fn keygen<T, const K:usize, const ETA1_64:usize>(rng:&mut Fips203Rng<T>, ek:&mut [u8], dk:&mut [u8]) {
    let d = (rng.f)(&mut rng.rng);
    let z = (rng.f)(&mut rng.rng);
    keygen_internal::<K,ETA1_64>(&d, &z, ek, dk);
}
#[inline]
fn keygen_internal<const K:usize, const ETA1_64:usize>(d:&[u8], z:&[u8], ek:&mut [u8], dk:&mut [u8]) {
    kpke::keygen::<K, ETA1_64>(d, ek, dk);
    dk[384*K..384*K*2+32].clone_from_slice(&ek);
    dk[384*K*2+32..384*K*2+64].clone_from_slice(&h(&ek));
    dk[384*K*2+64..].clone_from_slice(z);
}

pub(crate) fn encaps
<T, const K:usize, const ETA1_64:usize, const ETA2_64:usize, const DU_32:usize, const DV_32:usize>
(ek:&[u8], rng:&mut Fips203Rng<T>, k:&mut [u8;32], c:&mut [u8], du:u8, dv:u8) -> Result<(),Error> {
    // check input
    /* The following checks are not required as they have been enforced by the public wrapper function in lib.rs
    let kc1 = ek.len() == 384*K+32;
     */
    let mut kc2 = true;
    for i in 0..K {
        let tmp = byte_encode::<{32*12}>(12, &byte_decode(12, &ek[i*384..i*384+384]));
        kc2 &= ek[i*384..i*384+384] == tmp;
    }
    if !kc2 {return Err(Error::InvalidInput)} //Invalid encapsulation key

    let m = (rng.f)(&mut rng.rng);
    encaps_internal::<K,ETA1_64,ETA2_64,DU_32,DV_32>(ek, &m, k, c, du, dv) 
}
#[inline]
fn encaps_internal
<const K:usize, const ETA1_64:usize, const ETA2_64:usize, const DU_32:usize, const DV_32:usize>
(ek:&[u8], m:&[u8;32], k:&mut [u8;32], c:&mut [u8], du:u8, dv:u8) -> Result<(),Error> {
    let mut m_h:[u8;64] = [0;64];
    m_h[..32].clone_from_slice(m);
    m_h[32..].clone_from_slice(&h(ek));
    let r: [u8; 32];
    (*k,r) = g(&m_h);
    kpke::encrypt::<K, ETA1_64, ETA2_64, DU_32, DV_32>(ek, m, &r, c, du, dv);
    Ok(())
}

pub(crate) fn decaps
<const K:usize, const ETA1_64:usize, const ETA2_64:usize, const DU_32:usize, const DV_32:usize, const ZC_LEN:usize>
(dk:&[u8], c:&[u8], k:&mut [u8;32], c_:&mut [u8], du:u8, dv:u8) -> Result<(), Error> {
    // check input
    /* 
    The following checks are not required as they have been enforced by the public wrapper function in lib.rs
    let kc1 = c.len() == 32*((du as usize)*K+(dv as usize));
    let kc2 = dk.len() == 768*K+96;
     */
    let kc3 = h(&dk[384*K..768*K+32]) == dk[768*K+32..768*K+64];
    if !kc3 {return Err(Error::InvalidInput)} // Invalid decapsulation input

    // internal
    let m = kpke::decrypt::<K>(&dk[0..384*K], c, du, dv);

    let mut m_h = [0u8;64];
    m_h[..32].clone_from_slice(&m);
    m_h[32..].clone_from_slice(&dk[768*K+32..768*K+64]);
    let r: [u8; 32];
    (*k,r) = g(&m_h);
    
    let mut z_c = [0u8;ZC_LEN];
    z_c[..32].clone_from_slice(&dk[768*K+64..768*K+96]);
    z_c[32..].clone_from_slice(c);
    let k2 = j(&z_c);

    kpke::encrypt::<K, ETA1_64, ETA2_64, DU_32, DV_32>(&dk[384*K..768*K+32], &m, &r, c_, du, dv);

    //TODO destroy flag
    //let c_match = c == c_;
    if c != c_ {*k = k2} // Decapsulation failure
    Ok(())
}


//TODO
#[cfg(not(feature = "std"))]
#[cfg(test)]
mod tests {
    use super::*;
    include!("../tests/data/data.rs");

    #[test]
    fn test_keygen() {
        for i in 0..25 {
            test::<{384*2+32},{768*2+96},2,{64*3}>(
                &keygen_512[i].0,&keygen_512[i].1,&keygen_512[i].2,&keygen_512[i].3
            );
        }
        for i in 0..25 {
            test::<{384*3+32},{768*3+96},3,{64*2}>(
                &keygen_768[i].0,&keygen_768[i].1,&keygen_768[i].2,&keygen_768[i].3
            );
        }
        for i in 0..25 {
            test::<{384*4+32},{768*4+96},4,{64*2}>(
                &keygen_1024[i].0,&keygen_1024[i].1,&keygen_1024[i].2,&keygen_1024[i].3
            );
        }

        #[inline]
        fn test<const EK_LEN:usize, const DK_LEN:usize, const K:usize, const ETA1_64:usize>(d:&[u8], z:&[u8], ek:&[u8], dk:&[u8]) {
            let mut ek1 = [0u8;EK_LEN];
            let mut dk1 = [0u8;DK_LEN];
            keygen_internal::<K,{ETA1_64}>(&d, &z, &mut ek1, &mut dk1);
            assert_eq!(ek1,ek);
            assert_eq!(dk1,dk);
        }
    }

    #[test]
    fn test_encaps() {
        for i in 0..25 {
            test::<{384*2+32},{32*(10*2+4)},2,{3*64},{2*64},{10*32},{4*32}>(
                10,4,&encaps_512[i].0,&encaps_512[i].1,&encaps_512[i].2,&encaps_512[i].3
            );
        }
        for i in 0..25 {
            test::<{384*3+32},{32*(10*3+4)},3,{2*64},{2*64},{10*32},{4*32}>(
                10,4,&encaps_768[i].0,&encaps_768[i].1,&encaps_768[i].2,&encaps_768[i].3
            );
        }
        for i in 0..25 {
            test::<{384*4+32},{32*(11*4+5)},4,{2*64},{2*64},{11*32},{5*32}>(
                11,5,&encaps_1024[i].0,&encaps_1024[i].1,&encaps_1024[i].2,&encaps_1024[i].3
            );
        }

        #[inline]
        fn test<const EK_LEN:usize, const C_LEN:usize, const K:usize, const ETA1_64:usize, const ETA2_64:usize, const DU_32:usize, const DV_32:usize>(du: u8, dv: u8, ek:&[u8], m:&[u8;32], c:&[u8], k:&[u8]) {
            let mut k1 = [0u8;32];
            let mut c1 = [0u8;C_LEN];
            let _ = encaps_internal::<K,{ETA1_64},{ETA2_64},{DU_32},{DV_32}>(ek, m, &mut k1, &mut c1, du, dv);
            assert_eq!(c1,c);
            assert_eq!(k1,k);
        }
    }

    #[test]
    fn test_decaps() {
        for i in 0..10 {
            test::<{768*2+96},{32*(10*2+4)},2,{3*64},{2*64},{10*32},{4*32},{32+32*(10*2+4)}>(
                10,4,&decaps_512[i].0,&decaps_512[i].1,&decaps_512[i].2
            );
        }
        for i in 0..10 {
            test::<{768*3+96},{32*(10*3+4)},3,{2*64},{2*64},{10*32},{4*32},{32+32*(10*3+4)}>(
                10,4,&decaps_768[i].0,&decaps_768[i].1,&decaps_768[i].2
            );
        }
        for i in 0..10 {
            test::<{768*4+96},{32*(11*4+5)},4,{2*64},{2*64},{11*32},{5*32},{32+32*(11*4+5)}>(
                11,5,&decaps_1024[i].0,&decaps_1024[i].1,&decaps_1024[i].2
            );
        }

        #[inline]
        fn test<const DK_LEN:usize, const C_LEN:usize, const K:usize, const ETA1_64:usize, const ETA2_64:usize, const DU_32:usize, const DV_32:usize, const ZC_LEN:usize>(du: u8, dv: u8, dk:&[u8], c:&[u8], k:&[u8]) {
            let mut k1 = [0u8;32];
            let mut c_ = [0u8;C_LEN];
            let _ = decaps::<K,ETA1_64,ETA2_64,DU_32,DV_32,ZC_LEN>(&dk, &c, &mut k1, &mut c_, du, dv);
            assert_eq!(k1,k);
        }
    }
}