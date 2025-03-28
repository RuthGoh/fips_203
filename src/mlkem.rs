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
//#[cfg(feature = "no_std")]
#[cfg(test)]
mod tests {
    use hex::{decode_to_slice, encode_upper};
    use serde_json::Value;
    use super::*;
    
    #[test]
    fn test_keygen() {
        let data: Value = serde_json::from_str(include_str!("../tests/data/keygen.json")).expect("unable to parse data");
        
        for i in 0..25 {
            let d = &data["testGroups"][0]["tests"][i];
            //K=2, ETA1=3
            test::<{384*2+32},{768*2+96},2,{64*3}>(
                d["d"].as_str().expect("failed to retrieve data"),d["z"].as_str().expect("failed to retrieve data"),
                d["ek"].as_str().expect("failed to retrieve data"),d["dk"].as_str().expect("failed to retrieve data")
            );
        }
        for i in 0..25 {
            let d = &data["testGroups"][1]["tests"][i];
            //K=3, ETA1=2
            test::<{384*3+32},{768*3+96},3,{64*2}>(
                d["d"].as_str().expect("failed to retrieve data"),d["z"].as_str().expect("failed to retrieve data"),
                d["ek"].as_str().expect("failed to retrieve data"),d["dk"].as_str().expect("failed to retrieve data")
            );
        }
        for i in 0..25 {
            let d = &data["testGroups"][2]["tests"][i];
            //K=4, ETA1=2
            test::<{384*4+32},{768*4+96},4,{64*2}>(
                d["d"].as_str().expect("failed to retrieve data"),d["z"].as_str().expect("failed to retrieve data"),
                d["ek"].as_str().expect("failed to retrieve data"),d["dk"].as_str().expect("failed to retrieve data")
            );
        }

        #[inline]
        fn test<const EK_LEN:usize, const DK_LEN:usize, const K:usize, const ETA1_64:usize>(d_str:&str, z_str:&str, ek_str:&str, dk_str:&str) {
            let mut ek = [0u8;EK_LEN];
            let mut dk = [0u8;DK_LEN];
            let mut d = [0u8;32];
            let mut z = [0u8;32];
            decode_to_slice(d_str,&mut d).expect("Decode failure");
            decode_to_slice(z_str,&mut z).expect("Decode failure");
            keygen_internal::<K,{ETA1_64}>(&d, &z, &mut ek, &mut dk);
            assert_eq!(encode_upper(ek),ek_str);
            assert_eq!(encode_upper(dk),dk_str);
        }
    }

    #[test]
    fn test_encaps() {
        let data: Value = serde_json::from_str(include_str!("../tests/data/encaps_decaps.json")).expect("unable to parse data");

        for i in 0..25 {
            let d = &data["testGroups"][0]["tests"][i];
            //K=2, ETA1=3, ETA2=2, DU=10, DV=4
            test::<{384*2+32},{32*(10*2+4)},2,{3*64},{2*64},{10*32},{4*32}>(
                10,4,
                d["ek"].as_str().expect("failed to retrieve data"),d["m"].as_str().expect("failed to retrieve data"),
                d["c"].as_str().expect("failed to retrieve data"),d["k"].as_str().expect("failed to retrieve data")
            );
        }
        for i in 0..25 {
            let d = &data["testGroups"][1]["tests"][i];
            //K=3, ETA1=2, ETA2=2, DU=10, DV=4
            test::<{384*3+32},{32*(10*3+4)},3,{2*64},{2*64},{10*32},{4*32}>(
                10,4,
                d["ek"].as_str().expect("failed to retrieve data"),d["m"].as_str().expect("failed to retrieve data"),
                d["c"].as_str().expect("failed to retrieve data"),d["k"].as_str().expect("failed to retrieve data")
            );
        }
        for i in 0..25 {
            let d = &data["testGroups"][2]["tests"][i];
            //K=4, ETA1=2, ETA2=2, DU=11, DV=5
            test::<{384*4+32},{32*(11*4+5)},4,{2*64},{2*64},{11*32},{5*32}>(
                11,5,
                d["ek"].as_str().expect("failed to retrieve data"),d["m"].as_str().expect("failed to retrieve data"),
                d["c"].as_str().expect("failed to retrieve data"),d["k"].as_str().expect("failed to retrieve data")
            );
        }

        #[inline]
        fn test<const EK_LEN:usize, const C_LEN:usize, const K:usize, const ETA1_64:usize, const ETA2_64:usize, const DU_32:usize, const DV_32:usize>(du: u8, dv: u8, ek_str:&str, m_str:&str, c_str:&str, k_str:&str) {
            let mut ek = [0u8;EK_LEN];
            let mut m = [0u8;32];
            decode_to_slice(ek_str,&mut ek).expect("Decode failure");
            decode_to_slice(m_str,&mut m).expect("Decode failure");
            let mut k = [0u8;32];
            let mut c = [0u8;C_LEN];
            let _ = encaps_internal::<K,{ETA1_64},{ETA2_64},{DU_32},{DV_32}>(&ek, &m, &mut k, &mut c, du, dv);
            assert_eq!(encode_upper(c),c_str);
            assert_eq!(encode_upper(k),k_str);
        }
    }

    #[test]
    fn test_decaps() {
        let data: Value = serde_json::from_str(include_str!("../tests/data/encaps_decaps.json")).expect("unable to parse data");
        
        let dk = data["testGroups"][3]["dk"].as_str().expect("failed to retrieve data");
        for i in 0..10 {
            let c = data["testGroups"][3]["tests"][i]["c"].as_str().expect("failed to retrieve data");
            let k = data["testGroups"][3]["tests"][i]["k"].as_str().expect("failed to retrieve data");
            //K=2, ETA1=3, ETA2=2, DU=10, DV=4
            test::<{768*2+96},{32*(10*2+4)},2,{3*64},{2*64},{10*32},{4*32},{32+32*(10*2+4)}>(
                10,4,dk,c,k
            );
        }
        let dk = data["testGroups"][4]["dk"].as_str().expect("failed to retrieve data");
        for i in 0..10 {
            let c = data["testGroups"][4]["tests"][i]["c"].as_str().expect("failed to retrieve data");
            let k = data["testGroups"][4]["tests"][i]["k"].as_str().expect("failed to retrieve data");
            //K=3, ETA1=2, ETA2=2, DU=10, DV=4
            test::<{768*3+96},{32*(10*3+4)},3,{2*64},{2*64},{10*32},{4*32},{32+32*(10*3+4)}>(
                10,4,dk,c,k
            );
        }
        let dk = data["testGroups"][5]["dk"].as_str().expect("failed to retrieve data");
        for i in 0..10 {
            let c = data["testGroups"][5]["tests"][i]["c"].as_str().expect("failed to retrieve data");
            let k = data["testGroups"][5]["tests"][i]["k"].as_str().expect("failed to retrieve data");
            //K=4, ETA1=2, ETA2=2, DU=11, DV=5
            test::<{768*4+96},{32*(11*4+5)},4,{2*64},{2*64},{11*32},{5*32},{32+32*(11*4+5)}>(
                11,5,dk,c,k
            );
        }

        #[inline]
        fn test<const DK_LEN:usize, const C_LEN:usize, const K:usize, const ETA1_64:usize, const ETA2_64:usize, const DU_32:usize, const DV_32:usize, const ZC_LEN:usize>(du: u8, dv: u8, dk_str:&str, c_str:&str, k_str:&str) {
            let mut dk = [0u8;DK_LEN];
            let mut c = [0u8;C_LEN];
            decode_to_slice(dk_str,&mut dk).expect("Decode failure");
            decode_to_slice(c_str,&mut c).expect("Decode failure");
            let mut k = [0u8;32];
            let mut c_ = [0u8;C_LEN];
            let _ = decaps::<K,ETA1_64,ETA2_64,DU_32,DV_32,ZC_LEN>(&dk, &c, &mut k, &mut c_, du, dv);
            assert_eq!(encode_upper(k),k_str);
        }
    }
}