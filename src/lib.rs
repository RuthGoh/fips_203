// cargo check --lib --no-default-features --target thumbv7m-none-eabi
// cargo check --lib

//TODO: inline

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

//TODO: consider a no_std/std mod
#[cfg(not(feature = "std"))]
use core::panic::PanicInfo;
#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

mod crypto_fns;
mod byte_fns;
mod sample;
mod ntt;
mod kpke;
mod mlkem;

// errors
#[derive(Debug)]
pub enum Error {
    DecapsulationFailure,
    InvalidKey
    //TODO: more
}
impl core::error::Error for Error {}
use core::fmt::{Display, Formatter, Result as fmtResult};
impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmtResult {
        match self {
            Error::DecapsulationFailure => write!(f,"Decapsulation Failure"),
            Error::InvalidKey => write!(f, "Invalid Key")
        }
    }
}

const Q: u16 = 3329;
// UNUSED const N: u16 = 256;

//TODO: rng.fill errors
// rng
pub struct Fips203Rng<T> {
    rng: T,
    f: fn(&mut T) -> [u8;32]
}
// constructor for default rng
// requires std
#[cfg(feature = "std")]
use rand::{prelude::ThreadRng, Rng};
#[cfg(feature = "std")]
impl Default for Fips203Rng<ThreadRng> {
    fn default() -> Self {
        Fips203Rng::<ThreadRng> {
            rng: rand::rng(),
            f: |rng:&mut ThreadRng| {
                let mut m = [0u8;32];
                rng.fill(&mut m);
                m
            }
        }
    }
}
// constructor for custom rng
impl<T> Fips203Rng<T> {
    pub fn new(r:T, func:fn(&mut T) -> [u8;32]) -> Self {
        Fips203Rng::<T> {
            rng: r,
            f: func
        }
    }
}

trait MlkemT {
    const K: usize;
    const ETA1: usize;
    const ETA2: usize;
    const DU: usize;
    const DV: usize;

    const EK_LEN:usize = 384*Self::K+32;
    const DK_LEN:usize = 768*Self::K+96;
    const C_LEN:usize = 32*(Self::DU*Self::K+Self::DV);
}
macro_rules! impl_mlkem {
    ($name:ident, $k:expr, $eta1:expr, $eta2:expr, $du:expr, $dv:expr) => {
        pub struct $name {}
        impl MlkemT for $name {
            const K: usize = $k;
            const ETA1: usize = $eta1;
            const ETA2: usize = $eta2;
            const DU: usize = $du;
            const DV: usize = $dv;
        }
        impl $name {
            pub fn keygen<T>(rng:&mut Fips203Rng<T>) -> ([u8;Self::EK_LEN], [u8;Self::DK_LEN]) {
                let mut ek = [0u8;Self::EK_LEN];
                let mut dk = [0u8;Self::DK_LEN];
                mlkem::keygen::<T, {$k}, {$eta1*64}>(rng, &mut ek, &mut dk);
                (ek,dk)
            }
            pub fn encaps<T>(ek:&[u8;Self::EK_LEN], rng:&mut Fips203Rng<T>) -> Result<([u8;32],[u8;Self::C_LEN]),Error> {
                let mut k = [0u8;32];
                let mut c = [0u8;Self::C_LEN];
                match mlkem::encaps::
                <T, {$k}, {$eta1*64}, {$eta2*64}, {$du*32}, {$dv*32}>
                (ek, rng, &mut k, &mut c, Self::DU as u8, Self::DV as u8) {
                    Ok(_) => Ok((k,c)),
                    Err(e) => Err(e)
                }
            }
            pub fn decaps(dk:&[u8;Self::DK_LEN], c:&[u8;Self::C_LEN]) -> Result<[u8;32], Error> {
                let mut k = [0u8;32];
                let mut c_ = [0u8;Self::C_LEN];
                match mlkem::decaps::
                <{$k}, {$eta1*64}, {$eta2*64}, {$du*32}, {$dv*32}, {32+32*($du*$k+$dv)}>
                (dk, c, &mut k, &mut c_, $du as u8, $dv as u8) {
                    Ok(_) => Ok(k),
                    Err(e) => Err(e)
                }
            } 
        }
    };
}
impl_mlkem!(MLKEM_512,2,3,2,10,4);
impl_mlkem!(MLKEM_768,3,2,2,10,4);
impl_mlkem!(MLKEM_1024,4,2,2,11,5);