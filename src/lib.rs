// cargo check --lib --no-default-features --target thumbv7m-none-eabi
// cargo check --lib

//TODO: inline

#![cfg_attr(not(feature = "std"), no_std)]
#![no_main]
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
/* const K: usize = 2;
const ETA1: usize = 3;
const ETA2: usize = 2;
const DU: usize = 10;
const DV: usize = 4; */

// rng
use rand_chacha::ChaCha20Rng;
use rand_core::{SeedableRng, RngCore};
pub struct Rng<T> {
    rng: T,
    f: fn(&mut T, &mut [u8;32])
}
/* fn test() {
    let r = ChaCha20Rng::from_os_rng();
    fn func(rng:&mut ChaCha20Rng, m:&mut [u8;32]) {RngCore::fill_bytes(rng, m);}
    let mut rng = Rng::<ChaCha20Rng>{
        rng: r,
        f: func
    };
    let mut a = [0u8;32];
    (rng.f)(&mut rng.rng, &mut a);
} */
/* #[cfg(not(feature = "std"))]
fn get_rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(3810201380398309218u64)
}
#[cfg(feature = "std")]
fn test_get_rng() -> Result<ChaCha20Rng, getrandom::Error> {
    ChaCha20Rng::try_from_os_rng()
}
#[cfg(feature = "std")]
fn get_rng() -> ChaCha20Rng {
    match ChaCha20Rng::try_from_os_rng() {
        Ok(x) => x,
        Err(_) => panic!("Failed to generate random numbers."),
    }
} */

trait MlkemT {
    const K: usize;
    const ETA1: usize;
    const ETA2: usize;
    const DU: usize;
    const DV: usize;
    // rng type instead of struct?

    fn new(&self) -> Self where Self:Sized;
    //fn with_rng(&self) -> Self where Self:Sized;

    fn keygen(&self) -> ([u8;384*K+32],[u8;768*K+96]) where Self:Sized {
        mlkem::keygen(rng)
    }
    fn encaps<T>(&self, ek:&[u8;384*K+32]) -> Result<([u8;32],[u8;32*(DU*K+DV)]),Error> {
        mlkem::encaps(ek, rng)
    }
    fn decaps(&self, dk:&[u8;768*K+96], c:&[u8;32*(DU*K+DV)]) -> Result<[u8;32], Error> {
        mlkem::decaps(dk, c)
    }
}
pub struct MLKEM_512 {
    //rng: Rng<T>
    //TODO: rng bit security level
}
impl MlkemT for MLKEM_512 {
    const K: usize = 2;
    const ETA1: usize = 3;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;

    fn new(&self) -> Self where Self:Sized {MLKEM_512{}}
}
/* pub struct MLKEM_768 {}
impl MlkemT for MLKEM_768 {
    const K: usize = 3;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
}
pub struct MLKEM_1024 {}
impl MlkemT for MLKEM_1024 {
    const K: usize = 4;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 11;
    const DV: usize = 5;
} */

trait TestT {
    const K:usize;
    fn testfn()->u8;
}
enum Test {
    A(Test1),
}
struct Test1 {}
impl TestT for Test1 {
    const K:usize = 3;
    fn testfn()->u8 {1}
}
impl Test {
    fn t() -> Self {
        Test::A(Test1 {})
    }
}