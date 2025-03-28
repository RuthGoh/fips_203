// Check compilation with
// cargo check --lib --no-default-features --target thumbv7m-none-eabi
// cargo check --lib

//! Pure Rust implementation of [FIPS 203](https://doi.org/10.6028/NIST.FIPS.203).
//! 
//! Use with `default-features=false` for no-std.
//! 
#![cfg_attr(feature = "std", doc = r##"
# Example
```
use fips203::{MLKEM_1024, Fips203Rng};

pub fn main() {
    let mut rng = Fips203Rng::default();
    let (ek,dk) = MLKEM_1024::keygen(&mut rng);
    let (k,c) = MLKEM_1024::encaps(&ek, &mut rng).expect("Encapsulation failure");
    let k_prime = MLKEM_1024::decaps(&dk, &c).expect("Decapsulation failure");
    if k != k_prime {panic!("Decapsulation failure")}
}
```
"##)]

//TODO: inline

//TODO
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![allow(non_camel_case_types)]

//use zeroize::Zeroizing;

mod crypto_fns;
mod byte_fns;
mod sample;
mod ntt;
mod kpke;
mod mlkem;

/// Custom errors for the package
#[derive(Debug)]
pub enum Error {
    /// Input failed input checks. Used in `encaps` and `decaps`
    InvalidInput
    //TODO: more
}
impl core::error::Error for Error {}
use core::fmt::{Display, Formatter, Result as fmtResult};
impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmtResult {
        match self {
            Error::InvalidInput => write!(f, "Invalid input, failed input check")
        }
    }
}

const Q: u16 = 3329;
// UNUSED const N: u16 = 256;

//TODO: rng.fill errors
/// Struct defining the Random Bit Generator to be used.
/// 
#[cfg_attr(feature = "std", doc = r##"
# Example
Default RNG
```
# use fips203::Fips203Rng;
let mut rng = Fips203Rng::default();
```
Custom RNG
```
# use fips203::Fips203Rng;
use rand::{prelude::ThreadRng, Rng};

let r = rand::rng();
let f = |rng:&mut ThreadRng| {
    rng.random::<[u8;32]>()
};
let mut rng = Fips203Rng::custom(r, f);
```
"##)]
pub struct Fips203Rng<T> {
    /// A random number generator with type T.
    pub rng: T,
    /// A function which takes in an RNG of type T and returns a randomly-filled 32-byte array.
    pub f: fn(&mut T) -> [u8;32]
}
#[cfg(feature = "std")]
use rand::{prelude::ThreadRng, Rng};
#[cfg(feature = "std")]
impl Default for Fips203Rng<ThreadRng> {
    /// Constructor for default RNG.
    /// 
    /// Not available with `default-features=false`, requires `std`.
    /// 
    /// Uses [rand 0.9.0](`rand`)
    /// 
    /// * `rng` [`rand::rng`], ChaCha12
    /// * `f` [`rand::random`] 
    /// 
    /// [`Default`] documentation.
    fn default() -> Self {
        Fips203Rng::<ThreadRng> {
            rng: rand::rng(),
            f: |rng:&mut ThreadRng| {
                rng.random::<[u8;32]>()
            }
        }
    }
}
impl<T> Fips203Rng<T> {
    /// Constructor for a custom RNG
    /// 
    /// Note that the RBG should have a bit-strength of at least 128 (ML-KEM 512), 192 (ML-KEM 768), or 256 (ML-KEM 1024)
    pub fn custom(r:T, func:fn(&mut T) -> [u8;32]) -> Self {
        Fips203Rng::<T> {
            rng: r,
            f: func
        }
    }
}

macro_rules! impl_mlkem {
    ($name:ident, $k:expr, $eta1:expr, $eta2:expr, $du:expr, $dv:expr) => {
        /// Module for ML-KEM.
        pub mod $name {
            use super::*;

            const EK_LEN:usize = 384*$k+32;
            const DK_LEN:usize = 768*$k+96;
            const C_LEN:usize = 32*($du*$k+$dv);

            /// Generates an encapsulation key and a corresponding decapsulation key.
            /// 
            /// # Arguments
            /// * `rng` An implementation of [`Fips203Rng`]
            /// # Returns
            /// * `(encapsulation key, decapsulation key)`
            pub fn keygen<T>(rng:&mut Fips203Rng<T>) -> ([u8;EK_LEN], [u8;DK_LEN]) {
                let mut ek = [0u8;EK_LEN];
                let mut dk = [0u8;DK_LEN];
                mlkem::keygen::<T, {$k}, {$eta1*64}>(rng, &mut ek, &mut dk);
                (ek,dk)
            }

            /// Uses the encapsulation key to generate a shared secret key and an associated ciphertext.
            /// 
            /// Includes encapsulation key check. If check fails, function returns `Err(InvalidInput)`.
            /// 
            /// # Arguments
            /// * `ek` An encapsulation key
            /// * `rng` An implementation of [`Fips203Rng`]
            /// # Returns
            /// * `Result<(shared secret key, ciphertext), Error>`
            pub fn encaps<T>(ek:&[u8;EK_LEN], rng:&mut Fips203Rng<T>) -> Result<([u8;32],[u8;C_LEN]),Error> {
                let mut k = [0u8;32];
                let mut c = [0u8;C_LEN];
                match mlkem::encaps::
                <T, {$k}, {$eta1*64}, {$eta2*64}, {$du*32}, {$dv*32}>
                (ek, rng, &mut k, &mut c, $du, $dv) {
                    Ok(_) => Ok((k,c)),
                    Err(e) => Err(e)
                }
            }

            /// Uses the decapsulation key to produce a shared secret key from a ciphertext.
            /// 
            /// Includes decapsulation input check. If check fails, function returns `Err(InvalidInput)`.
            /// 
            /// # Arguments
            /// * `dk` A decapsulation key
            /// * `c` A ciphertext
            /// # Returns
            /// * `Result<shared secret key, Error>`
            pub fn decaps(dk:&[u8;DK_LEN], c:&[u8;C_LEN]) -> Result<[u8;32], Error> {
                let mut k = [0u8;32];
                let mut c_ = [0u8;C_LEN];
                match mlkem::decaps::
                <{$k}, {$eta1*64}, {$eta2*64}, {$du*32}, {$dv*32}, {32+32*($du*$k+$dv)}>
                (dk, c, &mut k, &mut c_, $du, $dv) {
                    Ok(_) => Ok(k),
                    Err(e) => Err(e)
                }
            }

            #[cfg(test)]
            mod tests {
                use super::*;

                #[test]
                #[cfg(feature = "std")]
                /// Test a complete run-through of the algorithms.
                fn test_correct() {
                    let mut rng = Fips203Rng::default();
                    for _ in 0..10 {
                        let (ek,dk) = keygen(&mut rng);
                        let (k,c) = encaps(&ek, &mut rng).expect("Encaps fail.");
                        let k_ = decaps(&dk, &c).expect("Decaps fail.");
                        assert_eq!(k,k_);
                    }
                }

                #[test]
                #[cfg(feature = "std")]
                /// Test a complete run-through with a custom RNG.
                fn test_custom_rng() {
                    let mut rng = Fips203Rng::custom((),|rng:&mut ()| {rand::random::<[u8;32]>()});
                    for _ in 0..5 {
                        let (ek,dk) = keygen(&mut rng);
                        let (k,c) = encaps(&ek, &mut rng).expect("Encaps fail.");
                        let k_ = decaps(&dk, &c).expect("Decaps fail.");
                        assert_eq!(k,k_);
                    }
                }

                #[test]
                #[cfg(feature = "std")]
                /// `decaps` should implicitly reject.
                /// Test with a random `c` and a modified `dk`.
                fn test_implicit_reject() {
                    let mut rng = Fips203Rng::default();
                    for _ in 0..5 {
                        let (ek,mut dk) = keygen(&mut rng);
                        let (k,c) = encaps(&ek, &mut rng).expect("Encaps fail.");

                        // create random `c`
                        let c_ = rand::random::<[u8;C_LEN]>();
                        let k_ = decaps(&dk, &c_).expect("Decaps fail.");
                        assert_ne!(k,k_);

                        // modify `dk`
                        for i in 0..10 {dk[i] = 0;}
                        let k_ = decaps(&dk, &c).expect("Decaps fail.");
                        assert_ne!(k,k_);
                    }
                }

                #[test]
                /// Also see `test_compile_fail`.
                fn test_encaps_input_checks() {
                    let mut rng = Fips203Rng::custom((),|rng:&mut ()| {[0u8;32]});
                    let mut ek = [0u8;EK_LEN];
                    let mut tmp = [0u16;256];
                    tmp[0] = 3329;
                    for i in 0..$k {
                        ek[i*384..i*384+384].clone_from_slice(&byte_fns::byte_encode::<{32*12}>(12, &tmp));
                    }
                    match encaps(&ek, &mut rng) {
                        Err(Error::InvalidInput) => (),
                        _ => panic!("encaps did not produce expected error.")
                        
                    }
                }

                #[test]
                /// Also see `test_compile_fail`.
                fn test_decaps_input_checks() {
                    let mut rng = Fips203Rng::custom((),|rng:&mut ()| {[0u8;32]});
                    let (ek,mut dk) = keygen(&mut rng);
                    if dk[384*$k] == 0 {dk[384*$k] = 1;} else {dk[384*$k] = 0;}
                    let (_,c) = encaps(&ek, &mut rng).expect("Encaps fail.");
                    match decaps(&dk, &c) {
                        Err(Error::InvalidInput) => (),
                        _ => panic!("decaps did not produce expected error.")
                    }
                }
            }
            /// Empty function to test code which fails to compile as doc_tests.
            /// 
            /// Test `encaps` input check
            /// ```compile_fail
            /// let mut rng = Fips203Rng::custom((),|rng:&mut ()| {[0u8;32]});
            /// let ek = [0u8;32];
            /// let _ = encaps(&ek, &mut rng).expect("Encaps fail.");
            /// ```
            /// 
            /// 
            /// Test `decaps` input check
            /// ```compile_fail
            /// // Test `c` length check
            /// let c = [0u8;32];
            /// let _ = decaps(&[0u8;DK_LEN], &c).expect("Decaps fail.");
            /// ```
            /// 
            /// ```compile_fail
            /// // Test `dk` length check
            /// let dk = [0u8;32];
            /// let _ = decaps(&dk, &[0u8;C_LEN]).expect("Decaps fail.");
            /// ```
            #[allow(dead_code)]
            fn test_compile_fail() {}
        }
    };
}
impl_mlkem!(MLKEM_512,2,3,2,10,4);
impl_mlkem!(MLKEM_768,3,2,2,10,4);
impl_mlkem!(MLKEM_1024,4,2,2,11,5);