// Check compilation with
// cargo check --lib --no-default-features --target thumbv7m-none-eabi
// cargo check --lib

//! DO NOT USE. SECURITY CANNOT BE GUARANTEED.
//! 
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
    let (k,c) = MLKEM_1024::encaps(ek, &mut rng).expect("Encapsulation failure");
    let k_prime = MLKEM_1024::decaps(dk, c).expect("Decapsulation failure");
    if k != k_prime {panic!("Decapsulation failure")}
}
```
"##)]

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![allow(non_camel_case_types)]

mod crypto_fns;
mod byte_fns;
mod sample;
mod ntt;
mod kpke;
mod mlkem;
mod types;
use types::{Z,S};

/// Custom errors for the package
#[derive(Debug)]
pub enum Error {
    /// Input failed input checks. Used in `encaps` and `decaps`.
    InvalidInput
}
impl core::error::Error for Error {}
use core::{array, fmt::{Display, Formatter, Result as fmtResult}};
impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmtResult {
        match self {
            Error::InvalidInput => write!(f, "Invalid input, failed input check")
        }
    }
}

const Q: u16 = 3329;
// UNUSED const N: u16 = 256;

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
    rng: T,
    /// A function which takes in an RNG of type T and returns a randomly-filled 32-byte array.
    f: fn(&mut T) -> [u8;32],
    /// A private function which converts `[u8;32]` to `[S;32]`. Must also zero byte-array.
    g: fn(&mut [u8;32]) -> [S;32]
}
const G:fn(&mut [u8;32]) -> [S;32] = |r:&mut [u8;32]| {
    let a: [S; 32] = array::from_fn(|i| S(r[i]));
    r.zeroize();
    a
};
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
            },
            g: G
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
            f: func,
            g: G
        }
    }
}

use zeroize::Zeroize;
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
                mlkem::keygen::<T, {$k}, {$eta1*64}, EK_LEN>(rng, &mut ek, &mut dk);
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
            pub fn encaps<T>(mut ek:[u8;EK_LEN], rng:&mut Fips203Rng<T>) -> Result<([u8;32],[u8;C_LEN]),Error> {
                let ek_s = types::bytes_to_ss::<EK_LEN>(&ek);
                ek.zeroize();
                let mut k = [0u8;32];
                let mut c: [S;C_LEN] = core::array::from_fn(|_| S(0));
                match mlkem::encaps::
                <T, {$k}, {$eta1*64}, {$eta2*64}, {$du*32}, {$dv*32}, EK_LEN>
                (&ek_s, rng, &mut k, &mut c, $du, $dv) {
                    Ok(_) => Ok((k,types::ss_to_bytes(&c))),
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
            pub fn decaps(mut dk:[u8;DK_LEN], mut c:[u8;C_LEN]) -> Result<[u8;32], Error> {
                let dk_s = types::bytes_to_ss::<DK_LEN>(&dk);
                dk.zeroize();
                let c_s = types::bytes_to_ss::<C_LEN>(&c);
                c.zeroize();
                let mut k = [0u8;32];
                let mut c_:[S;C_LEN] = core::array::from_fn(|_| S(0));
                match mlkem::decaps::
                <{$k}, {$eta1*64}, {$eta2*64}, {$du*32}, {$dv*32}, {32+32*($du*$k+$dv)}, {384*$k+32}>
                (&dk_s, &c_s, &mut k, &mut c_, $du, $dv) {
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
                        let (k,c) = encaps(ek, &mut rng).expect("Encaps fail.");
                        let k_ = decaps(dk, c).expect("Decaps fail.");
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
                        let (k,c) = encaps(ek, &mut rng).expect("Encaps fail.");

                        // create random `c`
                        let c_ = rand::random::<[u8;C_LEN]>();
                        let k_ = decaps(dk, c_).expect("Decaps fail.");
                        assert_ne!(k,k_);

                        // modify `dk`
                        for i in 0..10 {dk[i] = 0;}
                        let k_ = decaps(dk, c).expect("Decaps fail.");
                        assert_ne!(k,k_);
                    }
                }

                #[test]
                /// Test a complete run-through with a custom RNG.
                fn test_custom_rng() {
                    let mut rng = Fips203Rng::custom((),|_rng:&mut ()| {[0u8;32]});
                    let (ek,dk) = keygen(&mut rng);
                    let (k,c) = encaps(ek, &mut rng).expect("Encaps fail.");
                    let k_ = decaps(dk, c).expect("Decaps fail.");
                    assert_eq!(k,k_);
                }

                #[test]
                /// Also see `test_compile_fail`.
                fn test_encaps_input_checks() {
                    let mut rng = Fips203Rng::custom((),|_rng:&mut ()| {[0u8;32]});
                    let mut ek = [0u8;EK_LEN];
                    let mut tmp: [Z;256] = core::array::from_fn(|_| Z(0));
                    tmp[0] = Z(3329);
                    for i in 0..$k {
                        ek[i*384..i*384+384].clone_from_slice(&types::ss_to_bytes::<384>(&byte_fns::byte_encode::<{32*12}>(12, &tmp)));
                    }
                    match encaps(ek, &mut rng) {
                        Err(Error::InvalidInput) => (),
                        _ => panic!("encaps did not produce expected error.")
                        
                    }
                }

                #[test]
                /// Also see `test_compile_fail`.
                fn test_decaps_input_checks() {
                    let mut rng = Fips203Rng::custom((),|_rng:&mut ()| {[0u8;32]});
                    let (ek,mut dk) = keygen(&mut rng);
                    if dk[384*$k] == 0 {dk[384*$k] = 1;} else {dk[384*$k] = 0;}
                    let (_,c) = encaps(ek, &mut rng).expect("Encaps fail.");
                    match decaps(dk, c) {
                        Err(Error::InvalidInput) => (),
                        _ => panic!("decaps did not produce expected error.")
                    }
                }
            }
            /// Empty function to test code which fails to compile as doc_tests.
            /// 
            /// Test `encaps` input check
            /// ```compile_pass
            /// use fips203::{MLKEM_512,Fips203Rng};
            /// let mut rng = Fips203Rng::custom((),|_rng:&mut ()| {[0u8;32]});
            /// let ek = [0u8;384*2+32];
            /// let _ = encaps(ek, &mut rng).expect("Encaps fail.");
            /// ```
            /// ```compile_fail
            /// use fips203::{MLKEM_512,Fips203Rng};
            /// let mut rng = Fips203Rng::custom((),|_rng:&mut ()| {[0u8;32]});
            /// let ek = [0u8;32];
            /// let _ = encaps(ek, &mut rng).expect("Encaps fail.");
            /// ```
            /// 
            /// 
            /// Test `decaps` input check
            /// ```compile_pass
            /// // Test `c` length check
            /// use fips203::MLKEM_512;
            /// let _ = decaps([0u8;768*2+96], [0u8;32*(10*2+4)]).expect("Decaps fail.");
            /// ```
            /// ```compile_fail
            /// // Test `c` length check
            /// use fips203::MLKEM_512;
            /// let _ = decaps([0u8;768*2+96], [0u8;32]).expect("Decaps fail.");
            /// ```
            /// 
            /// ```compile_pass
            /// // Test `dk` length check
            /// use fips203::MLKEM_512;
            /// let _ = MLKEM_1024::decaps([0u8;768*2+96], [0u8;32*(10*2+4)]).expect("Decapsulation failure");
            /// ```
            /// ```compile_fail
            /// // Test `dk` length check
            /// use fips203::MLKEM_512;
            /// let _ = MLKEM_1024::decaps([0u8;32], [0u8;32*(10*2+4)]).expect("Decapsulation failure");
            /// ```
            #[allow(dead_code)]
            fn test_compile_fail() {}
        }
    };
}
impl_mlkem!(MLKEM_512,2,3,2,10,4);
impl_mlkem!(MLKEM_768,3,2,2,10,4);
impl_mlkem!(MLKEM_1024,4,2,2,11,5);