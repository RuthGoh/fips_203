#![no_std]

mod convert_compress;
mod sample;
mod ntt;
mod kpke;
mod mlkem;
mod crypto_funcs;

const Q: u16 = 3329;
const N: u16 = 256;
const K: usize = 3;
const ETA1: usize = 2;
const ETA2: usize = 2;
const DU: usize = 10;
const DV: usize = 4;

// check SHA3 cryptographically secure
// 'cryptographic module', etc, check all section 3.3

fn main() {
    //println!("Hello, world!");
    /* let param_sets: [[u8;5];3] = [
        [2,3,2,10,4],
        [3,2,2,10,4],
        [4,2,2,11,5]
    ]; */
}