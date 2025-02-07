mod convert_compress;
mod sample;
mod ntt;
mod kpke;
mod mlkem;
mod crypto_funcs;

//use std::sync::Mutex;
//use once_cell::sync::OnceCell;

const Q: u16 = 3329;
const N: u16 = 256;
// k, 𝜂1, 𝜂2, 𝑑𝑢, and 𝑑v
static PARAMS: [usize;5] = [3,2,2,10,4]; // as usize?
//static PARAMS: OnceCell<Mutex<[u8;5]>> = OnceCell::new();

// check SHA3 cryptographically secure
// 'cryptographic module', etc, check all section 3.3

fn main() {
    println!("Hello, world!");
    // Parameter Sets
    // In order: k, n1, n2, du, dv
    /* let param_sets: [[u8;5];3] = [
        [2,3,2,10,4],
        [3,2,2,10,4],
        [4,2,2,11,5]
    ];
    PARAMS.set(Mutex::new(param_sets[0])); */
}