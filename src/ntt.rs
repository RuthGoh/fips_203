/// Pre-calculated values for as shown in Appendix A
// for 17^BitRev7(index) mod 3329
const zeta_lookup: [i32;128] = [
    1,1729,2580,3289,2642,630,1897,848,
    1062,1919,193,797,2786,3260,569,1746,
    296,2447,1339,1476,3046,56,2240,1333,
    1426,2094,535,2882,2393,2879,1974,821,
    289,331,3253,1756,1197,2304,2277,2055,
    650,1977,2513,632,2865,33,1320,1915,
    2319,1435,807,452,1438,2868,1534,2402,
    2647,2617,1481,648,2474,3110,1227,910,
    17,2761,583,2649,1637,723,2288,1100,
    1409,2662,3281,233,756,2156,3015,3050,
    1703,1651,2789,1789,1847,952,1461,2687,
    939,2308,2437,2388,733,2337,268,641,
    1584,2298,2037,3220,375,2549,2090,1645,
    1063,319,2773,757,2099,561,2466,2594,
    2804,1092,403,1026,1143,2150,2775,886,
    1722,1212,1874,1029,2110,2935,885,2154
];
// for 17^(2*BitRev7(index)+1)
// negative values have been replaced, mod 3329
const gamma_lookup: [u32;128] = [
    17, 3312, 2761, 568, 583, 2746, 2649, 680, 
    1637, 1692, 723, 2606, 2288, 1041, 1100, 2229, 
    1409, 1920, 2662, 667, 3281, 48, 233, 3096, 
    756, 2573, 2156, 1173, 3015, 314, 3050, 279, 
    1703, 1626, 1651, 1678, 2789, 540, 1789, 1540, 
    1847, 1482, 952, 2377, 1461, 1868, 2687, 642, 
    939, 2390, 2308, 1021, 2437, 892, 2388, 941, 
    733, 2596, 2337, 992, 268, 3061, 641, 2688, 
    1584, 1745, 2298, 1031, 2037, 1292, 3220, 109, 
    375, 2954, 2549, 780, 2090, 1239, 1645, 1684, 
    1063, 2266, 319, 3010, 2773, 556, 757, 2572, 
    2099, 1230, 561, 2768, 2466, 863, 2594, 735, 
    2804, 525, 1092, 2237, 403, 2926, 1026, 2303, 
    1143, 2186, 2150, 1179, 2775, 554, 886, 2443, 
    1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300, 
    2110, 1219, 2935, 394, 885, 2444, 2154, 1175
];

use crate::Q;

// q=3329
pub fn NTT(f:&[u16]) -> Vec<u16> {
    let mut f: Vec<i32> = f.iter().map(|&e| e as i32).collect();
    let mut len: usize = 128;
    let mut start: usize;
    let mut i: usize = 1;
    // i = 1->128, len = 129
    while len>=2 {
        start = 0;
        let len2 = len<<1;
        while start < 256 {
            for j in start..(start+len) {
                // this block runs 897 times
                let t = (zeta_lookup[i]*f[j+len])%Q as i32;
                f[j+len] = (f[j] as i32 - t as i32)%Q as i32;
                f[j] = (f[j] + t)%Q as i32;
            }
            i += 1;
            start += len2;
        }
        len >>= 1;
    }
    f.iter().map(|&e| e as u16).collect()
}

pub fn NTT_inv(f:&[u16]) -> Vec<u16> {
    let mut f: Vec<i32> = f.iter().map(|&e| e as i32).collect();
    let mut len: usize = 2;
    let mut start: usize;
    let mut i: usize = 127;
    while len <= 128 {
        start = 0;
        while start < 256 {
            for j in start..(start+len) {
                // as above
                let t = f[j];
                f[j] = (t + f[j+len])%Q as i32;
                f[j+len] = (zeta_lookup[i]*(f[j+len]-t))%Q as i32;
            }
            i -= 1;
            start += len<<1;
        }
        len <<= 1;
    }
    for e in f.iter_mut() {*e = (*e*3303)%Q as i32}
    f.iter().map(|&e| e as u16).collect()
}

pub fn multiply_NTTs(vec1:&[u16], vec2:&[u16]) -> Vec<u16> {
    let mut res_vec: Vec<u16> = Vec::with_capacity(256);
    for i in 0..128 {
        let i2 = 2*i;
        res_vec.extend(base_case_multiply(
            vec1[i2] as u32, vec1[i2+1] as u32, 
            vec2[i2] as u32, vec1[i2+1] as u32, 
            gamma_lookup[i])
        );
    }
    res_vec
}

// check output bit length
fn base_case_multiply(a0:u32, a1:u32, b0:u32, b1:u32, gamma:u32) -> Vec<u16> {
    vec![
        ((a0*b0+a1*b1*gamma)%Q as u32) as u16,
        ((a0*b1+a1*b0)%Q as u32) as u16
    ]
}