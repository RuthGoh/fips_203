use crate::PARAMS;
use crate::sample::{sample_NTT, sample_poly_CBD};
use crate::crypto_funcs::{g, prf};
use crate::ntt::{NTT, NTT_inv, multiply_NTTs};
use crate::convert_compress::{byte_encode, byte_decode, compress, decompress};

fn mul_mat_vec(m:&Vec<Vec<Vec<u16>>>, v:&Vec<Vec<u16>>, t:bool) -> Vec<Vec<u16>>{
    let l = m.len();
    let mut res: Vec<Vec<u16>> = Vec::with_capacity(l);
    for i in 0..l {
        res.push(vec![0;l]);
        for j in 0..l {
            let temp = multiply_NTTs(
                // if transpose = true, swap i and j
                if t {&m[j][i]} else {&m[i][j]}, &v[j]
            );
            for x in 0..l {
                res[i][x] += temp[x];
            }
        }
    }
    res
}
fn add_vecs(l:Vec<&Vec<Vec<u16>>>) -> Vec<Vec<u16>> {
    let l1 = l[0].len();
    let l2 = l[0][0].len();
    let mut res:Vec<Vec<u16>> = Vec::with_capacity(l1);
    for i in 0..l1 {
        res.push(vec![0;l2]);
        for j in 0..l2 {
            res[i][j] = {
                let mut acc:u16 = 0;
                for x in 0..l.len() {
                    acc += l[x][i][j];
                }
                acc
            }
        }
    }
    res
}

pub fn keygen(mut d:Vec<u8>) -> (Vec<u8>,Vec<u8>) {
    let k = PARAMS[0] as u8;
    let mut a: Vec<Vec<Vec<u16>>> = Vec::with_capacity(PARAMS[0]);
    let mut s: Vec<Vec<u16>> = Vec::with_capacity(PARAMS[0]);
    let mut e: Vec<Vec<u16>> = Vec::with_capacity(PARAMS[0]);

    d.push(k);
    let hash = g(&d);
    let hash: Vec<&[u8]> = hash.chunks_exact(32).collect(); // roe = hash[0], sigma = hash[1]
    let mut roe: Vec<u8> = hash[0].to_vec();
    // push values for j,i onto roe
    // roe will keep track of i,j
    roe.push(0); roe.push(0);
    for i in 0..k {
        // push empty vector with capacity k to put j0 to j(k-1) in
        a.push(Vec::with_capacity(PARAMS[0]));
        roe[32] = 0;
        for j in 0..k {
            a[i as usize].push(sample_NTT(&roe));
            roe[32] += 1;
        }
        roe[33] += 1;
    }

    let mut sigma_n = hash[1].to_vec();
    sigma_n.push(0); // the last element of the vector keeps count of N
    for _ in 0..PARAMS[0] {
        s.push(NTT(&sample_poly_CBD(k, &prf(PARAMS[1],&sigma_n))));
        sigma_n[32] += 1;
    }
    for _ in 0..PARAMS[0] {
        e.push(NTT(&sample_poly_CBD(k, &prf(PARAMS[1],&sigma_n))));
        sigma_n[32] += 1;
    }

    for i in s.iter_mut() {*i = NTT(i)};
    for i in e.iter_mut() {*i = NTT(i)};
    /* let mut t: Vec<Vec<u32>> = Vec::with_capacity(PARAMS[0]);
    for i in 0..PARAMS[0] {
        t.push(vec![0;PARAMS[0]]);
        for j in 0..PARAMS[0] {
            let temp = multiply_NTTs(&a[i][j], &s[j]);
            for x in 0..PARAMS[0] {
                t[i][x] += temp[x];
            }
        }
        for j in 0..PARAMS[0] {
            t[i][j] += e[i][j] as u32;
        }
    } */
    let t = add_vecs(vec![&mul_mat_vec(&a, &s, false), &e]);

    let mut dk: Vec<u8> = Vec::with_capacity(384*PARAMS[0]);
    for i in 0..PARAMS[0] {
        Vec::append(&mut dk, &mut byte_encode(12, &t[i]));
    }
    let mut ek1: Vec<u8> = Vec::with_capacity(384*PARAMS[0]+32);
    for i in 0..PARAMS[0] {
        Vec::append(&mut ek1, &mut byte_encode(12, &s[i]));
    }
    ([ek1,hash[0].to_vec()].concat(), dk)
}

pub fn encrypt(ek:&[u8], m:&[u8], mut r:Vec<u8>) -> Vec<u8> {
    let mut t: Vec<Vec<u16>> = Vec::with_capacity(PARAMS[0]);
    let mut a: Vec<Vec<Vec<u16>>> = Vec::with_capacity(PARAMS[0]);
    let mut y: Vec<Vec<u16>> = Vec::with_capacity(PARAMS[0]);
    let mut e1: Vec<Vec<u16>> = Vec::with_capacity(PARAMS[0]);

    for i in 0..PARAMS[0] {
        t.push(byte_decode(12, &ek[PARAMS[0]*i..PARAMS[0]*i+384]));
    }
    let mut roe: Vec<u8> = ek[384*PARAMS[0]..384*PARAMS[0]+32].to_vec();
    // push values for j,i onto roe
    // roe will keep track of i,j
    roe.push(0); roe.push(0);
    for i in 0..PARAMS[0] {
        // push empty vector with capacity k to put j0 to j(k-1) in
        a.push(Vec::with_capacity(PARAMS[0]));
        roe[32] = 0;
        for j in 0..PARAMS[0] as u8 {
            a[i].push(sample_NTT(&roe));
            roe[32] += 1;
        }
        roe[33] += 1;
    }

    r.push(0); // the last element of the vector keeps count of N
    for _ in 0..PARAMS[0] {
        y.push(sample_poly_CBD(PARAMS[1] as u8, &prf(PARAMS[1],&r)));
        r[32] += 1;
    }
    for _ in 0..PARAMS[0] {
        e1.push(sample_poly_CBD(PARAMS[2] as u8, &prf(PARAMS[2],&r)));
        r[32] += 1;
    }

    let e2 = sample_poly_CBD(PARAMS[2] as u8, &prf(PARAMS[2],&r));
    let mut y_ = Vec::with_capacity(PARAMS[0]);
    for i in 0..PARAMS[0] {
        y_.push(NTT(&y[i]));
    }
    /* // transpose a
    for i in 0..PARAMS[0] {
        for j in 0..PARAMS[0] {
            let temp = a[i][j];
            a[i][j] = a[j][i];
            a[j][i] = temp;
        }
    } */
    /* let mut u: Vec<Vec<u32>> = Vec::with_capacity(PARAMS[0]);
    for i in 0..PARAMS[0] {
        let mut u_acc = vec![0;PARAMS[0]];
        for j in 0..PARAMS[0] {
            let temp = multiply_NTTs(&a[i][j], &y[j]);
            for x in 0..PARAMS[0] {
                u_acc[x] += temp[x];
            }
        }
        u.push(NTT_inv(&u_acc));
        for j in 0..PARAMS[0] {
            u[i][j] += e1[i][j] as u32;
        }
    } */
    let u = add_vecs(vec![&mul_mat_vec(&a, &y_, true), &e1]);
    let mu = decompress(1, &mut byte_decode(1, m));

    /* // transpose t
    for i in 0..PARAMS[0] {
        for j in 0..PARAMS[0] {
            let temp = t[i][j];
            t[i][j] = t[j][i];
            t[j][i] = temp;
        }
    }
    let mut v: Vec<Vec<u32>> = Vec::with_capacity(PARAMS[0]);
    for i in 0..PARAMS[0] {
        let v_acc = vec![0;PARAMS[0]];
        let temp = multiply_NTTs(&t[i], &y[i]);
        for j in 0..PARAMS[0] {
            v_acc[j] += temp[j];
        }
        NTT_inv(&v_acc);
/*         for j in 0..PARAMS[0] {
            v[i][j] += e[i][j] as u32;
        } */
    }
    multiply_NTTs(&t, &y_);
    let mut v = NTT_inv(&multiply_NTTs(&t, &y_));
    */
    let l = t.len();
    for i in 0..l {
        for j in 0..l {
            let temp = t[i][j];
            t[i][j] = t[j][i];
            t[j][i] = temp;
        }
    }
    let mut v = Vec::with_capacity(l);
    for i in 0..l {
        v.push(NTT_inv(&multiply_NTTs(&t[i], &y_[i])));
    }
    for i in 0..l {
        v[i] += e2[i] + mu[i];
    }

    let c1 = byte_encode(PARAMS[3] as u8,compress(PARAMS[3], &mut u));
    let c2 = byte_encode(PARAMS[4] as u8,compress(PARAMS[4], &mut v));
    [c1,c2].concat()
}

pub fn decrypt(dk:&[u8], c:&[u8]) -> Vec<u8> {
    let mut u: Vec<Vec<u16>> = Vec::with_capacity(PARAMS[0]);
    let du = PARAMS[3] as u8;
    for i in 0..PARAMS[0] {
        u.push(decompress(du, &byte_decode(du, &c[i*32*PARAMS[3]..i*32*PARAMS[3]+32*PARAMS[3]])));
    }
    let v = decompress(PARAMS[4] as u8, &byte_decode(PARAMS[4] as u8, &c[32*PARAMS[3]*PARAMS[0]..32*(PARAMS[3]*PARAMS[0]+PARAMS[4])]));
    let mut s: Vec<Vec<u16>> = Vec::with_capacity(PARAMS[0]);
    for i in 0..PARAMS[0] {
        s.push(byte_decode(12, &dk[i*32*12..i*32*12+32*12]));
    }
    // transpose s
    for i in 0..PARAMS[0] {
        for j in 0..PARAMS[0] {
            let temp = s[i][j];
            s[i][j] =  s[j][i];
            s[j][i] = temp;
        }
    }
    let mut w = NTT_inv(&multiply_NTTs(s, &NTT(u)));
    for i in 0..w.len() {
        w[i] = v[i] - w[i];
    }
    compress(1, &mut w);
    byte_encode(1, &w);
}