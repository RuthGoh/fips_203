use fips203::{MLKEM_1024, Fips203Rng};

pub(crate) fn main() {
    let mut def_rng = Fips203Rng::default();
    use rand::{prelude::ThreadRng, Rng};
    let mut rng = Fips203Rng::new(rand::rng(), |rng:&mut ThreadRng| {
        let mut m = [0u8;32];
        rng.fill(&mut m);
        m
    });

    let (ek,dk) = MLKEM_1024::keygen(&mut rng);
    let (k,c) = match MLKEM_1024::encaps(&ek, &mut rng) {
        Ok(x) => x,
        Err(e) => panic!("{}",e)
    };
    let k_ = match MLKEM_1024::decaps(&dk, &c) {
        Ok(x) => x,
        Err(e) => panic!("{}",e)
    };
    if k != k_ {panic!("Decapsulation failure")}
}