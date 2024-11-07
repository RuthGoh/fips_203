use crate::convert_compress::bytes_to_bits;

fn sample_NTT(seed_vec:&Vec<u8>) -> Vec<u16> {
    Vec::new()
}

// q=3329
fn sample_poly_CBD(eta:u8, seed_vec:&Vec<u8>) -> Vec<u16> {
    let eta = eta as usize;
    let mut sample_vec: Vec<u16> = Vec::with_capacity(256);
    sample_vec.extend(
        bytes_to_bits(seed_vec).into_iter().map(|e| e as u16).collect::<Vec<u16>>()
        .chunks_exact(eta*2).map(
            |chunk| -> u16{
                let mut it = chunk.iter();
                (it.by_ref().take(eta).sum::<u16>() - it.sum::<u16>())%3329
            }
    ));
    sample_vec
}