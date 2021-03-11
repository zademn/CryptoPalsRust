use rand::Rng;
use rayon::prelude::*;
pub fn u8_to_ascii(s: &[u8]) -> String {
    return s.iter().map(|x| *x as char).collect::<String>();
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let res = (0..n).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
    return res;
}

pub fn xor(s1: &[u8], s2: &[u8]) -> Vec<u8> {
    let s3: Vec<u8> = s1.par_iter().zip(s2).map(|(a, b)| a ^ b).collect();
    return s3;
}
