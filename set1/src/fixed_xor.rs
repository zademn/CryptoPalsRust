
use rayon::prelude::*;

pub fn xor(s1b: &[u8], s2b: &[u8]) -> Vec<u8> {
    let s3b: Vec<_> = s1b.par_iter().zip(s2b).map(|(a, b)| a ^ b).collect();
    s3b
}
pub fn xor_hex(s1: &str, s2: &str) -> String {
    let s1b = hex::decode(s1).unwrap();
    let s2b = hex::decode(s2).unwrap();

    let s3: Vec<_> = s1b.par_iter().zip(s2b).map(|(a, b)| a ^ b).collect();

    hex::encode(s3)
}

pub fn challenge2() {
    let s1 = "1c0111001f010100061a024b53535009181c";
    let s2 = "686974207468652062756c6c277320657965";

    println!("{:?}", xor_hex(s1, s2));
    println!(
        "{:?}",
        hex::encode(xor(
            &hex::decode(s1).unwrap(),
            &hex::decode(s2).unwrap()
        ))
    );
}
