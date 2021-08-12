use rayon::prelude::*;

pub fn repeated_xor_hex(s1: &str, s2: &str) -> String {
    let s1_dec = hex::decode(s1).unwrap();
    let s2_dec = hex::decode(s2).unwrap();

    let l1 = s1_dec.len();
    let l2 = s2_dec.len();
    let s3: Vec<_> = (0..l1)
        .into_par_iter()
        .map(|i| &s1_dec[i] ^ &s2_dec[i % l2])
        .collect();

    hex::encode(s3)
}

pub fn challenge5() {
    let s1 =
        hex::encode("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
    let s2 = hex::encode("ICE");

    println!("{:?}", repeated_xor_hex(&s1, &s2));
}
