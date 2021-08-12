use rayon::prelude::*;
use crate::single_byte_xor;
use itertools::Itertools;
use std::collections::VecDeque;
use std::error::Error;

#[allow(dead_code)]
fn hamming_distance_string(s1b: &[u8], s2b: &[u8]) -> u32 {
    let ham = s1b
        .par_iter()
        .zip(s2b)
        .map(|(a, b)| (a ^ b).count_ones())
        .sum();

    ham
}



pub fn challenge6() -> Result<(), Box<dyn Error>> {
    let s1 = "this is a test";
    let s2 = "wokka wokka!!!";
    println!(
        "{:?}",
        hamming_distance_string(&s1.as_bytes(), &s2.as_bytes())
    );

    // get text
    let recv =
        reqwest::blocking::get("https://cryptopals.com/static/challenge-data/6.txt")?.text()?;
    let recv_split: Vec<_> = recv.split('\n').collect(); //split the strings

    // decode b64 strings
    let encrypted: Vec<_> = recv_split[0..recv_split.len() - 1]
        .iter()
        .map(|s| base64::decode(s).unwrap())
        .flatten()
        .collect(); // split into bytes

    let mut hams: Vec<(u8, f64)> = Vec::new();
    println!("Computing keysize...");
    for keysize in 2..42 {
        let chunks: Vec<_> = (0..4)
            .map(|i| &encrypted[i * keysize..i * keysize + keysize])
            .collect();
        //println!("{:?}", chunks);
        let mut ham = 0;
        for pair in chunks.iter().combinations(2) {
            ham += hamming_distance_string(&pair[0], &pair[1]);
        }

        let ham_mean = (ham as f64) / 6_f64;
        let ham_mean = ham_mean / (keysize as f64);
        hams.push((keysize as u8, ham_mean));
    }
    hams.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

    //println!("{:?}", hams);
    // take 4 keys
    println!("Breaking keys...");
    for (keysize, _) in hams[..4].iter() {
        let mut key: VecDeque<u8> = VecDeque::new();

        let keysize = (*keysize) as usize;
        let chunks: Vec<_> = (0..encrypted.len() - keysize)
            .step_by(keysize)
            .map(|i| &encrypted[i..i + keysize])
            .collect();
        //println!("{:?}", chunks);

        for i in 0..keysize {
            let mut chunk_tp = Vec::new();
            for chunk in chunks.iter() {
                chunk_tp.push(chunk[i])
            }

            let (_, _, key_byte) = single_byte_xor::single_byte_xor(&chunk_tp);
            key.push_back(key_byte);
        }
        let key: Vec<_> = key.iter().map(|x| *x as u8).collect();
        println!("{:?}", std::str::from_utf8(&key).unwrap());
    }
    Ok(())
}
