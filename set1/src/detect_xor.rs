use crate::single_byte_xor;

use rayon::prelude::*;

use std::error::Error;

pub fn challenge4() -> Result<(), Box<dyn Error>> {
    println!("Fetching data...");
    let recv =
        reqwest::blocking::get("https://cryptopals.com/static/challenge-data/4.txt")?.text()?;
    let recv_split: Vec<_> = recv.split('\n').collect();

    println!("Calculating...");
    // Find the string with the smallest score
    /*Normal solve*/
    // let mut scores: Vec<(String, f64, u8)> = Vec::new();
    // for line in recv_split.iter() {
    //     let (s, score, k) = single_byte_xor::single_byte_xor(&hex::decode(line).unwrap());
    //     scores.push((s, score, k));
    // }

    /*One liner*/
    let mut scores: Vec<_> = recv_split
        .par_iter()
        .map(|line| single_byte_xor::single_byte_xor(&hex::decode(line).unwrap()))
        .collect();
    scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    println!("Found: {}", scores[0].0);
    Ok(())
}
