use base64;
use hex;
use itertools::Itertools;
use reqwest;
use std::error::Error;

pub fn detect_ecb(s: &[u8]) -> bool {
    let s_split = s.chunks(16); // split in chunks of 16B
                                // check if 2 are equal
    for pair in s_split.combinations(2) {
        if pair[0] == pair[1] {
            return true;
        }
    }
    return false;
}
pub fn challenge8() -> Result<(), Box<dyn Error>> {
    let recv =
        reqwest::blocking::get("https://cryptopals.com/static/challenge-data/8.txt")?.text()?;
    let recv_split: Vec<_> = recv.split("\n").map(|x| hex::decode(x).unwrap()).collect(); //split the strings
    let recv_split = recv_split[..recv_split.len() - 1].to_vec(); // eliminate the whitespace

    for (i, s) in recv_split.iter().enumerate() {
        if detect_ecb(s) {
            //i = 132
            println!("{}", i);
            break;
        }
    }

    return Ok(());
}
