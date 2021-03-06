use crate::ctr::CtrMode;
use base64;
use set1::single_byte_xor::single_byte_xor;
use std::fs;
use utils::number::{u8_to_ascii, xor};

pub fn fixed_nonce_ctr_sub(content: &Vec<Vec<u8>>) -> Vec<u8> {
    // content is a list of encrypted ciphertexts under the same key

    // Idea: each position was encrypted using the same byte. Break it with the single_byte_xor

    // get max_len of ciphertexts
    let mut max_len = 0;
    for c in content {
        if c.len() > max_len {
            max_len = c.len();
        }
    }

    let mut keystream: Vec<u8> = Vec::new();
    for i in 0..max_len {
        // construct the string we want to break
        let mut s: Vec<u8> = Vec::new();
        for c in content.iter() {
            if c.len() > i {
                s.push(c[i]);
            }
        }

        let (_, _, b) = single_byte_xor(&s);
        keystream.push(b);
    }
    return keystream;
}
pub fn challenge19_20() {
    // this is for 20 too i guess...

    let content = fs::read_to_string("../files/19.txt").expect("error on reading file");
    //println!("{}", content);
    let content = content.split("\r\n").collect::<Vec<&str>>();
    //println!("{:?}", content);
    let content = content
        .iter()
        .map(|s| base64::decode(s).unwrap())
        .collect::<Vec<Vec<u8>>>();
    // for c in content.iter() {
    //     println!("{:?}", c);
    // }

    let keystream = fixed_nonce_ctr_sub(&content);

    // almost, too lazy to do the trigrams stuff
    for c in content.iter() {
        println!("{}", u8_to_ascii(&xor(&keystream, &c)));
    }
}
