
use lazy_static::lazy_static;
use rayon::prelude::*;
use std::collections::HashMap;

lazy_static! {
    static ref CHARACTER_FREQ: HashMap<char, f64> = [
        ('a', 0.0651738),
        ('b', 0.0124248),
        ('c', 0.0217339),
        ('d', 0.0349835),
        ('e', 0.1041442),
        ('f', 0.0197881),
        ('g', 0.0158610),
        ('h', 0.0492888),
        ('i', 0.0558094),
        ('j', 0.0009033),
        ('k', 0.0050529),
        ('l', 0.0331490),
        ('m', 0.0202124),
        ('n', 0.0564513),
        ('o', 0.0596302),
        ('p', 0.0137645),
        ('q', 0.0008606),
        ('r', 0.0497563),
        ('s', 0.0515760),
        ('t', 0.0729357),
        ('u', 0.0225134),
        ('v', 0.0082903),
        ('w', 0.0171272),
        ('x', 0.0013692),
        ('y', 0.0145984),
        ('z', 0.0007836),
        (' ', 0.1918182)
    ]
    .iter()
    .cloned()
    .collect();
}

fn score_string(s: &str) -> f64 {
    let score: f64 = s
        .par_chars()
        .map(|c| {
            let mut x = c;
            if ('A'..='Z').contains(&x) {
                x = (x as u8 + 32) as char;
            }
            if ('a'..='z').contains(&x) || x == ' ' {
                CHARACTER_FREQ[&x]
            } else {
                0.
            }
        })
        .sum();

    score
}
pub fn single_byte_xor(s: &[u8]) -> (String, f64, u8) {
    //println!("{}", CHARACTER_FREQ[&'a']);
    //let s = hex::decode(s).unwrap();

    let mut s2: String = String::from("");
    let mut max_score = 0.;
    let mut key = 0;
    for i in 0..255 {
        let m: String = s.par_iter().map(|a| (a ^ i) as char).collect();
        let sc = score_string(&m);

        //println!("{}", score_string(&m));
        //println!("{}", m);

        if sc > max_score {
            max_score = sc;
            s2 = m;
            key = i;
        }
    }
    //println!("{}", s2);
    (s2, max_score, key)
}

pub fn challenge3() {
    let s = hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
        .unwrap();
    //Cooking MC's like a pound of bacon
    let (good_str, score, key) = single_byte_xor(&s);
    println!("{}, {}, {}", good_str, score, key);
}
