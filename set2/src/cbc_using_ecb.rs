use reqwest;

use crate::oracle::Encrypt;
use crate::pkcs7_padding::{pkcs7_pad, pkcs7_unpad};
use base64;
use rand::Rng;
use set1::aes_ecb::{aes_decrypt, aes_encrypt};
use set1::fixed_xor::xor;
use std::{env::temp_dir, error::Error};
use utils::number::u8_to_ascii;
pub struct CbcOracle {
    key: Vec<u8>,
}

impl CbcOracle {
    pub fn new(key: Option<&[u8]>) -> CbcOracle {
        let mut temp_key;
        match key {
            Some(key) => temp_key = key.to_vec(),
            None => {
                let mut rng = rand::thread_rng();
                temp_key = (0..16).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
            }
        }
        return CbcOracle { key: temp_key };
    }
    pub fn decrypt(&self, ciphertext: &[u8], iv: &[u8]) -> Vec<u8> {
        // message len must be a multiple of 16
        assert_eq!(ciphertext.len() % 16, 0);
        let mut plaintext: Vec<u8> = Vec::new(); // Final message var

        let mut xor_block = iv.to_vec(); // c0 = iv
        for i in (0..ciphertext.len() - 16 + 1).step_by(16) {
            //CBC Logic
            let temp = aes_decrypt(&ciphertext[i..i + 16], &self.key); // Dec(ci)
            let mut message_block = xor(&temp, &xor_block); // mi = Dec(ci) xor ci-1
            plaintext.append(&mut message_block); // append mi
            xor_block = ciphertext[i..i + 16].to_vec();
        }
        return plaintext;
    }
}
impl Encrypt for CbcOracle {
    fn encrypt(&self, plaintext: &[u8], iv: &[u8]) -> Vec<u8> {
        // message len must be a multiple of 16
        let plaintext = pkcs7_pad(plaintext, None);
        assert_eq!(plaintext.len() % 16, 0);

        let mut ciphertext: Vec<u8> = Vec::new(); //final ciphertext var

        let mut ciphertext_block = iv.to_vec();
        for i in (0..plaintext.len() - 16 + 1).step_by(16) {
            // CBC logic
            let temp = xor(&plaintext[i..i + 16], &ciphertext_block); // mi xor ci-1
            ciphertext_block = aes_encrypt(&temp, &self.key); // ci = Enc(m xor ci-1)
            ciphertext.append(&mut ciphertext_block.to_vec()); // append ci to final c
        }
        return ciphertext;
    }
}

pub fn challenge10() -> Result<(), Box<dyn Error>> {
    println!("Test cbc");
    let test_message: [u8; 48] = [32; 48];
    let oracle = CbcOracle::new(None);
    let iv = [0; 16];
    let enc = oracle.encrypt(&test_message, &iv);
    let dec = oracle.decrypt(&enc, &iv);

    //println!("{}, {:?}", enc.len(), enc);
    println!("{}, {:?}", dec.len(), dec);

    println!("Fetching data...");
    let recv =
        reqwest::blocking::get("https://cryptopals.com/static/challenge-data/10.txt")?.text()?;
    let recv_split: Vec<_> = recv.split("\n").collect(); //split the strings

    let ciphertext: Vec<u8> = recv_split[0..recv_split.len() - 1]
        .iter() // iter through the strings
        .map(|s| base64::decode(*s).unwrap()) // decode frm b64
        .collect::<Vec<_>>() // collect them into Vec<Vec<u8>>
        .concat(); // Concat them into Vec<u8>

    println!("Decrypting...");
    println!("{}", ciphertext.len());
    let ciphertext = pkcs7_pad(&ciphertext, None);

    // CBC decrypt
    let key = b"YELLOW SUBMARINE";
    let oracle = CbcOracle::new(Some(key));
    let iv: [u8; 16] = [0; 16];
    let message = oracle.decrypt(&ciphertext, &iv);
    //println!("{:?}", message);
    //let message = pkcs7_unpad(&message).unwrap();
    println!("{}", u8_to_ascii(&message));
    Ok(())
}
