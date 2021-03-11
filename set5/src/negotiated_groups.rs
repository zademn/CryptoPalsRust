use std::hash;
use crate::mitm_key_fixing::DhParty;
use num_bigint::BigUint;
use set2::cbc_using_ecb::CbcOracle;
use set2::oracle::Encrypt;
use set2::pkcs7_padding::pkcs7_unpad;
use sha1::{Digest, Sha1};
use utils::number::u8_to_ascii;
use std::error::Error;


pub fn negotiated_groups(alice: &mut DhParty, bob: &mut DhParty, g: &BigUint){
    // Set parameters with new g
    alice.set_parameters(Some(g.clone()), Some(alice.dh.p.clone()));
    let A = alice.get_public_key();
    bob.set_parameters(Some(g.clone()), Some(bob.dh.p.clone()));
    let B = bob.get_public_key();

    // Set secret
    alice.set_secret(&B);
    bob.set_secret(&A);
    // send encrypted messages
    let plaintext1 = b"hello from alice";
    let (ciphertext1, iv1) = alice.send_message(plaintext1);

    println!(
        "Bob decrypted msg: {}",
        u8_to_ascii(&bob.decrypt_message(&ciphertext1, &iv1))
    );
    let (ciphertext2, iv2) = bob.send_message(b"hello from bob");
    println!(
        "Alice decrypted msg: {}",
        u8_to_ascii(&alice.decrypt_message(&ciphertext2, &iv2))
    );

    // temp key
    let mut key= b"1234".to_vec();
    if *g == BigUint::from(1 as usize){
        // for g = 1 => key = 1
        key = b"1".to_vec();
    }
    else if *g == BigUint::from(0 as usize){
        // for g = 1 => key = 1
        key = b"0".to_vec();
    }
    else if *g == alice.dh.p.clone() - 1 as usize{
        key = b"1".to_vec();
    }
    // first batch
    let func = || -> Result<(), Box<dyn Error>> {
        println!("using key = {}", u8_to_ascii(&key));
        let mut hasher = Sha1::new();
        hasher.update(key);
        let key = &hasher.finalize()[..16];

        let oracle = CbcOracle::new(Some(key));
        let plaintext1_mitm = oracle.decrypt(&ciphertext1, &iv1);
        println!(
            "mitm alice message: {}",
            u8_to_ascii(&pkcs7_unpad(&plaintext1_mitm)?)
        );

        let oracle = CbcOracle::new(Some(key));
        let plaintext2_mitm = oracle.decrypt(&ciphertext2, &iv2);
        println!(
            "mitm bob message: {}",
            u8_to_ascii(&pkcs7_unpad(&plaintext2_mitm)?)
        );

        Ok(())
    };

    // for g = p - 1 = -1 mod p try key = p-1 too
    if let Err(_err) = func(){
        let key_temp = (alice.dh.p.clone() -1 as usize).to_str_radix(10).into_bytes();
        key = key_temp.clone();
        println!("Using key = {}", u8_to_ascii(&key));

        let mut hasher = Sha1::new();
        hasher.update(key);
        let key = &hasher.finalize()[..16];

        let oracle = CbcOracle::new(Some(key));
        let plaintext1_mitm = oracle.decrypt(&ciphertext1, &iv1);
        println!(
            "mitm alice message: {}",
            u8_to_ascii(&pkcs7_unpad(&plaintext1_mitm).unwrap())
        );

        let oracle = CbcOracle::new(Some(key));
        let plaintext2_mitm = oracle.decrypt(&ciphertext2, &iv2);
        println!(
            "mitm bob message: {}",
            u8_to_ascii(&pkcs7_unpad(&plaintext2_mitm).unwrap())
        );
    }

}



pub fn challenge35(){
    let mut alice = DhParty::new(None, None, None);
    let mut bob = DhParty::new(None, None, None);

    negotiated_groups(&mut alice, &mut bob, &BigUint::from(1 as usize));
    println!();
    negotiated_groups(&mut alice, &mut bob, &BigUint::from(0 as usize));
    println!();

    let p = alice.dh.p.clone();
    negotiated_groups(&mut alice, &mut bob, &(p-1 as usize));
    println!();
}