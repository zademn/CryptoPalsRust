use crate::rsa::Rsa;
use num_bigint::{BigInt, BigUint, Sign};
use utils::algorithms::{crt, mod_inv};
use utils::number::u8_to_ascii;

pub fn challenge40() {
    let e = BigInt::from(3);
    let rsa0 = Rsa::new(512, Some(e.clone()));
    let rsa1 = Rsa::new(512, Some(e.clone()));
    let rsa2 = Rsa::new(512, Some(e.clone()));

    let m = b"nuclear_codes";

    println!{"Generating ciphertexts..."}
    let c0 = BigInt::from_bytes_be(Sign::Plus, &rsa0.encrypt(m));
    let c1 = BigInt::from_bytes_be(Sign::Plus, &rsa1.encrypt(m));
    let c2 = BigInt::from_bytes_be(Sign::Plus, &rsa2.encrypt(m));
    let (n0, _) = rsa0.get_pubkey();
    let (n1, _) = rsa1.get_pubkey();
    let (n2, _) = rsa2.get_pubkey();

    println!("Decrypting...");
    let nvec = vec![n0, n1, n2];
    let cvec = vec![c0, c1, c2];

    let res = crt(cvec, nvec).unwrap();
    let (_, m_decr): (_, Vec<u8>) = res.nth_root(3).to_bytes_be();

    println!("{}", u8_to_ascii(&m_decr));
}
