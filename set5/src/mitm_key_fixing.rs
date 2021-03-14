#[allow(unused_imports)]
use crate::diffie_hellman::DiffieHellman;
use num_bigint::BigUint;
use set2::cbc_using_ecb::CbcOracle;
use set2::oracle::Encrypt;
use set2::pkcs7_padding::pkcs7_unpad;
use sha1::{Digest, Sha1};
use utils::number::{random_bytes, u8_to_ascii};

pub struct DhParty {
    pub dh: DiffieHellman,
    sk: BigUint,
    pub pk: BigUint,
    secret: BigUint,
}
impl DhParty {
    pub fn new(g: Option<BigUint>, p: Option<BigUint>, sk: Option<BigUint>) -> DhParty {
        let dh = DiffieHellman::new(g, p);
        let (sk, pk) = dh.generate_key_pair(sk);
        return DhParty {
            dh: dh.clone(),
            sk: sk,
            pk: pk,
            secret: Default::default(),
        };
    }
    pub fn get_public_key(&self) -> BigUint {
        return self.pk.clone();
    }
    pub fn set_parameters(&mut self, g: Option<BigUint>, p: Option<BigUint>) {
        let dh = DiffieHellman::new(g, p);
        let (_, pk) = dh.generate_key_pair(Some(self.sk.clone()));
        self.pk = pk;
        self.dh = dh;
    }
    pub fn set_secret(&mut self, other_pk: &BigUint) {
        self.secret = self.dh.generate_secret(&self.sk, &other_pk);
    }
    pub fn send_message(&self, plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // generate hashed key
        let key = self.secret.to_str_radix(10).into_bytes();
        let mut hasher = Sha1::new();
        hasher.update(key);
        let key = &hasher.finalize()[..16];

        // Encrypt message
        let oracle = CbcOracle::new(Some(key));
        let iv = random_bytes(16);
        let ciphertext = oracle.encrypt(&plaintext, &iv);

        return (ciphertext, iv);
    }
    pub fn decrypt_message(&self, ciphertext: &[u8], iv: &[u8]) -> Vec<u8> {
        // generate hashed key
        let key = self.secret.to_str_radix(10).into_bytes();
        let mut hasher = Sha1::new();
        hasher.update(key);
        let key = &hasher.finalize()[..16];

        let oracle = CbcOracle::new(Some(key));
        let plaintext = oracle.decrypt(&ciphertext, &iv);
        return pkcs7_unpad(&plaintext).unwrap();
    }
}

pub fn key_fixing_attack(alice: &mut DhParty, bob: &mut DhParty) {
    // Get p, g, A
    let (p, g, A) = (
        alice.dh.p.clone(),
        alice.dh.g.clone(),
        alice.get_public_key(),
    );
    // Send p, g, p to bob
    bob.set_secret(&p);

    // Get B
    let B = bob.get_public_key();
    // send p to alice
    alice.set_secret(&p);

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

    // Mitm messages
    let key = b"0";
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
pub fn challenge34() {
    let mut alice = DhParty::new(None, None, None);
    let mut bob = DhParty::new(None, None, None);

    key_fixing_attack(&mut alice, &mut bob);
}
