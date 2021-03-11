use num_bigint::algorithms::xgcd;
use num_bigint::RandPrime;
use num_bigint::{BigInt, Sign};
use rand::thread_rng;
use utils::algorithms::mod_inv;
use utils::number::u8_to_ascii;

pub struct Rsa {
    p: BigInt,
    q: BigInt,
    n: BigInt,
    phi: BigInt,
    e: BigInt,
    d: BigInt,
}

impl Rsa {
    pub fn new(keysize: usize, e_temp: Option<BigInt>) -> Rsa {
        let mut e;
        match e_temp {
            Some(v) => e = v,
            None => e = BigInt::from(65537),
        }

        // generate primes
        let mut rng = thread_rng();
        let mut p = BigInt::from_biguint(Sign::Plus, rng.gen_prime(keysize));
        let mut q = BigInt::from_biguint(Sign::Plus, rng.gen_prime(keysize));
        let mut n = &p * &q;
        let mut phi = (&p - 1) * (&q - 1);
        loop {
            let (z, _, _) = xgcd(&e, &phi, false);
            if z == BigInt::from(1) {
                break;
            } else {
                rng = thread_rng();
                p = BigInt::from_biguint(Sign::Plus, rng.gen_prime(keysize));
                q = BigInt::from_biguint(Sign::Plus, rng.gen_prime(keysize));
                n = &p * &q;
                phi = (&p - 1) * (&q - 1);
            }
        }
        let d = mod_inv(&e, &phi).unwrap();
        assert!((&d * &e) % &phi == BigInt::from(1));
        return Rsa {
            p: p,
            q: q,
            n: n.clone(),
            phi: phi,
            e: e,
            d: d,
        };
    }
    pub fn get_pubkey(&self) -> (BigInt, BigInt) {
        return (self.n.clone(), self.e.clone());
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let plaintext = BigInt::from_bytes_be(Sign::Plus, &plaintext);
        let ciphertext = plaintext.modpow(&self.e, &self.n);
        let (_, ciphertext) = ciphertext.to_bytes_be();

        return ciphertext;
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        let ciphertext = BigInt::from_bytes_be(Sign::Plus, &ciphertext);
        let plaintext = ciphertext.modpow(&self.d, &self.n);
        let (_, plaintext) = plaintext.to_bytes_be();

        return plaintext;
    }
}

pub fn challenge39() {
    //let cipher_rsa = Rsa::new(512, Some(BigInt::from(3)));
    let cipher_rsa = Rsa::new(512, None);

    let plaintext = b"secret_message";

    let ciphertext = cipher_rsa.encrypt(plaintext);
    println!("ciphertext: {}", u8_to_ascii(&ciphertext));

    let plaintext_decr = cipher_rsa.decrypt(&ciphertext);
    println!("plaintext_decr: {}", u8_to_ascii(&plaintext_decr));
}
