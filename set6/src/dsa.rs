use indicatif::{ProgressIterator};
use num_bigint::{BigInt, RandBigInt, Sign};

use sha2::{Digest, Sha256};
use utils::algorithms::mod_inv;


pub struct Dsa {
    p: BigInt,
    q: BigInt,
    g: BigInt,
    sk: BigInt,
    pk: BigInt,
    k_bound: BigInt,
}
impl Dsa {
    pub fn new(nonce_strength: Option<BigInt>) -> Dsa {
        let p = BigInt::parse_bytes(b"800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16).unwrap();
        let q = BigInt::parse_bytes(b"f4f47f05794b256174bba6e9b396a7707e563c5b", 16).unwrap();
        let g = BigInt::parse_bytes(b"5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16).unwrap();

        let mut rng = rand::thread_rng();
        let sk = rng.gen_bigint_range(&BigInt::from(2), &(&q - 1));
        let pk = g.modpow(&sk, &p);

        let k_bound;
        match nonce_strength {
            Some(v) => k_bound = v,
            None => k_bound = &q - 1,
        }

        Dsa {
            p,
            q,
            g,
            sk,
            pk,
            k_bound,
        }
    }
    pub fn get_pub_key(&self) -> BigInt {
        self.pk.clone()
    }

    pub fn sign(&self, msg: &[u8]) -> (BigInt, BigInt) {
        let mut rng = rand::thread_rng();
        let mut k;
        let mut r;
        let mut s;

        loop {
            k = rng.gen_bigint_range(&BigInt::from(1), &self.k_bound);
            r = self.g.modpow(&k, &self.p) % &self.q;
            if r == BigInt::from(0) {
                continue;
            }

            // hash the message
            let mut hasher = Sha256::new();
            hasher.update(msg);
            let h = hasher.finalize();
            let h = BigInt::from_bytes_be(Sign::Plus, &h);

            s = mod_inv(&k, &self.q).unwrap() * (h + &self.sk * &r) % &self.q;

            if s != BigInt::from(0) {
                return (r, s);
            }
        }
    }

    pub fn verify(&self, r: BigInt, s: BigInt, msg: &[u8]) -> bool {
        if r > self.q || r < BigInt::from(0) || s > self.q || s < BigInt::from(0) {
            println!("Signature out of range");
            return false;
        }

        let w = mod_inv(&s, &self.q).unwrap();

        // hash the message
        let mut hasher = Sha256::new();
        hasher.update(msg);
        let h = hasher.finalize();
        let h = BigInt::from_bytes_be(Sign::Plus, &h);

        let u1 = &h * &w % &self.q;
        let u2 = &r * &w % &self.q;
        let v = (self.g.modpow(&u1, &self.p) * self.pk.modpow(&u2, &self.p) % &self.p) % &self.q;

        if v == r {
            return true;
        }
        false
    }
}

pub fn break_nonce(
    dsa: &Dsa,
    r: BigInt,
    s: BigInt,
    h: BigInt,
    pk: BigInt,
    k_bound: BigInt,
) -> Option<BigInt> {
    let mut sk;

    for i in num_iter::range_inclusive(BigInt::from(1), k_bound).progress() {
        let temp = mod_inv(&r, &dsa.q);
        match temp {
            Some(v) => {
                sk = (((&s * i - &h) * v % &dsa.q) + &dsa.q) % &dsa.q;
            }
            None => continue,
        }

        if dsa.g.modpow(&sk, &dsa.p) == pk {
            return Some(sk);
        }
    }
    None
}

pub fn challenge43() {
    let k_bound = BigInt::from(2 << (12 - 1));
    let dsa = Dsa::new(Some(k_bound.clone()));
    let msg = b"waddup";
    let (r, s) = dsa.sign(msg);
    println!("test dsa: {}", dsa.verify(r.clone(), s.clone(), msg));

    // hash the message
    let mut hasher = Sha256::new();
    hasher.update(msg);
    let h = hasher.finalize();
    let h = BigInt::from_bytes_be(Sign::Plus, &h);

    let pk = dsa.get_pub_key();
    let my_sk = break_nonce(
        &dsa,
        r,
        s,
        h,
        pk,
        k_bound,
    );

    println!("real sk {}", dsa.sk);
    println!("my sk: {}", my_sk.unwrap_or(BigInt::from(-1)));
}
