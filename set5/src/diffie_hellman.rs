use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};


#[derive(Clone, Debug)]
pub struct DiffieHellman {
    pub g: BigUint,
    pub p: BigUint,
}

impl DiffieHellman {
    pub fn new(g_temp: Option<BigUint>, p_temp: Option<BigUint>) -> DiffieHellman {
        let g;
        match g_temp {
            Some(v) => g = v,
            None => {
                g = BigUint::from(2_u8);
            }
        }

        let p;
        match p_temp{
            Some(v) => p = v,
            None => p = BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap(),
        }
        DiffieHellman { g, p }
    }

    pub fn generate_key_pair(&self, sk_temp: Option<BigUint>) -> (BigUint, BigUint) {
        let sk;
        match sk_temp {
            Some(v) => sk = v,
            None => {
                let mut rng = rand::thread_rng();
                sk = rng.gen_biguint(2048);
            }
        }
        let pk = self.g.modpow(&sk, &self.p);
        (sk, pk)
    }

    pub fn generate_secret(&self, sk: &BigUint, pk: &BigUint) -> BigUint {
        pk.modpow(sk, &self.p)
    }
}

pub fn challenge33() {
    let dh = DiffieHellman::new(None, None);
    let (sk1, pk1) = dh.generate_key_pair(Some(BigUint::from(2_usize)));
    let (sk2, pk2) = dh.generate_key_pair(Some(BigUint::from(3_usize)));
    println!("{}, {}", sk1, pk1);
    println!("{}, {}", sk2, pk2);

    let secret1 = dh.generate_secret(&sk1, &pk2);
    let secret2 = dh.generate_secret(&sk2, &pk1);

    println!("{}, {}", secret1, secret2);
}
