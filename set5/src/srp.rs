use num_bigint::{BigUint, RandBigInt};
use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac, NewMac};
use crypto_mac::MacError;

pub struct SrpClient {
    pub p: BigUint,
    pub g: BigUint,
    k: BigUint,
    pub email: String,
    password: String,
    sk: BigUint,
}
impl SrpClient {
    pub fn new(k: BigUint, password: String, email: String, g: BigUint, p: BigUint) -> SrpClient {
        // generate secret key
        let mut rng = rand::thread_rng();
        let sk = rng.gen_biguint(2048);

        return SrpClient {
            p: p,
            g: g,
            k: k,
            email: email,
            password: password,
            sk: sk,
        };
    }

    pub fn get_pub_key(&self) -> BigUint {
        return self.g.modpow(&self.sk, &self.p);
    }

    pub fn generate_hmac(&self, salt: BigUint, server_pk: BigUint, u: BigUint) -> Vec<u8> {
        // 1
        let mut buf = salt.to_bytes_be();
        buf.extend(self.password.as_bytes());
        let mut hasher = Sha256::new();
        hasher.update(buf);
        let xh = hasher.finalize();

        // 2
        let x = BigUint::from_bytes_be(&xh);

        // 3
        let S = server_pk + &self.p - (&self.k * self.g.modpow(&x, &self.p)) % &self.p;
        let S = S.modpow(&(&self.sk + u * &x), &self.p);

        println!("client {}", S);

        let mut buf = S.to_bytes_be();
        let mut hasher = Sha256::new();
        hasher.update(buf);
        let K = hasher.finalize();

        // generate hmac
        let mut hmac = Hmac::<Sha256>::new_varkey(&K).expect("error on hmac creation");
        hmac.update(&salt.to_bytes_be());
        let res = hmac.finalize();
        return res.into_bytes().to_vec();
    }
}
pub struct SrpServer {
    pub p: BigUint,
    pub g: BigUint,
    k: BigUint,
    pub email: String,
    password: String,
    pub salt: BigUint,
    v: BigUint,
    sk: BigUint,
}

impl SrpServer {
    pub fn new(k: BigUint, password: String, email: String, g: BigUint, p: BigUint) -> SrpServer {
        let g = g;
        let p = p;
        // 1;
        let mut rng = rand::thread_rng();
        let salt = rng.gen_biguint(2048);

        // 2
        let mut buf = salt.to_bytes_be();
        buf.extend(password.as_bytes());
        let mut hasher = Sha256::new();
        hasher.update(buf);
        let xh = hasher.finalize();

        // 3
        let x = BigUint::from_bytes_be(&xh);

        // 4
        let v = g.modpow(&x, &p);

        // secret key
        let sk = rng.gen_biguint(2048);
        return SrpServer {
            p: p,
            g: g,
            k: k,
            email: email,
            password: password,
            salt: salt,
            v: v,
            sk: sk,
        };
    }

    pub fn get_pub_key(&self) -> BigUint {
        return (&self.k * &self.v + self.g.modpow(&self.sk, &self.p)) % &self.p;
    }

    pub fn validate_client(&self, client_pk: BigUint,  u: BigUint, client_mac: &[u8]) -> Result<(), MacError> {
        // 1
        let S = client_pk * self.v.modpow(&u, &self.p);
        let S = S.modpow(&self.sk, &self.p);
        println!("server {}", S);

        // 2
        let mut buf = S.to_bytes_be();
        let mut hasher = Sha256::new();
        hasher.update(buf);
        let K = hasher.finalize();

        // validate hmac
        let mut hmac = Hmac::<Sha256>::new_varkey(&K).expect("error on hmac creation");
        hmac.update(&self.salt.to_bytes_be());
        
        return hmac.verify(&client_mac);
    }
}

pub fn srp_exchange(client: &SrpClient, server: &SrpServer) {
    // C -> S
    let (email, client_pk) = (client.email.clone(), client.get_pub_key());

    // S -> C
    let (salt, server_pk) = (server.salt.clone(), server.get_pub_key());

    // Compute `u` 
    let mut buf = client_pk.to_bytes_be();
    buf.extend(server_pk.to_bytes_be());
    let mut hasher = Sha256::new();
    hasher.update(buf);
    let uh = hasher.finalize();
    let u = BigUint::from_bytes_be(&uh);

    // C -> S hmac 
    let hmac_client = client.generate_hmac(salt, server_pk, u.clone());
    // S checks hmac and sents result
    let res = server.validate_client(client_pk, u, &hmac_client);
    match res {
        Ok(_) => println!("Verified!"),
        Err(_) => println!("Mac error"),
    }
}

pub fn challenge36() {
    let k = BigUint::from(3 as usize);
    let password = String::from("secret_password");
    let email = String::from("me@abc.com");
    let g = BigUint::from(2 as usize);
    let p = BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap();
    let client = SrpClient::new(k.clone(), password.clone(), email.clone(), g.clone(), p.clone());
    let server = SrpServer::new(k.clone(), password.clone(), email.clone(), g.clone(), p.clone());

    srp_exchange(&client, &server);
}
