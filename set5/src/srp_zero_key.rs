use crate::srp::{SrpClient, SrpServer};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac, NewMac};

pub fn srp_exchange_zero(client: &SrpClient, server: &SrpServer, client_pk: BigUint) {
    // C -> S
    let (_email, client_pk) = (client.email.clone(), client_pk);

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
    //let hmac_client = client.generate_hmac(salt, server_pk, u.clone());
    // the computed `S` = 0 => the response will be the mac of 0
    let buf = BigUint::from(0usize).to_bytes_be();
    let mut hasher = Sha256::new();
    hasher.update(buf);
    let K = hasher.finalize();

    // generate hmac
    let mut hmac = Hmac::<Sha256>::new_varkey(&K).expect("error on hmac creation");
    hmac.update(&salt.to_bytes_be());
    let hmac_client = hmac.finalize().into_bytes();
    
    // S checks hmac and sents result
    let res = server.validate_client(client_pk, u, &hmac_client);
    match res {
        Ok(_) => println!("Verified!"),
        Err(_) => println!("Mac error"),
    }
}

pub fn challenge37(){
    let k = BigUint::from(3_usize);
    let password = String::from("secret_password");
    let password2 = String::from("random");
    let email = String::from("me@abc.com");
    let g = BigUint::from(2_usize);
    let p = BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap();
    let client = SrpClient::new(k.clone(), password2, email.clone(), g.clone(), p.clone());
    let server = SrpServer::new(k, password, email, g, p.clone());

    srp_exchange_zero(&client, &server, BigUint::from(0usize));
    srp_exchange_zero(&client, &server, p.clone());
    srp_exchange_zero(&client, &server, 2usize * p);


}