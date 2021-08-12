use num_bigint::{BigInt, Sign};
use set5::rsa::Rsa;
use utils::algorithms::mod_inv;
use utils::number::u8_to_ascii;

struct RsaServer {
    rsa: Rsa,
    decrypted_ciphertexts: Vec<Vec<u8>>,
}
impl RsaServer {
    pub fn new(rsa: Rsa) -> RsaServer {
        RsaServer {
            rsa,
            decrypted_ciphertexts: Default::default(),
        }
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        if self.decrypted_ciphertexts.contains(&ciphertext.to_vec()) {
            return Err(String::from("Ciphertext already decrypted"));
        }
        // add ciphertext to decrypted ciphertexts
        self.decrypted_ciphertexts.push(ciphertext.to_vec());
        let plaintext = self.rsa.decrypt(&ciphertext);
        Ok(plaintext)
    }
}

pub fn challenge41() {
    let rsa0 = Rsa::new(512, None);
    let mut rsa_server = RsaServer::new(rsa0);

    //testing decryption
    println!("Testing decryption twice");
    let plaintext = b"secret_message";
    let ciphertext = rsa_server.rsa.encrypt(plaintext);
    let res = rsa_server.decrypt(&ciphertext);
    println!("{:?}", res);
    let res = rsa_server.decrypt(&ciphertext);
    println!("{:?}", res);

    // Get pubkey 
    let (n, e) = rsa_server.rsa.get_pubkey();
    let s = BigInt::from(420);
    let s_inv = mod_inv(&s, &n).unwrap();

    // Construct ciphertext_
    let c = BigInt::from_bytes_be(Sign::Plus, &ciphertext);
    let (_, ciphertext_) = ((s.modpow(&e, &n) * &c) % &n).to_bytes_be();

    // Decrypt new ciphertext_
    let plaintext_ = rsa_server.decrypt(&ciphertext_).unwrap();
    let p_ = BigInt::from_bytes_be(Sign::Plus, &plaintext_);
    
    // Get real plaintext
    let p = &p_ * &s_inv %  &n;
    let (_, plaintext_decr) = p.to_bytes_be();

    println!("Original plaintext: {}", u8_to_ascii(plaintext));
    println!("plaintext decrypted: {}", u8_to_ascii(&plaintext_decr));

}
