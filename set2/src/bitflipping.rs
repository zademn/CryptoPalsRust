use crate::cbc_using_ecb::CbcOracle;
use crate::oracle::Encrypt;
use crate::pkcs7_padding::{pkcs7_pad, pkcs7_unpad};
use utils::number::{random_bytes, u8_to_ascii};
pub struct CbcOracleBitflip {
    key: Vec<u8>,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
}

impl CbcOracleBitflip {
    fn new(key: Option<&[u8]>) -> CbcOracleBitflip {
        let prefix = b"comment1=cooking%20MCs;userdata=";
        let suffix = b";comment2=%20like%20a%20pound%20of%20bacon";
        let mut temp_key;
        match key {
            Some(key) => temp_key = key.to_vec(),
            None => {
                let mut rng = rand::thread_rng();
                temp_key = random_bytes(16);
            }
        }
        return CbcOracleBitflip {
            key: temp_key,
            prefix: prefix.to_vec(),
            suffix: suffix.to_vec(),
        };
    }

    fn decrypt(&self, ciphertext: &[u8], iv: &[u8]) -> bool {
        let oracle = CbcOracle::new(Some(&self.key));
        let plaintext = oracle.decrypt(&ciphertext, iv);
        //println!("{}", u8_to_ascii(&plaintext));
        return u8_to_ascii(&plaintext).contains(";admin=true;");
    }
}
impl Encrypt for CbcOracleBitflip {
    fn encrypt(&self, plaintext: &[u8], iv: &[u8]) -> Vec<u8> {
        if plaintext.contains(&(';' as u8)) || plaintext.contains(&('=' as u8)) {
            println!("Invalid characters");
            return vec![];
        }
        let oracle = CbcOracle::new(Some(&self.key));
        let mut buf = self.prefix.to_vec();
        buf.extend(plaintext);
        buf.extend(&self.suffix);
        let ciphertext = oracle.encrypt(&buf, iv);

        return ciphertext;
    }
}

pub fn bitflipping(oracle: &CbcOracleBitflip, iv: &[u8]) {
    // we assume we can find these
    let prefix_len = oracle.prefix.len();
    let suffix_len = oracle.suffix.len();
    let block_size = 16;

    // Get the padding length
    let pad_len = block_size - prefix_len % block_size;

    // We need to add ; and = to our plaintext where our X are
    // Therefore the encryption of the previous block xored with the encryption of the default block xored our wanted char
    let plaintext = b"XadminXtrueXAAAA";
    let previous_block = [65 as u8; 16];
    let mut buf = vec![65 as u8; pad_len];
    buf.extend(&previous_block);
    buf.extend(plaintext);
    let mut ciphertext = oracle.encrypt(&buf, iv);
    ciphertext[prefix_len + pad_len] = ('X' as u8) ^ ciphertext[prefix_len + pad_len] ^ (';' as u8);
    ciphertext[prefix_len + pad_len + 6] =
        ('X' as u8) ^ ciphertext[prefix_len + pad_len + 6] ^ ('=' as u8);
    ciphertext[prefix_len + pad_len + 11] =
        ('X' as u8) ^ ciphertext[prefix_len + pad_len + 11] ^ (';' as u8);

    println!("{}", oracle.decrypt(&ciphertext, iv));
}
pub fn challenge16() {
    let oracle = CbcOracleBitflip::new(None);
    let iv = random_bytes(16);
    let ciphertext = oracle.encrypt(b"admin", &iv);
    //println!("{}", u8_to_ascii(&ciphertext));
    println!("{:?}", oracle.decrypt(&ciphertext, &iv));

    bitflipping(&oracle, &iv);
}
