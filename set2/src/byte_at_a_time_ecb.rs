use crate::pkcs7_padding::pkcs7_pad;
use aes::cipher;
use base64;
use rand::rngs::ThreadRng;
use rand::Rng;
use set1::aes_ecb::aes_encrypt;
use set1::detect_ecb::detect_ecb;
use utils::number::u8_to_ascii;

use crate::oracle::Encrypt;

pub struct EcbOracle {
    key: Vec<u8>,
    suffix: Vec<u8>,
}
impl EcbOracle {
    fn new() -> EcbOracle {
        let mut rng: ThreadRng = rand::thread_rng();
        let key = (0..16).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        let n = rng.gen::<u8>();
        let suffix = base64::decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap();

        return EcbOracle {
            key: key,
            suffix: suffix,
        };
    }
}
impl Encrypt for EcbOracle {
    fn encrypt(&self, plaintext: &[u8], iv: &[u8]) -> Vec<u8> {
        // iv is not used
        let mut buf = plaintext.to_vec();
        buf.extend(&self.suffix);
        let buf = pkcs7_pad(&buf, None);
        let ciphertext = aes_encrypt(&buf, &self.key);
        return ciphertext;
    }
}

pub fn find_block_size<T: Encrypt>(oracle: &T) -> usize {
    let mut block_size = 0;
    let mut i = 1;
    let l1 = oracle.encrypt(b"", Default::default()).len();
    loop {
        let msg: Vec<u8> = vec![65; i];
        let l2 = oracle.encrypt(&msg, Default::default()).len();
        if l1 != l2 {
            println!("Difference {} - {}", l2, l1);
            block_size = l2 - l1;
            break;
        }
        i += 1;
    }

    return block_size;
}
pub fn byte_at_a_time_ecb(oracle: &EcbOracle) -> Option<Vec<u8>> {
    //Step 1 - get block size
    let mut block_size = find_block_size(oracle);
    println!("Block size is: {}", block_size);
    //Step 2 - detect ecb
    if detect_ecb(&oracle.encrypt(&vec![65; 3 * block_size], Default::default())) {
        println!("Using ECB mode");
    } else {
        println!("Not using ECB mode");
        return None;
    }

    //Step 3 - craft a block 1 byte off
    let mut flag: Vec<u8> = vec![]; // flag variable
    let suffix_len = oracle.encrypt(b"", Default::default()).len();
    for i in (1..suffix_len) {
        let mut msg: Vec<u8> = vec![65; suffix_len - i]; // i bytes off
        let ciphertext1 = oracle.encrypt(&msg, Default::default()); // encrypt
        for byte in (0..255) {
            //iterate through possible last bytes
            let mut msg2 = msg.clone();
            msg2.extend(&flag); // append the flag we discovered so far
            msg2.push(byte as u8); //append the brute forced byte
            let ciphertext2 = oracle.encrypt(&msg2, Default::default());
            if ciphertext1[..suffix_len] == ciphertext2[..suffix_len] {
                // compare
                flag.push(byte);
                break;
            }
        }
    }
    return Some(flag);
}
pub fn challenge12() {
    let oracle = EcbOracle::new();
    let flag = byte_at_a_time_ecb(&oracle).unwrap();
    println!("{}", u8_to_ascii(&flag));
}
