use crate::byte_at_a_time_ecb::find_block_size;
use crate::oracle::Encrypt;
use crate::pkcs7_padding::pkcs7_pad;

use rand::rngs::ThreadRng;
use rand::Rng;
use set1::aes_ecb::aes_encrypt;
use set1::detect_ecb::detect_ecb;
use utils::number::u8_to_ascii;
pub struct HarderEcbOracle {
    key: Vec<u8>,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
}
impl HarderEcbOracle {
    fn new() -> HarderEcbOracle {
        let mut rng: ThreadRng = rand::thread_rng();
        let key = (0..16).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        let n = rng.gen::<u8>();
        let suffix = base64::decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap();
        let prefix = (0..n).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();

        HarderEcbOracle { key, prefix, suffix }
    }
}
impl Encrypt for HarderEcbOracle {
    fn encrypt(&self, plaintext: &[u8], _iv: &[u8]) -> Vec<u8> {
        let mut buf = self.prefix.to_vec();
        buf.extend(plaintext);
        buf.extend(&self.suffix);
        let buf = pkcs7_pad(&buf, None);
        let ciphertext = aes_encrypt(&buf, &self.key);
        ciphertext
    }
}

pub fn byte_at_a_time_ecb(oracle: &HarderEcbOracle) -> Option<Vec<u8>> {
    //Step 1 - get block size
    let block_size = find_block_size(oracle);
    println!("Block size is: {}", block_size);
    //Step 2 - detect ecb
    if detect_ecb(&oracle.encrypt(&vec![65; 3 * block_size], Default::default())) {
        println!("Using ECB mode");
    } else {
        println!("Not using ECB mode");
        return None;
    }

    // Step 3 - Detect random prefix size
    // We encrypt n = block_size * 2, block_size + 1, ... `A`s until we find 2 consecutive blocks that are equal
    // prefix.len() = (block_m + block_A1 + block_A2).len() - n
    let mut msg = vec![65_u8; block_size * 2];
    let mut prefix_len = 0;
    'outer: loop {
        let ciphertext = oracle.encrypt(&msg, Default::default());
        let ciphertext_split = ciphertext.chunks(block_size);
        for (i, (block1, block2)) in ciphertext_split
            .clone()
            .zip(ciphertext_split.skip(1))
            .enumerate()
        {
            if block1 == block2 {
                // i indexes the first block of the 2 equal blocks, we subtract only (n - block_size * 2)
                prefix_len = i * block_size - (msg.len() - block_size * 2);
                break 'outer;
            }
        }
        msg.push(65);
    }
    println!("prefix length: {}", prefix_len);

    //Step 4 - Now that we know the random prefix length we can decode the last byte like the last time
    // We pad the random prefix with `A` until we get a block
    let mut flag: Vec<u8> = vec![]; // flag variable
    let pad_len = block_size - prefix_len % block_size;
    let full_len = oracle
        .encrypt(&vec![65_u8; pad_len], Default::default())
        .len();
    let suffix_len = full_len - prefix_len - pad_len;
    println!("pad length {}", pad_len);
    println!("suffix_len: {}", suffix_len);
    for i in 1..suffix_len {
        let msg: Vec<u8> = vec![65; pad_len + suffix_len - i]; // i bytes off
        let ciphertext1 = oracle.encrypt(&msg, Default::default()); // encrypt
        for byte in 0..255 {
            //iterate through possible last bytes
            let mut msg2 = msg.clone();
            msg2.extend(&flag); // append the flag we discovered so far
            msg2.push(byte as u8); //append the brute forced byte
            let ciphertext2 = oracle.encrypt(&msg2, Default::default());
            if ciphertext1[..prefix_len + pad_len + suffix_len]
                == ciphertext2[..prefix_len + pad_len + suffix_len]
            {
                // compare
                flag.push(byte);
                break;
            }
        }
    }
    Some(flag)
}
pub fn challenge14() {
    let oracle = HarderEcbOracle::new();
    println!("length of prefix: {}", oracle.prefix.len());
    println!(
        "length of suffix: {}",
        pkcs7_pad(&oracle.suffix, None).len()
    );
    let flag = byte_at_a_time_ecb(&oracle).unwrap();
    println!();
    println!("{}", u8_to_ascii(&flag));
}
