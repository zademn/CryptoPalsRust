use base64;
use rand::seq::SliceRandom;
use set2::cbc_using_ecb::CbcOracle;
use set2::oracle::Encrypt;
use set2::pkcs7_padding::{pkcs7_pad, pkcs7_unpad};
use utils::number::{random_bytes, u8_to_ascii};

////https://www.youtube.com/watch?v=O5SeQxErXA4&t=3s
pub struct CbcOraclePadding {
    key: Vec<u8>,
}

impl CbcOraclePadding {
    fn new(key: Option<&[u8]>) -> CbcOraclePadding {
        let temp_key;
        match key {
            Some(key) => temp_key = key.to_vec(),
            None => {
                temp_key = random_bytes(16);
            }
        }
        return CbcOraclePadding { key: temp_key };
    }

    fn decrypt(&self, ciphertext: &[u8], iv: &[u8]) -> bool {
        let oracle = CbcOracle::new(Some(&self.key));
        let plaintext = oracle.decrypt(&ciphertext, iv);
        let plaintext = pkcs7_unpad(&plaintext);
        match plaintext {
            Ok(_) => return true,
            Err(_) => return false,
        }
    }
}
impl Encrypt for CbcOraclePadding {
    fn encrypt(&self, plaintext: &[u8], iv: &[u8]) -> Vec<u8> {
        let oracle = CbcOracle::new(Some(&self.key));
        let ciphertext = oracle.encrypt(&plaintext, iv);
        return ciphertext;
    }
}

pub fn padding_oracle_attack(oracle: &CbcOraclePadding, iv: &[u8], ciphertext: &[u8]) -> Vec<u8>{
    let mut plaintext: Vec<u8> = Vec::new();
    // Get the block_size from iv or assume we know it
    let block_size = iv.len();

    // split into `block_size` blocks -> iv || block1 || block2 ||...
    let mut ciphertext_chunks = iv.to_vec();
    ciphertext_chunks.extend(ciphertext.iter());
    let ciphertext_chunks = ciphertext_chunks.chunks(block_size).collect::<Vec<_>>();

    // Go through each block
    // i iterates the block
    for i in 1..ciphertext_chunks.len() {
        let mut plaintext_block: Vec<u8> = vec![0 as u8; 16]; // the block to be decrypted
        // j is the current position we want to decrypt
        // start from right to left -> block_size - 1 to 0
        for j in (0..block_size).rev() {
            let mut block1 = ciphertext_chunks[i - 1].to_vec();
            let mut block2 = ciphertext_chunks[i].to_vec();
            let expected_pad = (block_size - j) as u8;

            // change bytes of block1 based on the plaintext found to make the padding work
            // k iterates from j + 1 -> block_size -1  (the bytes on the right of j)
            for k in (j + 1..block_size) {
                block1[k] = ciphertext_chunks[i - 1][k] ^ plaintext_block[k] ^ expected_pad
            }
            //byte is the byte that we brute force
            let mut possible_bytes: Vec<u8> = vec![];
            for byte in (0..256 as usize) {
                block1[j] = byte as u8;

                // craft the new ciphertext
                let mut buf: Vec<u8> = Vec::new();
                buf.extend(&block1);
                buf.extend(&block2);

                // try oracle
                if oracle.decrypt(&buf, iv) {
                    //we might have to account for multiple valid paddings ->
                    // /x03/x03/x03 has /x03 and /x01 as valid padding. 
                    //We shall try the next byte too to eliminate them
                    possible_bytes.push(expected_pad ^ ciphertext_chunks[i - 1][j] ^ (byte as u8));
                }
            } // end byte for

            // Elimination phase
            if possible_bytes.len() > 1 {
                let j2 = j - 1;
                'outer: for possible_byte in possible_bytes {
                    let mut plaintext_block_tmp: Vec<u8> = plaintext_block.clone();
                    plaintext_block_tmp[j] = possible_byte; // Put the new byte in the plaintext_tmp
                    let mut block1_tmp = block1.to_vec();
                    let mut block2_tmp = block2.to_vec();
                    let expected_pad = (block_size - j2) as u8;

                    // change bytes of block1 based on the plaintext found to make the padding work
                    // k iterates from j + 1 -> block_size -1  (the bytes on the right of j)
                    for k in (j2..block_size) {
                        block1_tmp[k] = ciphertext_chunks[i - 1][k] ^ plaintext_block_tmp[k] ^ expected_pad
                    }
                    for byte in (0..256 as usize) {
                        block1_tmp[j2] = byte as u8;

                        // craft the new ciphertext
                        let mut buf: Vec<u8> = Vec::new();
                        buf.extend(&block1_tmp);
                        buf.extend(&block2_tmp);

                        // try oracle
                        if oracle.decrypt(&buf, iv) {
                            plaintext_block[j] = possible_byte;
                            break 'outer;
                        }
                    } // end byte for
                } // end possible_byte for
            } else  if possible_bytes.len() == 1{
                plaintext_block[j] = possible_bytes[0];
            }
        } // end j for

        // push front?
        //println!("{}", u8_to_ascii(&plaintext_block));
        plaintext.extend(&plaintext_block);
    }

    //println!("{}, {}", u8_to_ascii(&plaintext), plaintext.len());
    return pkcs7_unpad(&plaintext).unwrap();
}
pub fn challenge17() {
    let ss = vec![
        b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=".to_vec(),
        b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=".to_vec(),
        b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==".to_vec(),
        b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==".to_vec(),
        b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl".to_vec(),
        b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==".to_vec(),
        b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==".to_vec(),
        b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=".to_vec(),
        b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=".to_vec(),
        b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93".to_vec(),
    ];

    println!("Test padding...");
    let s = base64::decode(ss.choose(&mut rand::thread_rng()).unwrap()).unwrap();
    println!("To encrypt: {}", u8_to_ascii(&s));

    let oracle = CbcOraclePadding::new(None);
    let iv = random_bytes(16);
    let mut ciphertext = oracle.encrypt(&s, &iv);
    let ciph_len = ciphertext.len();

    println!("Valid decryption: {}", oracle.decrypt(&ciphertext, &iv));
    ciphertext[ciph_len - 1] = 34;
    println!("Error: {:?}", oracle.decrypt(&ciphertext, &iv));

    println!();
    println!("Starting padding oracle attack...");
    let ciphertext = oracle.encrypt(&s, &iv);
    println!("{}", u8_to_ascii(&padding_oracle_attack(&oracle, &iv, &ciphertext)));
}
