use byteorder::{ByteOrder, LittleEndian};
use set1::aes_ecb::{aes_decrypt, aes_encrypt};
use utils::number::{random_bytes, u8_to_ascii, xor};

pub struct CtrMode {
    key: Vec<u8>,
    counter: Vec<u8>,
    iv: Vec<u8>,
}

impl CtrMode {
    pub fn new(key: Option<&[u8]>, iv: Option<&[u8]>) -> CtrMode {
        // check if key or iv was provided, else generate random
        let temp_key;
        match key {
            Some(key) => temp_key = key.to_vec(),
            None => {
                temp_key = random_bytes(16);
            }
        }
        let temp_iv;
        match iv {
            Some(iv) => temp_iv = iv.to_vec(),
            None => {
                temp_iv = random_bytes(8);
            }
        }

        // init counter
        let mut counter = vec![0 as u8; 16];
        counter[..8].clone_from_slice(&temp_iv);

        return CtrMode {
            key: temp_key.to_vec(),
            counter: counter.to_vec(),
            iv: temp_iv,
        };
    }
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        // Generate keystream
        let keystream_len = (plaintext.len() / 16 + 1) * 16;
        let mut keystream = vec![0 as u8; keystream_len];
        let mut ciphertext: Vec<u8> = Vec::new();

        // This gives a different keystream after encryption
        // IDK why
        // for _ in plaintext.chunks(16) {
        //     keystream.extend_from_slice(&self.counter);
        //     self.increment_counter();
        // }

        for plaintext_chunk in plaintext.chunks(16) {
            let keystream = aes_encrypt(&self.counter, &self.key);
            println!("{:?}", keystream);
            ciphertext.extend_from_slice(&xor(&plaintext_chunk, &keystream));
            self.increment_counter();
        }
        //Encrypt keystream
        // let keystream = aes_encrypt(&keystream, &self.key);
        // println!("{:?}", keystream);
        // return xor(&plaintext, &keystream[..plaintext.len()]);
        return ciphertext;
    }

    fn increment_counter(&mut self) {
        let mut buf = LittleEndian::read_u64(&self.counter[8..]);
        buf += 1;
        LittleEndian::write_u64(&mut self.counter[8..], buf);
    }

    fn reset_counter(&mut self, iv: Option<&[u8]>) {
        // Check if iv was provided else generate random
        let temp_iv;
        match iv {
            Some(iv) => temp_iv = iv.to_vec(),
            None => {
                temp_iv = random_bytes(8);
            }
        }
        self.counter = vec![0 as u8; 16];
        self.counter[..8].clone_from_slice(&temp_iv);
    }
}

pub fn challenge18() {
    let key = b"YELLOW SUBMARINE";
    let iv = vec![0 as u8; 8];

    println!("Testing CtrMode...");
    let plaintext = b"This is a test plaintext";
    let mut cipher = CtrMode::new(Some(key), Some(&iv));
    let ciphertext = cipher.encrypt(plaintext);
    println!("{}", u8_to_ascii(&ciphertext));
    cipher.reset_counter(Some(&iv));
    let plaintext_decr = cipher.encrypt(&ciphertext);
    println!("{}", u8_to_ascii(&plaintext_decr));
    println!("{:?}", cipher.counter);

    println!();
    println!("Challenge");
    let ciphertext =
        base64::decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
            .unwrap();
    cipher.reset_counter(Some(&iv));
    let plaintext = cipher.encrypt(&ciphertext);
    println!("{}, {:?}", u8_to_ascii(&plaintext), cipher.counter);
}
