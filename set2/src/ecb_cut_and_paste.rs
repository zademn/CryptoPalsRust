use crate::pkcs7_padding::{pkcs7_pad, pkcs7_unpad};
use indexmap::IndexMap;
use rand::Rng;
use set1::aes_ecb::{aes_decrypt, aes_encrypt};
use std::collections::HashMap;
use utils::number::u8_to_ascii;

pub fn kv_parse(s: &str) -> IndexMap<String, String> {
    let s_split: Vec<_> = s.split("&").collect(); // split by &

    let mut hmap: IndexMap<String, String> = IndexMap::new();
    for s_spliti in s_split {
        let s_split2: Vec<_> = s_spliti.split("=").collect(); // Split by =
        assert_eq!(s_split2.len(), 2, "kv_parse assert error"); // verify there are indeed 2 arguments add
        hmap.insert(String::from(s_split2[0]), String::from(s_split2[1])); // add o hmap
    }
    return hmap;
}
pub fn kv_encode(hmap: IndexMap<String, String>) -> String {
    let mut s = String::new();
    for (key, value) in &hmap {
        s += &format!("{}={}&", key, value);
    }
    s.pop();
    return s;
}

struct ProfileMaker {
    uid: u32,
    key: Vec<u8>,
}
impl ProfileMaker {
    fn new() -> ProfileMaker {
        let mut rng = rand::thread_rng();
        let key = (0..16).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        return ProfileMaker { uid: 0, key: key };
    }
    fn profile_for(&mut self, s: &str) -> Option<String> {
        if s.contains('=') || s.contains('&') {
            return None;
        }
        let mut profile: IndexMap<String, String> = IndexMap::new();
        profile.insert(String::from("email"), String::from(s));
        profile.insert(String::from("uid"), String::from("10"));
        profile.insert(String::from("role"), String::from("user"));
        self.uid += 1;
        return Some(kv_encode(profile));
    }

    fn encrypt_profile(&self, s: &str) -> Vec<u8> {
        let s = s.as_bytes();
        let s = pkcs7_pad(s, None);
        let ciphertext = aes_encrypt(&s, &self.key);
        return ciphertext;
    }
    fn decrypt_profile(&self, ciphertext: &[u8]) -> IndexMap<String, String> {
        let profile = aes_decrypt(ciphertext, &self.key);
        let profile = u8_to_ascii(&pkcs7_unpad(&profile).unwrap());
        return kv_parse(&profile);
    }
}

pub fn challenge13() {
    println!("Test stuff");
    let s = "foo=bar&baz=qux&zap=zazzle";
    let hmap = kv_parse(s);
    println!("kv parse: {:?}", hmap);
    println!("kv encode: {}", kv_encode(hmap));

    let mut pm = ProfileMaker::new();
    let email = "foo@bar.com";

    let profile = pm.profile_for(&email).unwrap();
    println!("profile_for function {}", profile);

    let profile_encrypted = pm.encrypt_profile(&profile);
    println!("encrypted: {}", u8_to_ascii(&profile_encrypted));
    let profile_decrypted = pm.decrypt_profile(&profile_encrypted);
    println!("decrypted: {:?}", profile_decrypted);
    println!();
    println!("Start breaking cut and paste");
    // Step 1
    // "email=".len() = 6 -> complete with 10 `A` for block1
    //block 1 = email=AAAAAAAAAA
    let mut email1 = vec![65 as u8; 10];
    //block2 = admin + pad
    email1.extend(pkcs7_pad(b"admin", None));
    let profile = pm.profile_for(&u8_to_ascii(&email1)).unwrap();
    let ciphertext1 = pm.encrypt_profile(&profile);

    // Step 2
    //we want the following blocks: email=abcde@XYZ. || com&uid=10&role= || user + pad
    let mut email2 = b"abcde@XYZ.".to_vec(); // for the 1st block
    email2.extend(b"com"); // start of the 2nd block
    let profile = pm.profile_for(&u8_to_ascii(&email2)).unwrap();
    let ciphertext2 = pm.encrypt_profile(&profile);

    //forged ciphertext
    let mut forged_ciphertext = [0; 48];
    forged_ciphertext[..32].copy_from_slice(&ciphertext2[..32]);
    forged_ciphertext[32..48].copy_from_slice(&ciphertext1[16..32]);

    let profile_decrypted = pm.decrypt_profile(&forged_ciphertext);
    println!("{:?}", profile_decrypted);
}
