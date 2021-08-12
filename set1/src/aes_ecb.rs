use aes::Aes128;
use block_modes::block_padding::NoPadding;
use block_modes::BlockMode;
use block_modes::Ecb;

#[allow(dead_code)]
pub fn aes_encrypt(messsage: &[u8], key: &[u8]) -> Vec<u8> {
    // check len to be a multiple of 16, we let the user take care of the padding
    assert_eq!(messsage.len() % 16, 0);

    type Aes128Ecb = Ecb<Aes128, NoPadding>;
    let iv: [u8; 16] = Default::default();
    let cipher = Aes128Ecb::new_from_slices(key, &iv).unwrap();

    let ciphertext = cipher.encrypt_vec(&messsage);

    return ciphertext;
}
#[allow(dead_code)]
pub fn aes_decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    // check len to be a multiple of 16
    assert_eq!(ciphertext.len() % 16, 0);

    //Create AES block
    type AES128ECB = Ecb<Aes128, NoPadding>;
    let iv: [u8; 16] = Default::default();
    let cipher = AES128ECB::new_from_slices(key, &iv).unwrap();

    let message = cipher.decrypt_vec(&ciphertext).unwrap();

    return message;
}


#[cfg(test)]
mod tests {
    use super::*;
    use base64;
    use reqwest;
    use std::error::Error;
    use utils::number::u8_to_ascii;

    #[test]
    fn challenge7() -> Result<(), Box<dyn Error>> {
        println!("Fetching data...");
        let recv =
            reqwest::blocking::get("https://cryptopals.com/static/challenge-data/7.txt")?.text()?;
        let recv_split: Vec<_> = recv.split("\n").collect(); //split the strings
        let ciphertext: String = recv_split[0..recv_split.len() - 1]
            .iter()
            .map(|s| *s)
            .collect(); // split into bytes
        //dbg!(&ciphertext);
    
        println!("Decrypting...");
        //aes cipher
        let key = b"YELLOW SUBMARINE";
        println!("{}", ciphertext.len());
        let buf = base64::decode(ciphertext).unwrap();
        let message = aes_decrypt(&buf, key);
        //println!("{:?}", std::str::from_utf8(&message));
        println!("{}", u8_to_ascii(&message));
    
        return Ok(());
    }
}

