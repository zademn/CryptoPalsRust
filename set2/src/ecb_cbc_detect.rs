use crate::cbc_using_ecb::CbcOracle;
use crate::oracle::Encrypt;
use crate::pkcs7_padding;
use rand::Rng;
use set1::aes_ecb::aes_encrypt;
use set1::detect_ecb::detect_ecb;

pub fn get_ciphertext(s: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let n1 = rng.gen_range(5..11);
    let n2 = rng.gen_range(5..11);
    let b1 = (0..n1).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
    let b2 = (0..n2).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();

    //println!("{}, {}, {}", n1, s.len(), n2);

    let mut buf: Vec<u8> = vec![0; n1 + s.len() + n2];
    buf[..n1].clone_from_slice(&b1);
    buf[n1..n1 + s.len()].clone_from_slice(s);
    buf[n1 + s.len()..n1 + s.len() + n2].clone_from_slice(&b2);

    let buf = pkcs7_padding::pkcs7_pad(&buf, None);

    let y: f64 = rng.gen();
    if y > 0.5 {
        println!("Generated CBC");
        let oracle = CbcOracle::new(None);
        let iv = (0..16).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        return oracle.encrypt(&buf, &iv);
    } else {
        println!("Generated ECB");
        let key = (0..16).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        return aes_encrypt(&buf, &key);
    }
}

pub fn challenge11() {
    let s: [u8; 100] = [65; 100];
    for _ in (0..10) {
        let ciphertext = get_ciphertext(&s);
        if detect_ecb(&ciphertext) {
            println!("Detected ECB");
        } else {
            println!("Detected CBC");
        }
    }
}
