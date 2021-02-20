pub fn pkcs7_unpad(s: &[u8]) -> Result<Vec<u8>, String> {
    let padding_number = s[s.len() - 1];
    // check padding
    if s.len() < padding_number as usize {
        return Err(String::from("Invalid padding"));
    }
    
    let res_len = s.len() - padding_number as usize;
    if s[res_len..].iter().any(|&x| x != padding_number) {
        return Err(String::from("Invalid padding"));
    }
    let mut res = vec![0 as u8; res_len];
    res[..].clone_from_slice(&s[..res_len]);
    return Ok(res);
}

pub fn pkcs7_pad(s: &[u8], padded_block_len: Option<usize>) -> Vec<u8> {
    // padded_block_len is the final length
    let n = s.len();

    let mut padded_block_len = padded_block_len.unwrap_or((n / 16 + 1) * 16); // 16B blocks
    if padded_block_len <= n {
        padded_block_len = (n / 16 + 1) * 16;
    }
    let padding_number = padded_block_len - n;

    let mut res: Vec<u8> = vec![padding_number as u8; padded_block_len];
    res[..n].clone_from_slice(s);
    return res;
}

pub fn challenge9() {
    let s = "YELLOW SUBMARINE";

    let mut s_pad = pkcs7_pad(s.as_bytes(), Some(20));
    let s_pad_len = s_pad.len();
    println!("{:?}", s_pad);
    let s_unpad = pkcs7_unpad(&s_pad).unwrap();
    println!("{:?}", s_unpad);

    // Invalid padding
    s_pad[s_pad_len - 2..].copy_from_slice(&[2, 3]);
    let mut s_unpad: Vec<u8> = Vec::new();
    match pkcs7_unpad(&s_pad) {
        Ok(v) => {
            s_unpad = v;
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }
    println!("{:?}", s_unpad);
}
