use base64; //add these in dependencies
use hex;

pub fn hex_to_b64(s: &str) -> String {
    return base64::encode(hex::decode(s).unwrap());
}

pub fn challenge1(){
    let s = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    println!("{}", hex_to_b64(s));
}
