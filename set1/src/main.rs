mod aes_ecb;
#[allow(unused_must_use)]
mod break_rep_key_xor;
mod detect_xor;
mod detect_ecb;
mod fixed_xor;
mod hex_to_b64;
mod repeated_xor;
mod single_byte_xor;

fn main() {
    //hex_to_b64::challenge1();
    //fixed_xor::challenge2();
    //single_byte_xor::challenge3();
    //detect_xor::challenge4();
    //repeated_xor::challenge5();
    //break_rep_key_xor::challenge6();
    //aes_ecb::challenge7();
    detect_ecb::challenge8();
}
