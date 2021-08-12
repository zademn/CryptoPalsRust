mod aes_ecb;
#[allow(unused_must_use)]
mod break_rep_key_xor;
mod detect_ecb;
mod detect_xor;
mod fixed_xor;
mod hex_to_b64;
mod repeated_xor;
mod single_byte_xor;

use aes_ecb::challenge7;
use break_rep_key_xor::challenge6;
use detect_ecb::challenge8;
use detect_xor::challenge4;
use fixed_xor::challenge2;
use hex_to_b64::challenge1;
use repeated_xor::challenge5;
use single_byte_xor::challenge3;

fn main() {
    // challenge1();
    // challenge2();
    // challenge3();
    // challenge4();
    // challenge5();
    // challenge6();
    // challenge7();
    challenge8();
}
