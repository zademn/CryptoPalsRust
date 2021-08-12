use std::env;
use std::error::Error;

// set 1
use set1::aes_ecb::challenge7;
use set1::break_rep_key_xor::challenge6;
use set1::detect_ecb::challenge8;
use set1::detect_xor::challenge4;
use set1::fixed_xor::challenge2;
use set1::hex_to_b64::challenge1;
use set1::repeated_xor::challenge5;
use set1::single_byte_xor::challenge3;

// set 2
use ::set2::bitflipping::challenge16;
use ::set2::byte_at_a_time_ecb::challenge12;
use ::set2::byte_at_a_time_ecb2::challenge14;
use ::set2::cbc_using_ecb::challenge10;
use ::set2::ecb_cbc_detect::challenge11;
use ::set2::ecb_cut_and_paste::challenge13;
use ::set2::pkcs7_padding::challenge9;

// set 3
use set3::cbc_padding_oracle::challenge17;
use set3::ctr::challenge18;
use set3::fixed_nonce_ctr_sub::challenge19_20;
use set3::mt19937::challenge21;
use set3::mt19937_clone::challenge23;
use set3::mt19937_time::challenge22;

// set 4
// set 5
use set5::diffie_hellman::challenge33;
use set5::mitm_key_fixing::challenge34;
use set5::negotiated_groups::challenge35;
use set5::rsa::challenge39;
use set5::rsa_broadcast::challenge40;
use set5::srp::challenge36;
use set5::srp_zero_key::challenge37;

// set 6

use set6::bleichenbacher_e3::challenge42;
use set6::dsa::challenge43;
use set6::message_recovery::challenge41;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    let challenge_number = &args[1];
    match challenge_number.as_str() {
        "1" => challenge1(),
        "2" => challenge2(),
        "3" => challenge3(),
        "4" => challenge4()?,
        "5" => challenge5(),
        "6" => challenge6()?,
        "7" => challenge7()?,
        "8" => challenge8()?,
        "9" => challenge9(),
        "10" => challenge10()?,
        "11" => challenge11(),
        "12" => challenge12(),
        "13" => challenge13(),
        "14" => challenge14(),
        //"15" => challenge15(),
        "16" => challenge16(),
        "17" => challenge17(),
        "18" => challenge18(),
        "19" => challenge19_20(),
        //"20" => challenge20(),
        "21" => challenge21(),
        "22" => challenge22(),
        "23" => challenge23(),
        //"24" => challenge24(),
        // "25" => challenge25(),
        // "26" => challenge26(),
        // "27" => challenge27(),
        // "28" => challenge28(),
        // "29" => challenge29(),
        // "30" => challenge30(),
        // "31" => challenge31(),
        // "32" => challenge32(),
        "33" => challenge33(),
        "34" => challenge34(),
        "35" => challenge35(),
        "36" => challenge36(),
        "37" => challenge37(),
        //"38" => challenge38(),
        "39" => challenge39(),
        "40" => challenge40(),
        "41" => challenge41(),
        "42" => challenge42(),
        "43" => challenge43(),
        _ => panic!("Invalid challenge number"),
    }

    Ok(())
}
