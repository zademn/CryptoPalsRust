mod number;
mod algorithms;
use num_bigint::{BigInt, BigUint};
use number::{random_bytes, u8_to_ascii};
use ramp::Int;
use algorithms::mod_inv;

fn main() {
    // let s = b"dkljasdklasjclaksmcal()*9080980932";
    // println!("{}", u8_to_ascii(s));
    // println!("{:?}", random_bytes(10));
    // let x = BigUint::parse_bytes(b"1234", 10).unwrap();
    // let y = BigUint::parse_bytes(b"2", 10).unwrap();
    // let z = BigUint::from(10 as usize);
    // println!("{}", x);
    // println!("{}", &x * y);
    // println!("{}", x >> 2);
    // println!("{}", z >> 2);

    // let x = Int::from(1) << 128;
    // let y = Int::from(2);
    // println!("{}", x);
    // println!("{}", &x * y);
    // println!("{}", x >> 2);

    let x = BigInt::from(11);
    let y = BigInt::from(4);
    println!("{:?}", mod_inv(&y, &x));



}
