mod number;
use number::{random_bytes, u8_to_ascii};

fn main() {
    let s = b"dkljasdklasjclaksmcal()*9080980932";
    println!("{}", u8_to_ascii(s));
    println!("{:?}", random_bytes(10));
}
