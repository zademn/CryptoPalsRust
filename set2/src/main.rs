mod byte_at_a_time_ecb;
mod byte_at_a_time_ecb2;
mod cbc_using_ecb;
mod ecb_cbc_detect;
mod ecb_cut_and_paste;
mod oracle;
mod pkcs7_padding;
mod bitflipping;
fn main() {
    //pkcs7_padding::challenge9();
    //cbc_using_ecb::challenge10();
    //ecb_cbc_detect::challenge11();
    //byte_at_a_time_ecb::challenge12();
    //ecb_cut_and_paste::challenge13();
    //byte_at_a_time_ecb2::challenge14();
    bitflipping::challenge16();
}
