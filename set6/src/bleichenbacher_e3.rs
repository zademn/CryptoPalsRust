use set5::rsa::Rsa;


use regex::bytes;
// Attack: https://mailarchive.ietf.org/arch/msg/openpgp/5rnE9ZRN1AokBVj3VqblGlP63QE/

// more functions for rsa
trait Signature{
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
    fn verify(&self, signature: &[u8], msg: &[u8]) -> bool;
}

impl Signature for Rsa{
    fn sign(&self, msg: &[u8]) -> Vec<u8>{
        self.decrypt(&msg)
    }
    fn verify(&self, signature: &[u8], _msg: &[u8]) -> bool{

        let re = bytes::Regex::new(r"^\x00\x01\xff+?\x00.{15}(.{20})").unwrap();
        // .{15} for asn1
        // .{20} for the hash of the message

        if !re.is_match(signature){
            return false;
        }
        
        false
    }
}

pub fn challenge42(){

}