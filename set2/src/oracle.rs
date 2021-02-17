pub trait Encrypt{
    fn encrypt(&self, plaintext: &[u8], iv: &[u8]) -> Vec<u8>;
}