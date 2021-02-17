use rand::Rng;

pub fn u8_to_ascii(s: &[u8]) -> String {
    return s.iter().map(|x| *x as char).collect::<String>();
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let res = (0..n).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
    return res;
}
