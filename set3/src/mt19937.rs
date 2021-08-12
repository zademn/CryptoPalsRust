use std::usize;

pub fn get_lowest_bits(n: usize, num_bits: usize) -> usize {
    // Return the lowest num_bits of n
    (n & ((1  << num_bits) - 1)) as usize
}
// 64 bit system, on 32b I would've implemented with Wrapping
#[derive(Default, Debug)]
pub struct Mt19937 {
    pub w: usize,
    pub n: usize,
    pub m: usize,
    pub r: usize,
    pub a: usize,
    pub u: usize,
    pub d: usize,
    pub s: usize,
    pub b: usize,
    pub t: usize,
    pub c: usize,
    pub l: usize,
    pub f: usize,
    pub state: Vec<usize>,
    index: usize,
    upper_mask: usize,
    lower_mask: usize,
}
impl Mt19937 {
    pub fn new(seed: Option<usize>) -> Mt19937 {
        let mut mt = Mt19937 {
            w: 32,         // word size (in number of bits)
            n: 624,        // degree of recurrence
            m: 397,        // middle word, an offset
            r: 31,         // separation point of one word
            a: 0x9908B0DF_usize, // coefficients of the rational normal form twist matrix
            u: 11,         // additional Mersenne Twister tempering bit shifts/masks
            d: 0xFFFFFFFF_usize, // additional Mersenne Twister tempering bit shifts/masks
            s: 7,          // TGFSR(R) tempering bit shifts
            b: 0x9D2C5680_usize, // TGFSR(R) tempering bitmasks
            t: 15,         // TGFSR(R) tempering bit shifts
            c: 0xEFC60000_usize,   // TGFSR(R) tempering bitmasks
            l: 18,         // additional Mersenne Twister tempering bit shifts/masks
            f: 1812433253_usize,
            ..Default::default()
        };
        mt.lower_mask = (1_usize << mt.r) - 1_usize;
        mt.upper_mask = get_lowest_bits((!mt.lower_mask) as usize, mt.w);
        //println!("{:?}", mt);
        mt.index = mt.n + 1;
        
        match seed {
            Some(seed) => mt.seed(seed),
            None => mt.seed(5489_usize),
        }
        mt
    }
    pub fn seed(&mut self, seed: usize) {
        self.state.resize(self.n, 0_usize);
        self.index = self.n;
        self.state[0] = seed;
        for i in 1..self.n {
            self.state[i] = get_lowest_bits(
                (self.f * (self.state[i - 1] ^ (self.state[i - 1] >> (self.w - 2)))) + i,
                self.w,
            );
        }
    }

    pub fn extract_number(&mut self) -> Result<usize, String>{
        if self.index >= self.n {
            if self.index > self.n {
                return Err(String::from("Generator was never seeded"))
            }
            self.twist();
        }
        let mut y: usize = self.state[self.index];
        y = y ^ ((y >> self.u) & self.d);
        y = y ^ ((y << self.s) & self.b);
        y = y ^ ((y << self.t) & self.c);
        y = y ^ (y >> self.l);
        self.index+=1;
        
        Ok(get_lowest_bits(y, self.w))
    }

    fn twist(&mut self){
        for i in 0..self.n{
            let x = (self.state[i] & self.upper_mask) + (self.state[(i+1) % self.n] & self.lower_mask);
            let mut x_a = x >> 1;
            if (x % 2) != 0 {
                x_a ^= self.a;
            }
            self.state[i] = self.state[(i + self.m) % self.n] ^ x_a;
        }
        self.index = 0;
    }
}

pub fn challenge21() {
    println!("lowest bits test: {}", get_lowest_bits(255, 5));
    let mut mt = Mt19937::new(Some(123));
    for _ in 0..10{
        println!("{}", mt.extract_number().unwrap());
    }
}
