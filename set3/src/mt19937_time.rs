use crate::mt19937::Mt19937;
use rand::{Rng};

use std::time::{SystemTime, UNIX_EPOCH};

pub fn time_rng() -> (usize, usize) {
    let mut rng = rand::thread_rng();
    let t1 = rng.gen_range(40..1001);
    let mut now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    println!("{:?}", now);
    now += t1; // simulate waiting

    println!("Rng seed: {}", now);
    let mut mt = Mt19937::new(Some(now as usize));

    let t2 = rng.gen_range(40..1001);
    now += t2; // simulate waiting
    (mt.extract_number().unwrap(), now as usize)
}
pub fn challenge22() {
    let (num, mut now) = time_rng();
    println!("Time now: {}", now);
    loop {
        let mut mt = Mt19937::new(Some(now));
        if mt.extract_number().unwrap() == num {
            println!("Found seed: {}", now);
            break;
        }
        now -= 1; // decrease guess
    }
}
