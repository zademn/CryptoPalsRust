use crate::mt19937::Mt19937;

pub fn get_i_lsb(n: usize, i: usize) -> usize {
    return (n & (1 << (i))) >> i;
}
pub fn untemper_shift_right(y: usize, a: usize) -> usize {
    // y = y ^ (y >> a)
    // 5b example let y = x ^ (x >> 2)
    //   x4 x3 x2 x1 x0
    // ^       x4 x3 x2
    // = y4 y3 y2 y1 y0
    //
    // y2 = x4 ^ x2 = y4 ^ x2 => x2 = y2 ^ y4
    //
    // => x4x3= y4y3 and x2 = y2 ^ x4, x1 = y1 ^ x3, x0 = y0 ^ x2

    let mut x: usize = 0;
    let mask_32b = 0xffff_ffff;
    let mask_msb = (mask_32b << (32 - a)) & mask_32b; // the first `a` msb

    x = y & mask_msb; // copy the first `a` msb
    for (j, i) in (0..32 - a).rev().enumerate() {
        x = x | ((get_i_lsb(y, i) ^ get_i_lsb(x, 31 - j)) << i);
    }

    return x & mask_32b;
}

pub fn untemper_shift_left(y: usize, a: usize, t: usize) -> usize {
    // y = y ^ ((y << a) & t)
    // 5b example let y = x ^ ((x << 2) & t)
    //   x4 x3 x2 x1 x0
    // ^ x2 x1 x0
    // & t4 t3 t2
    // = y4 y3 y2 y1 y0
    //
    // x1x0 = y1y0
    // x_{i+a} = (xi & ti) ^ y_{i+a}

    let mut x: usize = 0;
    let mask_32b = 0xffff_ffff;
    let mask_lsb = (1 << a) - 1; // the last `a` lsbs

    x = y & mask_lsb; // copy the last `a` lsbs
    for i in (0..32 - a) {
        x = x | (((get_i_lsb(x, i) & get_i_lsb(t, i + a)) ^ get_i_lsb(y, i + a)) << (i + a));
        x = x & mask_32b;
    }
    return x & mask_32b;
}

pub fn untemper(y: usize, mt: &Mt19937) -> usize {
    let mut res = y;
    res = untemper_shift_right(y, mt.l);
    res = untemper_shift_left(res, mt.t, mt.c);
    res = untemper_shift_left(res, mt.s, mt.b);
    res = untemper_shift_right(res, mt.u);

    return res;
}
pub fn challenge23() {
    println!("Test untempering...");
    let x = 1234512345 & 0xffff_ffff;
    let a = 12;
    //let y: usize = x ^ (x >> a);
    println!("x {}", x);
    println!("x {}", untemper_shift_right(x ^ (x >> a), a));
    println!(
        "x {}",
        untemper_shift_left(x ^ ((x << a) & 54321), a, 54321)
    );

    println!();
    println!("Challenge...");
    let seed = 123;
    let mut mt = Mt19937::new(Some(seed));

    // get outputs
    let outputs: Vec<usize> = (0..624)
        .into_iter()
        .map(|_| mt.extract_number().unwrap())
        .collect();

    // clone
    let state_cloned: Vec<usize> = outputs.iter().map(|out| untemper(*out, &mt)).collect();
    let mut mt_cloned = Mt19937::new(None);
    mt_cloned.state = state_cloned;

    // check outputs
    let outputs: Vec<usize> = (0..10)
        .into_iter()
        .map(|_| mt.extract_number().unwrap())
        .collect();

    let outputs_cloned: Vec<usize> = (0..10)
        .into_iter()
        .map(|_| mt_cloned.extract_number().unwrap())
        .collect();

    println!("{:?}", outputs);
    println!("{:?}", outputs_cloned);
}
