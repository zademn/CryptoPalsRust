use num_bigint::algorithms::xgcd;
use num_bigint::BigInt;
use num_traits::{One, Zero};

// pub fn mod_inv(n: &BigInt, modulus: &BigInt) -> BigInt {
//     let (zero, one): (BigInt, BigInt) = (Zero::zero(), One::one());
//     let mut mn = (modulus.clone(), n.clone());
//     let mut xy: (BigInt, BigInt) = (Zero::zero(), One::one());

//     while mn.1 != zero {
//         xy = (xy.1.clone(), &xy.0 - &(&mn.0 / &mn.1) * &xy.1);
//         mn = (mn.1.clone(), &mn.0 % &mn.1);
//     }

//     while xy.0 < zero {
//         xy.0 += modulus;
//     }
//     xy.0.clone()
// }

pub fn mod_inv(n: &BigInt, modulus: &BigInt) -> Option<BigInt> {
    let (g, n, _) = xgcd(n, modulus, true);
    let n = n.unwrap();
    if g == BigInt::from(1) {
        Some((n % modulus + modulus) % modulus)
    } else {
        None
    }
}

pub fn crt(residues: Vec<BigInt>, moduli: Vec<BigInt>) -> Option<BigInt> {
    let prod = moduli.iter().product::<BigInt>();
    let mut sum = BigInt::from(0);

    for (residue, modulus) in residues.iter().zip(moduli) {
        let p = &prod / &modulus;
        sum += residue * mod_inv(&p, &modulus)? * p
    }

    return Some(sum % prod);
}
