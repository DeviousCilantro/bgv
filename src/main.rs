use std::io::{self, Write};
use rug::Integer;
use ring::rand::{SystemRandom, SecureRandom};
use xxcalc::polynomial::Polynomial;

fn generate_range(rng: &dyn SecureRandom, lower_bound: i32, upper_bound: i32) -> f64 {
    let mut buf = [0u8; 4];
    loop {
        rng.fill(&mut buf).unwrap();
        let val = u32::from_le_bytes(buf);
        let random = lower_bound + (i64::from(val) % ((upper_bound - lower_bound + 1) as i64)) as i32;
        if random >= lower_bound && random <= upper_bound {
            return f64::from(random);
        }
    }
}

fn poly_modulo(polynomial: Polynomial, modulus: Polynomial) -> Polynomial {
    polynomial.clone() - ((polynomial / modulus.clone()) * modulus)
}

fn coeff_modulo(coeff_vec: &mut Polynomial, modulus: f64) -> Polynomial {
    for i in 0..=coeff_vec.degree() {
        coeff_vec[i] = coeff_vec[i].rem_euclid(modulus);
    }
    coeff_vec.clone()
}

fn generate_keypair() -> (Polynomial, (Polynomial, Polynomial)) {
    let rng = SystemRandom::new();

    let mut modulus_coefficients = vec![0.0; 2049];
    modulus_coefficients[0] = 1.0;
    modulus_coefficients[2048] = 1.0;
    let modulus = Polynomial::new(modulus_coefficients.as_slice());

    let mut sk: Polynomial = Polynomial::new(&[1.0; 2048]);
    let mut e: Polynomial = Polynomial::new(&[1.0; 2048]);
    let mut a: Polynomial = Polynomial::new(&[1.0; 2048]);

    for i in 0..2048 {
        sk[i]   = generate_range(&rng, -1, 1);
        e[i]    = generate_range(&rng, -1, 1);
        a[i]    = generate_range(&rng, 0, 65535);
    }

    let mut sum = poly_modulo(a.clone() * sk.clone(), modulus) + (e.clone() * Polynomial::constant(2.0));

    sum *= Polynomial::constant(-1.0);

    let pk1 = coeff_modulo(&mut sum, 65536.0);
    let mut pk2 = a;

    pk2 = coeff_modulo(&mut pk2, 65536.0);

    (sk, (pk1, pk2))

}

fn integer_to_polynomial(integer: &Integer) -> Polynomial {
    let plaintext = format!("{integer:b}");
    let mut plaintext_coefficients = Vec::new();

    for character in plaintext.chars() {
        if character == '0' {
            plaintext_coefficients.push(0.0);
        } else {
            plaintext_coefficients.push(1.0);
        }
    }

    plaintext_coefficients.reverse();

    Polynomial::new(plaintext_coefficients.as_slice())

}

fn encrypt_plaintext(pk: (Polynomial, Polynomial), plaintext: &Integer) -> (Polynomial, Polynomial) {
    let plaintext = integer_to_polynomial(plaintext);
    let (pk1, pk2) = pk;
    let rng = SystemRandom::new();
    let mut modulus_coefficients = vec![0.0; 2049];
    modulus_coefficients[0] = 1.0;
    modulus_coefficients[2048] = 1.0;
    let modulus = Polynomial::new(modulus_coefficients.as_slice());
    let mut u: Polynomial = Polynomial::new(&[1.0; 2048]);
    let mut e1: Polynomial = Polynomial::new(&[1.0; 2048]);
    let mut e2: Polynomial = Polynomial::new(&[1.0; 2048]);

    for i in 0..2048 {
        u[i]  = generate_range(&rng, -1, 1);
        e1[i]  = generate_range(&rng, -1, 1);
        e2[i]  = generate_range(&rng, -1, 1);
    }

    let mut c1 = poly_modulo(pk1 * u.clone(), modulus.clone()) + (e1.clone() * Polynomial::constant(2.0)) + plaintext.clone();
    let mut c2 = poly_modulo(pk2 * u.clone(), modulus) + (e2.clone() * Polynomial::constant(2.0));

    c1 = coeff_modulo(&mut c1, 65536.0);
    c2 = coeff_modulo(&mut c2, 65536.0);

    (c1, c2)

}

fn decrypt_ciphertext(ciphertext: (Polynomial, Polynomial), sk: Polynomial) -> Integer { 
    let (c1, c2) = ciphertext;
    let mut plaintext_coefficients: Vec<f64> = Vec::new();
    let mut modulus_coefficients = vec![0.0; 2049];
    modulus_coefficients[0] = 1.0;
    modulus_coefficients[2048] = 1.0;
    let modulus = Polynomial::new(modulus_coefficients.as_slice());

    let mut sum = poly_modulo(c2 * sk, modulus) + c1;

    sum = coeff_modulo(&mut sum, 65536.0);

    sum = coeff_modulo(&mut sum, 2.0);

    let mut carry: f64 = 0.0;

    for i in 0..2048 {
        if sum[i] >= 2.0 {
            if carry == 0.0 {
                plaintext_coefficients.push(0.0);
                carry = 1.0;
            } else {
                plaintext_coefficients.push(1.0);
                carry = 1.0;
            }
        } else if sum[i] == 1.0 {
            if carry == 0.0 {
                plaintext_coefficients.push(1.0);
            } else {
                plaintext_coefficients.push(0.0);
                carry = 1.0;
            }
        } else if carry == 0.0 {
            plaintext_coefficients.push(0.0);
        } else {
            plaintext_coefficients.push(1.0);
            carry = 0.0;
        }
    }

    plaintext_coefficients.reverse();

    let plaintext: String = plaintext_coefficients.iter()
        .map(std::string::ToString::to_string)
        .collect::<String>();

    Integer::from_str_radix(&plaintext, 2).unwrap()

}

fn main() {
    let (sk, pk) = generate_keypair();
    print!("\nEnter the plaintext: ");
    let mut input = String::new();
    io::stdout().flush().unwrap();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = input.trim();
    let plaintext = Integer::from_str_radix(&hex::encode(input), 16).unwrap();
    let ciphertext = encrypt_plaintext(pk.clone(), &plaintext);
    println!("\nEncrypted ciphertext: ({}, {})", ciphertext.0, ciphertext.1);
    let output_plaintext = decrypt_ciphertext(ciphertext, sk.clone());
    let output_plaintext = String::from_utf8(hex::decode(format!("{:X}", &output_plaintext)).unwrap()).unwrap();
    println!("\nDecrypted plaintext: {output_plaintext}");
    assert_eq!(output_plaintext, input, "Correctness not verified.");
    println!("\nCorrectness verified.");
}
