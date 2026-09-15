use tfhe_goldilocks::glwe::GlweSecretKey;
use tfhe_goldilocks::keygen::{gen_bootstrapping_key, gen_key_switching_key};
use tfhe_goldilocks::lwe::LweSecretKey;
use tfhe_goldilocks::ntt::NttContext;
use tfhe_goldilocks::params::T_PLAIN;
use tfhe_goldilocks::pbs::programmable_bootstrap;

use rand::rngs::StdRng;
use rand::SeedableRng;
use std::time::Instant;

fn main() {
    println!("=== TFHE PBS over Goldilocks Field ===");
    println!("Q = 2^64 - 2^32 + 1 (Goldilocks prime)");
    println!("n = 728, N = 1024, B = 256, l = 8, t = 4\n");

    let mut rng = StdRng::seed_from_u64(2024);
    let ctx = NttContext::new();

    println!("Generating keys...");
    let lwe_sk = LweSecretKey::generate(&mut rng);
    let glwe_sk = GlweSecretKey::generate(&mut rng);

    println!("Generating bootstrapping key (this may take a while)...");
    let bsk = gen_bootstrapping_key(&lwe_sk, &glwe_sk, &ctx, &mut rng);

    println!("Generating key-switching key...");
    let ksk = gen_key_switching_key(&lwe_sk, &glwe_sk, &mut rng);

    // Identity LUT: f(m) = m
    let lut_identity: [u64; 4] = [0, 1, 2, 3];
    println!("\n--- Testing Identity LUT: f(m) = m ---");
    test_lut(&lwe_sk, &lut_identity, &bsk, &ksk, &ctx, &mut rng, |m| m);

    // Complement LUT: f(m) = 3 - m
    let lut_complement: [u64; 4] = [3, 2, 1, 0];
    println!("\n--- Testing Complement LUT: f(m) = 3 - m ---");
    test_lut(&lwe_sk, &lut_complement, &bsk, &ksk, &ctx, &mut rng, |m| {
        3 - m
    });

    // Square LUT: f(m) = m^2 mod 4
    let lut_square: [u64; 4] = [0, 1, 0, 1];
    println!("\n--- Testing Square LUT: f(m) = m^2 mod 4 ---");
    test_lut(&lwe_sk, &lut_square, &bsk, &ksk, &ctx, &mut rng, |m| {
        (m * m) % T_PLAIN
    });

    // Timing: run a single PBS and measure
    println!("\n--- PBS Timing ---");
    let ct_bench = lwe_sk.encrypt(1, &mut rng);
    let start = Instant::now();
    let _ct_out = programmable_bootstrap(&ct_bench, &lut_identity, &bsk, &ksk, &ctx);
    let elapsed = start.elapsed();
    println!(
        "  Single PBS time: {:.3} ms",
        elapsed.as_secs_f64() * 1000.0
    );

    println!("\nAll tests passed!");
}

fn test_lut<R: rand::Rng, F: Fn(u64) -> u64>(
    lwe_sk: &LweSecretKey,
    lut: &[u64; 4],
    bsk: &tfhe_goldilocks::keygen::BootstrappingKey,
    ksk: &tfhe_goldilocks::keygen::KeySwitchingKey,
    ctx: &NttContext,
    rng: &mut R,
    expected_fn: F,
) {
    for m in 0..T_PLAIN {
        let ct = lwe_sk.encrypt(m, rng);
        let ct_out = programmable_bootstrap(&ct, lut, bsk, ksk, ctx);
        let decrypted = lwe_sk.decrypt(&ct_out);
        let expected = expected_fn(m);
        let status = if decrypted == expected { "OK" } else { "FAIL" };
        println!(
            "  f({}) = {} (decrypted: {}) [{}]",
            m, expected, decrypted, status
        );
        assert_eq!(decrypted, expected, "PBS failed for m={}", m);
    }
}
