use std::time::Instant;

use p3_batch_stark::{
    prove_batch, prove_batch_with_northstar, verify_batch, verify_batch_with_northstar, ProverData,
    StarkInstance,
};
use p3_field::{PrimeField64, TwoAdicField};
use p3_matrix::Matrix;

use rand::rngs::StdRng;
use rand::SeedableRng;

use tfhe_goldilocks::field::GF;
use tfhe_goldilocks::glwe::GlweSecretKey;
use tfhe_goldilocks::keygen::{
    gen_bootstrapping_key, gen_glwe_key_switching_key, gen_key_switching_key, make_s_out_poly,
};
use tfhe_goldilocks::lwe::LweSecretKey;
use tfhe_goldilocks::ntt::NttContext;
use tfhe_goldilocks::params::{DELTA, N_LWE, N_POLY, T_PLAIN};
use tfhe_goldilocks::pbs::programmable_bootstrap;
use tfhe_goldilocks::poly::Poly;

use vfhe::br_air::BlindRotateAir;
use vfhe::br_trace::{
    generate_blind_rotate_trace, generate_br_preprocessed, generate_br_public_values,
};
use vfhe::config::{make_test_config, Challenge, Val};
use vfhe::glwe_ks_air::GlweKsAir;
use vfhe::glwe_ks_trace::{
    generate_glwe_ks_preprocessed, generate_glwe_ks_trace, sample_extract_from_ntt,
};
use vfhe::ms_air::ModSwitchAir;
use vfhe::ms_trace::generate_ms_trace;
use vfhe::northstar_sumcheck::{compute_northstar_witness, make_northstar_verifier_data};

/// Build test vector (LUT) for function f: Z_t → Z_t.
/// Negacyclic encoding: tv[j] = Δ·f(floor(j·t/N)) for j = 0..N-1
fn make_test_vector<F: Fn(u64) -> u64>(f: F) -> Poly {
    let n = N_POLY as u64;
    let coeffs: Vec<GF> = (0..N_POLY)
        .map(|j| {
            let m = (j as u64 * T_PLAIN) / n;
            let fm = f(m % T_PLAIN);
            GF(DELTA.wrapping_mul(fm))
        })
        .collect();
    Poly::from_coeffs(coeffs)
}

fn main() {
    println!("=== VFHE: End-to-End Verifiable PBS ===\n");

    // ================================================================
    // OFFLINE PREPROCESSING (not timed — independent of ciphertext)
    // ================================================================
    println!("--- Offline Preprocessing (not timed) ---");
    let preprocess_start = Instant::now();

    let config = make_test_config();
    let ctx = NttContext::new();
    let mut rng = StdRng::seed_from_u64(0xFEE2_E0B5);

    // Key generation
    let lwe_sk = LweSecretKey::generate(&mut rng);
    let glwe_sk = GlweSecretKey::generate(&mut rng);
    println!("  Keys: LWE dim={}, GLWE N={}", N_LWE, N_POLY);

    // BSK[i] = GGSW_{glwe_sk}(lwe_sk[i])
    let bsk = gen_bootstrapping_key(&lwe_sk, &glwe_sk, &ctx, &mut rng);
    println!("  BSK: {} GGSW entries", bsk.entries.len());

    // GLWE KSK: switches from glwe_sk to s_out (embeds lwe_sk)
    let s_out_poly = make_s_out_poly(&lwe_sk);
    let glwe_ksk = gen_glwe_key_switching_key(&glwe_sk, &s_out_poly, &ctx, &mut rng);
    println!("  GLWE KSK: {} RLev entries", glwe_ksk.entries.len());

    // LUT: identity function f(m) = m
    let test_vector = make_test_vector(|m| m);
    println!("  LUT: identity f(m) = m, plaintext space Z_{}", T_PLAIN);

    // Blind Rotation's BSK and structural columns are static verifier-key data.
    let (br_preprocessed, br_setup_num_blocks) = generate_br_preprocessed(&bsk.entries);
    let mut br_air = BlindRotateAir {
        preprocessed: br_preprocessed,
        num_blocks: br_setup_num_blocks,
        public_values: vec![Val::new(0); br_setup_num_blocks + 3 * N_POLY],
    };
    let br_log_kn = p3_util::log2_strict_usize(br_setup_num_blocks * N_POLY);
    let br_prover_data =
        ProverData::from_airs_and_degrees(&config, std::slice::from_ref(&br_air), &[br_log_kn]);

    // LWE KSK (for reference PBS test only — VFHE uses GLWE KSK)
    let lwe_ksk = gen_key_switching_key(&lwe_sk, &glwe_sk, &mut rng);

    let preprocess_time = preprocess_start.elapsed();
    println!(
        "  Preprocessing time: {:.1} ms\n",
        preprocess_time.as_secs_f64() * 1000.0
    );

    // ================================================================
    // FHE CORRECTNESS TEST (all messages)
    // ================================================================
    println!("--- FHE Correctness Test (reference PBS, all messages) ---");
    let lut_arr: [u64; 4] = [0, 1, 2, 3]; // identity
    let mut all_pass = true;
    for m in 0..T_PLAIN {
        let ct = lwe_sk.encrypt(m, &mut rng);
        let ct_out = programmable_bootstrap(&ct, &lut_arr, &bsk, &lwe_ksk, &ctx);
        let decrypted = lwe_sk.decrypt(&ct_out);
        if decrypted != m {
            println!("  FAIL: f({}) = {} (expected {})", m, decrypted, m);
            all_pass = false;
        }
    }
    if all_pass {
        println!("  PASS: f(m) = m correct for all m in Z_{}", T_PLAIN);
    } else {
        println!("  WARNING: FHE decryption errors detected (noise too large?)");
    }

    // ================================================================
    // INPUT: Encrypt a message
    // ================================================================
    let message: u64 = 2;
    assert!(message < T_PLAIN);
    let ct_in = lwe_sk.encrypt(message, &mut rng);
    println!("--- Input ---");
    println!("  Plaintext: m = {} (in Z_{})", message, T_PLAIN);
    assert_eq!(
        lwe_sk.decrypt(&ct_in),
        message,
        "Input encryption check failed"
    );
    println!("  Encryption verified OK\n");

    // ================================================================
    // END-TO-END PROVER (timed)
    // ================================================================
    println!("--- End-to-End Prover ---");
    let prover_total_start = Instant::now();

    // ---- Modulus Switching ----
    let modulus_switch_start = Instant::now();
    let ms_trace = generate_ms_trace(&ct_in);
    let a_tilde_values = ms_trace.a_switched.clone();
    let b_prime = ms_trace.b_switched;

    let ms_air = ModSwitchAir {
        preprocessed: ms_trace.preprocessed.clone(),
    };
    let ms_instances = vec![StarkInstance {
        air: &ms_air,
        trace: &ms_trace.witness,
        public_values: vec![],
    }];
    let ms_prover_data = ProverData::from_instances(&config, &ms_instances);
    let ms_proof = prove_batch(&config, &ms_instances, &ms_prover_data);
    let modulus_switch_time = modulus_switch_start.elapsed();
    let ms_proof_size = postcard::to_allocvec(&ms_proof).unwrap().len();
    println!(
        "  Modulus Switching: {:.1} ms, {:.1} KB",
        modulus_switch_time.as_secs_f64() * 1000.0,
        ms_proof_size as f64 / 1024.0
    );

    // ---- Blind Rotation + Northstar ----
    let blind_rotation_start = Instant::now();
    let br_trace =
        generate_blind_rotate_trace(&a_tilde_values, b_prime, &test_vector, &bsk.entries);
    let br_num_blocks = br_trace.num_blocks;
    assert_eq!(br_num_blocks, br_setup_num_blocks);
    let br_pv = br_trace.public_values.clone();
    br_air.public_values.clone_from(&br_pv);
    let br_instances = vec![StarkInstance {
        air: &br_air,
        trace: &br_trace.witness,
        public_values: br_pv.clone(),
    }];
    let br_f_cols: Vec<usize> = (6..14).collect();
    let br_g_cols: Vec<usize> = (24..32).collect();
    let br_log_block: usize = 10;
    let br_psi_block: Val = Val::two_adic_generator(br_log_block + 1);
    let br_omega_kn: Val = Val::two_adic_generator(br_log_kn);

    let br_trace_ref = &br_trace.witness;
    let br_f_c = br_f_cols.clone();
    let br_g_c = br_g_cols.clone();
    let br_proof = prove_batch_with_northstar(
        &config,
        &br_instances,
        &br_prover_data,
        Some(|alpha_sc: Challenge, eta: Challenge, rho: Challenge| {
            compute_northstar_witness(
                br_trace_ref,
                &br_f_c,
                &br_g_c,
                alpha_sc,
                eta,
                rho,
                br_log_block,
                br_num_blocks,
                br_psi_block,
            )
        }),
    );
    let blind_rotation_time = blind_rotation_start.elapsed();
    let br_proof_size = postcard::to_allocvec(&br_proof).unwrap().len();
    println!(
        "  Blind Rotation + Northstar: {:.1} ms, {:.1} KB",
        blind_rotation_time.as_secs_f64() * 1000.0,
        br_proof_size as f64 / 1024.0
    );
    println!(
        "    {} blocks × 1024 = {} rows",
        br_num_blocks,
        br_num_blocks * 1024
    );

    // ---- GLWE Key Switching + Northstar ----
    let key_switch_start = Instant::now();
    let ks_trace = generate_glwe_ks_trace(&br_trace.final_acc, &glwe_ksk);
    let ks_pv = ks_trace.public_values.clone();

    let ks_air = GlweKsAir {
        preprocessed: ks_trace.preprocessed.clone(),
    };
    let ks_instances = vec![StarkInstance {
        air: &ks_air,
        trace: &ks_trace.witness,
        public_values: ks_pv.clone(),
    }];
    let ks_prover_data = ProverData::from_instances(&config, &ks_instances);

    let ks_f_cols: Vec<usize> = (1..9).collect();
    let ks_g_cols: Vec<usize> = (74..82).collect();
    let ks_log_block: usize = 10;
    let ks_num_blocks: usize = 1;
    let ks_psi_block: Val = Val::two_adic_generator(ks_log_block + 1);
    let ks_log_kn = p3_util::log2_strict_usize(ks_trace.witness.height());
    let ks_omega_kn: Val = Val::two_adic_generator(ks_log_kn);

    let ks_trace_ref = &ks_trace.witness;
    let ks_f_c = ks_f_cols.clone();
    let ks_g_c = ks_g_cols.clone();
    let ks_proof = prove_batch_with_northstar(
        &config,
        &ks_instances,
        &ks_prover_data,
        Some(|alpha_sc: Challenge, eta: Challenge, rho: Challenge| {
            compute_northstar_witness(
                ks_trace_ref,
                &ks_f_c,
                &ks_g_c,
                alpha_sc,
                eta,
                rho,
                ks_log_block,
                ks_num_blocks,
                ks_psi_block,
            )
        }),
    );
    let key_switch_time = key_switch_start.elapsed();
    let ks_proof_size = postcard::to_allocvec(&ks_proof).unwrap().len();
    println!(
        "  GLWE Key Switching + Northstar: {:.1} ms, {:.1} KB",
        key_switch_time.as_secs_f64() * 1000.0,
        ks_proof_size as f64 / 1024.0
    );

    let prover_total_time = prover_total_start.elapsed();
    let total_proof_size = ms_proof_size + br_proof_size + ks_proof_size;
    println!(
        "\n  PROVER TOTAL: {:.1} ms, total proof: {:.1} KB\n",
        prover_total_time.as_secs_f64() * 1000.0,
        total_proof_size as f64 / 1024.0
    );

    // ================================================================
    // END-TO-END VERIFIER (timed)
    // ================================================================
    println!("--- End-to-End Verifier ---");
    let verifier_total_start = Instant::now();

    // Reconstruct the statement from the original ciphertext instead of trusting prover data.
    let modulus_switch_verify_start = Instant::now();
    let verified_ms_trace = generate_ms_trace(&ct_in);
    let verified_ms_air = ModSwitchAir {
        preprocessed: verified_ms_trace.preprocessed.clone(),
    };
    let verified_ms_data =
        ProverData::from_airs_and_degrees(&config, std::slice::from_ref(&verified_ms_air), &[10]);
    verify_batch(
        &config,
        std::slice::from_ref(&verified_ms_air),
        &ms_proof,
        &[vec![]],
        &verified_ms_data.common,
    )
    .expect("Modulus Switching verification failed");
    let modulus_switch_verify_time = modulus_switch_verify_start.elapsed();
    println!(
        "  Modulus Switching verified: {:.1} ms (incl. preprocessed commit)",
        modulus_switch_verify_time.as_secs_f64() * 1000.0
    );

    let verified_a_tilde_values = &verified_ms_trace.a_switched;
    let verified_b_prime = verified_ms_trace.b_switched;

    let blind_rotation_verify_start = Instant::now();
    let claimed_final_acc = &br_trace.final_acc;
    let verified_br_pv = generate_br_public_values(
        verified_a_tilde_values,
        verified_b_prime,
        &test_vector,
        claimed_final_acc,
    );
    drop(br_instances);
    br_air.public_values.clone_from(&verified_br_pv);
    let br_nvd = make_northstar_verifier_data(
        br_f_cols,
        br_g_cols,
        br_log_block,
        br_num_blocks,
        br_psi_block,
        br_omega_kn,
    );
    let br_npre = br_nvd.precompute::<Val>();
    verify_batch_with_northstar(
        &config,
        &[br_air],
        &br_proof,
        &[verified_br_pv],
        &br_prover_data.common,
        &br_npre,
    )
    .expect("Blind Rotation verification failed");
    let blind_rotation_verify_time = blind_rotation_verify_start.elapsed();
    println!(
        "  Blind Rotation verified: {:.1} ms",
        blind_rotation_verify_time.as_secs_f64() * 1000.0
    );

    // Bind Key Switching to the same final accumulator claimed by Blind Rotation.
    let key_switch_verify_start = Instant::now();
    let mut verified_ks_pv = Vec::with_capacity(4 * N_POLY);
    verified_ks_pv.extend(
        claimed_final_acc
            .a
            .coeffs
            .iter()
            .map(|value| Val::new(value.0)),
    );
    let mut claimed_final_b_ntt = claimed_final_acc.b.coeffs.clone();
    ctx.forward(&mut claimed_final_b_ntt);
    verified_ks_pv.extend(claimed_final_b_ntt.iter().map(|value| Val::new(value.0)));
    verified_ks_pv.extend_from_slice(&ks_pv[2 * N_POLY..4 * N_POLY]);
    let verified_ks_air = GlweKsAir {
        preprocessed: generate_glwe_ks_preprocessed(&glwe_ksk, &verified_ks_pv),
    };
    let verified_ks_data = ProverData::from_airs_and_degrees(
        &config,
        std::slice::from_ref(&verified_ks_air),
        &[ks_log_kn],
    );
    let ks_nvd = make_northstar_verifier_data(
        ks_f_cols,
        ks_g_cols,
        ks_log_block,
        ks_num_blocks,
        ks_psi_block,
        ks_omega_kn,
    );
    let ks_npre = ks_nvd.precompute::<Val>();
    verify_batch_with_northstar(
        &config,
        &[verified_ks_air],
        &ks_proof,
        &[verified_ks_pv.clone()],
        &verified_ks_data.common,
        &ks_npre,
    )
    .expect("GLWE Key Switching verification failed");
    let key_switch_verify_time = key_switch_verify_start.elapsed();
    println!(
        "  GLWE Key Switching verified: {:.1} ms",
        key_switch_verify_time.as_secs_f64() * 1000.0
    );

    // Verifier-side sample extraction
    let extract_start = Instant::now();
    let out_a_ntt: Vec<GF> = verified_ks_pv[2 * N_POLY..3 * N_POLY]
        .iter()
        .map(|v| GF(v.as_canonical_u64()))
        .collect();
    let out_b_ntt: Vec<GF> = verified_ks_pv[3 * N_POLY..4 * N_POLY]
        .iter()
        .map(|v| GF(v.as_canonical_u64()))
        .collect();
    let (lwe_mask_out, lwe_body_out) = sample_extract_from_ntt(&out_a_ntt, &out_b_ntt);
    let extract_time = extract_start.elapsed();
    println!(
        "  Sample extraction: {:.1} ms",
        extract_time.as_secs_f64() * 1000.0
    );

    let verifier_total_time = verifier_total_start.elapsed();
    println!(
        "\n  VERIFIER TOTAL: {:.1} ms\n",
        verifier_total_time.as_secs_f64() * 1000.0
    );

    // ================================================================
    // OUTPUT
    // ================================================================
    println!("--- Output ---");
    let output_ct = tfhe_goldilocks::lwe::LweCiphertext {
        a: lwe_mask_out,
        b: lwe_body_out,
    };
    let decrypted_output = lwe_sk.decrypt(&output_ct);
    println!("  Input:  m = {}", message);
    println!("  Output: f(m) = {} (decrypted)", decrypted_output);
    if decrypted_output == message {
        println!("  Correctness: PASS");
    } else {
        println!(
            "  Correctness: MISMATCH (expected {}, got {})",
            message, decrypted_output
        );
        println!("  (FHE noise may cause decryption errors; all STARK proofs verified correctly)");
    }

    // ================================================================
    // SUMMARY
    // ================================================================
    println!("\n--- Timing Summary ---");
    println!(
        "  Prover total:      {:.1} ms",
        prover_total_time.as_secs_f64() * 1000.0
    );
    println!(
        "    Modulus Switching:  {:.1} ms",
        modulus_switch_time.as_secs_f64() * 1000.0
    );
    println!(
        "    Blind Rotation:     {:.1} ms",
        blind_rotation_time.as_secs_f64() * 1000.0
    );
    println!(
        "    GLWE Key Switching: {:.1} ms",
        key_switch_time.as_secs_f64() * 1000.0
    );
    println!(
        "  Verifier total:    {:.1} ms",
        verifier_total_time.as_secs_f64() * 1000.0
    );
    println!(
        "    Modulus Switching:  {:.1} ms",
        modulus_switch_verify_time.as_secs_f64() * 1000.0
    );
    println!(
        "    Blind Rotation:     {:.1} ms",
        blind_rotation_verify_time.as_secs_f64() * 1000.0
    );
    println!(
        "    GLWE Key Switching: {:.1} ms",
        key_switch_verify_time.as_secs_f64() * 1000.0
    );
    println!(
        "    Sample extract:  {:.1} ms",
        extract_time.as_secs_f64() * 1000.0
    );
    println!("  Proof sizes:");
    println!(
        "    Modulus Switching:  {:.1} KB",
        ms_proof_size as f64 / 1024.0
    );
    println!(
        "    Blind Rotation:     {:.1} KB",
        br_proof_size as f64 / 1024.0
    );
    println!(
        "    GLWE Key Switching: {:.1} KB",
        ks_proof_size as f64 / 1024.0
    );
    println!(
        "    TOTAL:           {:.1} KB",
        total_proof_size as f64 / 1024.0
    );
    println!(
        "  Preprocessing:     {:.1} ms (offline)",
        preprocess_time.as_secs_f64() * 1000.0
    );
}
