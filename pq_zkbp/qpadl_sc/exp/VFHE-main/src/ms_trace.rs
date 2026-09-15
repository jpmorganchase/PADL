use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;

use tfhe_goldilocks::field::GF;
use tfhe_goldilocks::lwe::LweCiphertext;
use tfhe_goldilocks::params::{N_LWE, N_POLY, Q};

use crate::ms_columns::{NUM_MS_COLS, NUM_MS_PRE_COLS, RANGE_BITS, NUM_MS_COMPONENTS};

/// k = (Q - 1) / (4 * N_POLY)
const K_VAL: u64 = (Q - 1) / (4 * N_POLY as u64);

/// 2N = 2 * N_POLY
const TWO_N: u64 = 2 * N_POLY as u64;

/// Result of modulus-switch trace generation.
pub struct MsTraceData {
    pub witness: RowMajorMatrix<Goldilocks>,
    pub preprocessed: RowMajorMatrix<Goldilocks>,
    /// The modulus-switched mask values (for use in blind rotation)
    pub a_switched: Vec<u32>,
    /// The modulus-switched body value
    pub b_switched: u32,
}

/// Compute the modulus switch of a single value: round(2N * a / Q) mod 2N
fn modulus_switch_single(a: u64) -> u32 {
    let two_n = TWO_N as u128;
    let numerator = two_n * (a as u128);
    let rounded = (numerator + (Q as u128 / 2)) / (Q as u128);
    (rounded as u32) % (TWO_N as u32)
}

/// Compute b' (segment index in {1..2N}) from the modulus-switched output b.
/// b' = b when b ≥ 1, b' = 2N when b = 0.
fn compute_b_prime(b: u32) -> u64 {
    if b == 0 { TWO_N } else { b as u64 }
}

/// Generate modulus-switch trace from an LWE ciphertext.
///
/// Each row proves that one component a_i is correctly switched to b_i ∈ Z_{2N}.
pub fn generate_ms_trace(ct: &LweCiphertext) -> MsTraceData {
    assert_eq!(ct.a.len(), N_LWE);

    // Collect all components: mask (N_LWE) + body (1)
    let components: Vec<u64> = ct.a.iter().map(|x| x.0).chain(std::iter::once(ct.b.0)).collect();
    assert_eq!(components.len(), NUM_MS_COMPONENTS);

    // Pad to next power of two
    let num_rows = NUM_MS_COMPONENTS.next_power_of_two(); // 1024

    let mut witness = vec![Goldilocks::ZERO; num_rows * NUM_MS_COLS];
    let mut preprocessed = vec![Goldilocks::ZERO; num_rows * NUM_MS_PRE_COLS];
    let mut a_switched = Vec::with_capacity(N_LWE);
    let mut b_switched = 0u32;

    for row in 0..num_rows {
        let w_off = row * NUM_MS_COLS;
        let p_off = row * NUM_MS_PRE_COLS;

        // For padding rows (row >= NUM_MS_COMPONENTS), use a = k (exceptional point)
        // so that f=0, b_out=0, and all constraints are trivially satisfied.
        let a_val = if row < NUM_MS_COMPONENTS {
            components[row]
        } else {
            K_VAL // padding: exceptional point
        };

        // Verifier-derived statement: input and expected output.
        preprocessed[p_off] = Goldilocks::new(a_val);

        // Compute modulus switch
        let b = modulus_switch_single(a_val);
        let b_prime = compute_b_prime(b);
        preprocessed[p_off + 1] = Goldilocks::new(b as u64);

        if row < NUM_MS_COMPONENTS {
            if row < N_LWE {
                a_switched.push(b);
            } else {
                b_switched = b;
            }
        }

        // Compute flag and inverse witness
        let (f_val, inv_val) = if a_val == K_VAL {
            (0u64, 0u64)
        } else {
            let diff = GF(a_val) - GF(K_VAL);
            (1u64, diff.inv().0)
        };

        // Compute r = a - (2*b' - 1)*k - 1 in the field
        let r_val = if f_val == 1 {
            let two_bp_minus_1 = GF(2 * b_prime) - GF(1);
            let segment_start = two_bp_minus_1 * GF(K_VAL) + GF(1);
            (GF(a_val) - segment_start).0
        } else {
            0u64
        };

        // Fill witness
        let mut col = 0;

        // b_prime
        witness[w_off + col] = Goldilocks::new(b_prime);
        col += 1;

        // b_out
        witness[w_off + col] = Goldilocks::new(b as u64);
        col += 1;

        // f_flag
        witness[w_off + col] = Goldilocks::new(f_val);
        col += 1;

        // inv_witness
        witness[w_off + col] = Goldilocks::new(inv_val);
        col += 1;

        // r_bits (53 bits of r_val)
        for i in 0..RANGE_BITS {
            witness[w_off + col] = Goldilocks::new((r_val >> i) & 1);
            col += 1;
        }

        debug_assert_eq!(col, NUM_MS_COLS);
    }

    MsTraceData {
        witness: RowMajorMatrix::new(witness, NUM_MS_COLS),
        preprocessed: RowMajorMatrix::new(preprocessed, NUM_MS_PRE_COLS),
        a_switched,
        b_switched,
    }
}

#[cfg(test)]
mod tests {
    use p3_batch_stark::{ProverData, StarkInstance, prove_batch, verify_batch};

    use super::*;
    use crate::config::make_test_config;
    use crate::ms_air::ModSwitchAir;

    #[test]
    fn rejects_proof_for_different_input_ciphertext() {
        let config = make_test_config();
        let ciphertext = LweCiphertext {
            a: vec![GF::ZERO; N_LWE],
            b: GF::ZERO,
        };
        let trace = generate_ms_trace(&ciphertext);
        let air = ModSwitchAir {
            preprocessed: trace.preprocessed.clone(),
        };
        let instances = vec![StarkInstance {
            air: &air,
            trace: &trace.witness,
            public_values: vec![],
        }];
        let prover_data = ProverData::from_instances(&config, &instances);
        let proof = prove_batch(&config, &instances, &prover_data);

        let mut different_ciphertext = ciphertext;
        different_ciphertext.a[0] = GF(1);
        let different_trace = generate_ms_trace(&different_ciphertext);
        let different_air = ModSwitchAir {
            preprocessed: different_trace.preprocessed,
        };
        let verifier_data = ProverData::from_airs_and_degrees(
            &config,
            std::slice::from_ref(&different_air),
            &[10],
        );

        assert!(
            verify_batch(
                &config,
                std::slice::from_ref(&different_air),
                &proof,
                &[vec![]],
                &verifier_data.common,
            )
            .is_err()
        );
    }
}
