use crate::field::GF;
use crate::gadget::decompose_scalar_ks;
use crate::glwe::GlweCiphertext;
use crate::keygen::{BootstrappingKey, KeySwitchingKey};
use crate::lwe::{LweCiphertext, LweCiphertextBig};
use crate::ntt::NttContext;
use crate::params::{B_KS, DELTA, L_KS, N_LWE, N_POLY, Q, T_PLAIN};
use crate::poly::Poly;

/// Full Programmable Bootstrap
/// Input: LWE ciphertext encrypting m under LWE key
/// Output: LWE ciphertext encrypting f(m) under LWE key (with refreshed noise)
///
/// The function f is encoded via the test vector (lookup table).
pub fn programmable_bootstrap(
    ct: &LweCiphertext,
    lut: &[u64; 4], // f(0), f(1), f(2), f(3) for t=4
    bsk: &BootstrappingKey,
    ksk: &KeySwitchingKey,
    ctx: &NttContext,
) -> LweCiphertext {
    // Step 1: Modulus switch Q → 2N
    let (a_switched, b_switched) = modulus_switch(ct);

    // Step 2: Blind rotation
    let test_vector = build_test_vector(lut);
    let acc = blind_rotate(&a_switched, b_switched, &test_vector, bsk, ctx);

    // Step 3: Sample extraction
    let lwe_big = acc.sample_extract();

    // Step 4: Key switching (dim N_POLY → dim N_LWE)
    key_switch(&lwe_big, ksk)
}

/// Step 1: Modulus switching from Q to 2N
/// Scales each component: ã_i = round(2N * a_i / Q)
fn modulus_switch(ct: &LweCiphertext) -> (Vec<u32>, u32) {
    let two_n = (2 * N_POLY) as u128;

    let a_switched: Vec<u32> =
        ct.a.iter()
            .map(|&ai| {
                // round(2N * a_i / Q)
                let numerator = two_n * (ai.0 as u128);
                let rounded = (numerator + (Q as u128 / 2)) / (Q as u128);
                (rounded as u32) % (2 * N_POLY as u32)
            })
            .collect();

    let b_numerator = two_n * (ct.b.0 as u128);
    let b_switched = ((b_numerator + (Q as u128 / 2)) / (Q as u128)) as u32 % (2 * N_POLY as u32);

    (a_switched, b_switched)
}

/// Build the test vector (lookup table polynomial) for function f: Z_t → Z_t
/// The test vector v(X) is constructed so that after rotation by -(N/t)*m,
/// the constant coefficient gives Δ*f(m).
///
/// For t=4, N=1024: each message occupies N/t = 256 positions ("box").
/// v_j = Δ*f(⌊j*t/N⌋) for j = 0..N-1.
///
/// Boundary safety is handled by the half-box rotation in blind_rotate
/// (Zama-style padding), not by modifying the test vector values.
fn build_test_vector(lut: &[u64; 4]) -> Poly {
    let n = N_POLY;
    let t = T_PLAIN as usize;
    let _slots = n / t; // 256 positions per message value
    let mut coeffs = vec![GF::ZERO; n];

    for j in 0..n {
        let msg_idx = (j * t) / n; // which message value this slot represents
        coeffs[j] = GF(DELTA * lut[msg_idx]);
    }

    Poly::from_coeffs(coeffs)
}

/// Step 2: Blind rotation (Zama-style with half-box padding)
/// The initial rotation includes a half_box = N/(2t) shift so that the effective
/// read position lands in the CENTER of each message's box (256 positions wide).
/// This keeps reads far from the negacyclic boundary at position 0/2N.
fn blind_rotate(
    a_switched: &[u32],
    b_switched: u32,
    test_vector: &Poly,
    bsk: &BootstrappingKey,
    ctx: &NttContext,
) -> GlweCiphertext {
    let two_n = 2 * N_POLY;

    // Zama-style padding: shift by half_box = N/(2t) to center reads within each
    // message slot, avoiding the negacyclic boundary at position 0/2N.
    let half_box = (N_POLY / (2 * T_PLAIN as usize)) as u32; // = 128
    let b_shifted = (b_switched + half_box) % (two_n as u32);
    let neg_b = (two_n as u32 - b_shifted) % (two_n as u32);
    let rotated_tv = test_vector.monomial_rotate(neg_b as usize);
    let mut acc = GlweCiphertext::trivial(&rotated_tv);

    // For each LWE key bit i:
    // If s_i = 1: ACC should be rotated by ã_i
    // CMUX(BSK[i], ACC, X^{ã_i} * ACC)
    for i in 0..N_LWE {
        let ai = a_switched[i] as usize;
        if ai == 0 {
            continue; // No rotation needed regardless of key bit
        }

        // Compute rotated accumulator
        let acc_rotated = acc.monomial_rotate(ai);

        // CMUX: if BSK[i] encrypts 1, select rotated; if 0, keep original
        acc = bsk.entries[i].cmux(&acc, &acc_rotated, ctx);
    }

    acc
}

/// Step 4: Key switching
/// Switches LWE ciphertext from key s' (dim N_POLY) to key s (dim N_LWE)
fn key_switch(ct_big: &LweCiphertextBig, ksk: &KeySwitchingKey) -> LweCiphertext {
    // Output: (0, b') - Σ_{i,j} d_{i,j} * KSK[i][j]
    let mut result_a = vec![GF::ZERO; N_LWE];
    let mut result_b = ct_big.b;

    for i in 0..N_POLY {
        // Decompose a'_i in base B_KS
        let digits = decompose_scalar_ks(ct_big.a[i].0);

        for j in 0..L_KS {
            if digits[j] == 0 {
                continue;
            }
            let d = GF::from_signed(digits[j]);

            // Subtract d * KSK[i][j] from result
            let ksk_entry = &ksk.entries[i][j];
            for k in 0..N_LWE {
                result_a[k] = result_a[k] - d * ksk_entry.a[k];
            }
            result_b = result_b - d * ksk_entry.b;
        }
    }

    LweCiphertext {
        a: result_a,
        b: result_b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modulus_switch() {
        // Test that modulus switching maps correctly
        let a = vec![GF(Q / 2)]; // Should map to approximately N
        let ct = LweCiphertext {
            a: a.clone(),
            b: GF::ZERO,
        };

        // Manually test: round(2*1024 * (Q/2) / Q) = round(1024) = 1024
        let (a_sw, _) = modulus_switch(&LweCiphertext {
            a: vec![GF(Q / 2); N_LWE],
            b: GF::ZERO,
        });
        assert_eq!(a_sw[0], N_POLY as u32);
    }

    #[test]
    fn test_build_test_vector() {
        let lut = [0, 1, 2, 3]; // Identity function
        let tv = build_test_vector(&lut);

        // First N/t = 256 coefficients should be Δ*0 = 0
        for i in 0..256 {
            assert_eq!(tv.coeffs[i].0, 0, "Expected 0 at position {}", i);
        }
        // Next 256 should be Δ*1
        for i in 256..512 {
            assert_eq!(tv.coeffs[i].0, DELTA, "Expected DELTA at position {}", i);
        }
    }
}
