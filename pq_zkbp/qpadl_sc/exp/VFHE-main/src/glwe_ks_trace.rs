use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;

use tfhe_goldilocks::field::GF;
use tfhe_goldilocks::gadget::decompose_element_unsigned;
use tfhe_goldilocks::glwe::GlweCiphertext;
use tfhe_goldilocks::keygen::GlweKeySwitchingKey;
use tfhe_goldilocks::ntt::NttContext;
use tfhe_goldilocks::params::{LOG_B_PBS, L_PBS, N_POLY};

use crate::glwe_ks_columns::{NUM_GLWE_KS_COLS, NUM_GLWE_KS_PRE_COLS};

/// Compute is-zero gadget inverse hint for unsigned digits.
fn compute_inv_hint(digits: &[u64]) -> GF {
    let sigma_top = (255 - digits[4]) + (255 - digits[5])
        + (255 - digits[6]) + (255 - digits[7]);
    if sigma_top == 0 {
        GF::ZERO
    } else {
        GF(sigma_top).inv()
    }
}

/// Result of GLWE key-switching trace generation.
pub struct GlweKsTraceData {
    pub witness: RowMajorMatrix<Goldilocks>,
    pub preprocessed: RowMajorMatrix<Goldilocks>,
    /// Public values: [input_a_coeffs(N) ++ input_b_ntt(N) ++ out_a_ntt(N) ++ out_b_ntt(N)]
    pub public_values: Vec<Goldilocks>,
}

/// Generate the GLWE key-switch trace.
///
/// Proves: ACC' = (a(X), b(X)) - Σ_l d_l(X) · KSK[l]
/// where d_l(X) are the digit polynomials from decomposing a(X) coefficient-wise.
///
/// The verifier performs sample extraction on the output ACC' to obtain the final LWE.
pub fn generate_glwe_ks_trace(
    acc: &GlweCiphertext,    // Input GLWE accumulator from blind rotation
    ksk: &GlweKeySwitchingKey, // GLWE-to-GLWE KSK (L entries, each in NTT domain)
) -> GlweKsTraceData {
    let ctx = NttContext::new();

    // 1. Decompose each coefficient of a(X) into L=8 unsigned digits
    let input_a_coeffs: &[GF] = &acc.a.coeffs;
    let digits: Vec<Vec<u64>> = (0..N_POLY)
        .map(|j| decompose_element_unsigned(input_a_coeffs[j], LOG_B_PBS, L_PBS))
        .collect();

    // 2. Build digit polynomials and compute their NTTs
    //    digit_poly[l] has coefficient digits[j][l] at position j
    let mut decomp_ntt_all: Vec<Vec<GF>> = Vec::with_capacity(L_PBS);
    for l in 0..L_PBS {
        let coeffs: Vec<GF> = (0..N_POLY).map(|j| GF(digits[j][l])).collect();
        let mut ntt = coeffs;
        ctx.forward(&mut ntt);
        decomp_ntt_all.push(ntt);
    }

    // 3. Compute input NTT: a_ntt[j] = NTT(a(X))[j]
    let mut input_a_ntt = input_a_coeffs.to_vec();
    ctx.forward(&mut input_a_ntt);

    // 4. Compute input b NTT
    let mut input_b_ntt = acc.b.coeffs.clone();
    ctx.forward(&mut input_b_ntt);

    // 5. Compute output NTT via external product:
    //    out_a_ntt[j] = input_a_ntt[j] - Σ_l decomp_ntt[l][j] · ksk_a_ntt[l][j]
    //    out_b_ntt[j] = input_b_ntt[j] - Σ_l decomp_ntt[l][j] · ksk_b_ntt[l][j]
    let mut out_a_ntt = vec![GF::ZERO; N_POLY];
    let mut out_b_ntt = vec![GF::ZERO; N_POLY];
    for j in 0..N_POLY {
        let mut sum_a = GF::ZERO;
        let mut sum_b = GF::ZERO;
        for l in 0..L_PBS {
            let d = decomp_ntt_all[l][j];
            sum_a = sum_a + d * ksk.entries[l].0[j]; // ksk_a_ntt[l][j]
            sum_b = sum_b + d * ksk.entries[l].1[j]; // ksk_b_ntt[l][j]
        }
        out_a_ntt[j] = input_a_ntt[j] - sum_a;
        out_b_ntt[j] = input_b_ntt[j] - sum_b;
    }

    // 6. Fill witness trace (1024 rows × 86 columns)
    let mut witness = vec![Goldilocks::ZERO; N_POLY * NUM_GLWE_KS_COLS];

    for j in 0..N_POLY {
        let row = j * NUM_GLWE_KS_COLS;
        let mut col = 0;

        // input_a_coeff
        witness[row + col] = Goldilocks::new(input_a_coeffs[j].0);
        col += 1;

        // decomp[8]
        for l in 0..8 {
            witness[row + col] = Goldilocks::new(digits[j][l]);
            col += 1;
        }

        // inv_hint
        let inv_h = compute_inv_hint(&digits[j]);
        witness[row + col] = Goldilocks::new(inv_h.0);
        col += 1;

        // digit_bits[64]: binary decomposition of each digit
        for l in 0..8 {
            let d = digits[j][l];
            for k in 0..8 {
                witness[row + col] = Goldilocks::new(((d >> k) & 1) as u64);
                col += 1;
            }
        }

        // decomp_ntt[8]
        for l in 0..8 {
            witness[row + col] = Goldilocks::new(decomp_ntt_all[l][j].0);
            col += 1;
        }

        // input_b_ntt
        witness[row + col] = Goldilocks::new(input_b_ntt[j].0);
        col += 1;

        // out_a_ntt
        witness[row + col] = Goldilocks::new(out_a_ntt[j].0);
        col += 1;

        // out_b_ntt
        witness[row + col] = Goldilocks::new(out_b_ntt[j].0);
        col += 1;

        debug_assert_eq!(col, NUM_GLWE_KS_COLS);
    }

    // 7. Fill preprocessed trace with the KSK and claimed input/output statement.
    let mut preprocessed = vec![Goldilocks::ZERO; N_POLY * NUM_GLWE_KS_PRE_COLS];

    for j in 0..N_POLY {
        let row = j * NUM_GLWE_KS_PRE_COLS;

        // ksk_a_ntt[8]
        for l in 0..8 {
            preprocessed[row + l] = Goldilocks::new(ksk.entries[l].0[j].0);
        }
        // ksk_b_ntt[8]
        for l in 0..8 {
            preprocessed[row + 8 + l] = Goldilocks::new(ksk.entries[l].1[j].0);
        }
        preprocessed[row + 16] = Goldilocks::new(input_a_coeffs[j].0);
        preprocessed[row + 17] = Goldilocks::new(input_b_ntt[j].0);
        preprocessed[row + 18] = Goldilocks::new(out_a_ntt[j].0);
        preprocessed[row + 19] = Goldilocks::new(out_b_ntt[j].0);
    }

    // 8. Build public values
    //    Layout: [input_a_coeffs(N) ++ input_b_ntt(N) ++ out_a_ntt(N) ++ out_b_ntt(N)]
    //
    //    NTT <-> coeff binding is verified OUTSIDE the STARK:
    //    The verifier checks that the committed trace polynomial for decomp[l]
    //    (interpolating digit coefficients) matches decomp_ntt[l] after NTT.
    let mut public_values = Vec::with_capacity(4 * N_POLY);
    for j in 0..N_POLY {
        public_values.push(Goldilocks::new(input_a_coeffs[j].0));
    }
    for j in 0..N_POLY {
        public_values.push(Goldilocks::new(input_b_ntt[j].0));
    }
    for j in 0..N_POLY {
        public_values.push(Goldilocks::new(out_a_ntt[j].0));
    }
    for j in 0..N_POLY {
        public_values.push(Goldilocks::new(out_b_ntt[j].0));
    }

    GlweKsTraceData {
        witness: RowMajorMatrix::new(witness, NUM_GLWE_KS_COLS),
        preprocessed: RowMajorMatrix::new(preprocessed, NUM_GLWE_KS_PRE_COLS),
        public_values,
    }
}

/// Reconstruct GLWE Key Switching preprocessing from public setup and statement values.
pub fn generate_glwe_ks_preprocessed(
    ksk: &GlweKeySwitchingKey,
    public_values: &[Goldilocks],
) -> RowMajorMatrix<Goldilocks> {
    assert_eq!(public_values.len(), 4 * N_POLY);
    let mut preprocessed = vec![Goldilocks::ZERO; N_POLY * NUM_GLWE_KS_PRE_COLS];
    for j in 0..N_POLY {
        let row = j * NUM_GLWE_KS_PRE_COLS;
        for l in 0..8 {
            preprocessed[row + l] = Goldilocks::new(ksk.entries[l].0[j].0);
            preprocessed[row + 8 + l] = Goldilocks::new(ksk.entries[l].1[j].0);
        }
        preprocessed[row + 16] = public_values[j];
        preprocessed[row + 17] = public_values[N_POLY + j];
        preprocessed[row + 18] = public_values[2 * N_POLY + j];
        preprocessed[row + 19] = public_values[3 * N_POLY + j];
    }
    RowMajorMatrix::new(preprocessed, NUM_GLWE_KS_PRE_COLS)
}

/// Perform sample extraction on GLWE KS output (done by verifier, not proved).
///
/// Takes out_a_ntt and out_b_ntt, INTTs them, and extracts the LWE ciphertext.
/// Returns (lwe_mask[N_LWE], lwe_body).
pub fn sample_extract_from_ntt(
    out_a_ntt: &[GF],
    out_b_ntt: &[GF],
) -> (Vec<GF>, GF) {
    use tfhe_goldilocks::params::N_LWE;

    let ctx = NttContext::new();

    // INTT to get coefficient domain
    let mut a_coeffs = out_a_ntt.to_vec();
    ctx.inverse(&mut a_coeffs);

    let mut b_coeffs = out_b_ntt.to_vec();
    ctx.inverse(&mut b_coeffs);

    // Sample extraction: negacyclic structure
    // lwe_mask[0] = a'_0
    // lwe_mask[i] = -a'_{N-i} for i >= 1
    // Since s_out has zeros at positions N_LWE..N_POLY-1,
    // we only need the first N_LWE components (effective dimension).
    let mut lwe_mask = Vec::with_capacity(N_LWE);
    lwe_mask.push(a_coeffs[0]);
    for i in 1..N_LWE {
        lwe_mask.push(GF::ZERO - a_coeffs[N_POLY - i]); // -a'_{N-i}
    }

    let lwe_body = b_coeffs[0];

    (lwe_mask, lwe_body)
}
