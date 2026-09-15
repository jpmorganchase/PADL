use haste_algebra::Field as HasteFieldTrait;
use haste_fhe_core::KeySwitchingRLWEKey;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use tfhe_goldilocks::field::GF;
use tfhe_goldilocks::glwe::GlweCiphertext;
use tfhe_goldilocks::ntt::NttContext;
use tfhe_goldilocks::params::Q;

use crate::haste_compat::{
    haste_to_vfhe_ntt_permutation, HasteCompatibilityError, HasteField, HasteLweCiphertext,
    HASTE_KSK_BASIS_BITS, HASTE_KSK_LEVELS, HASTE_LWE_DIMENSION, HASTE_RING_DIMENSION,
};
use crate::haste_ks_columns::{HASTE_KS_TOTAL_BITS, NUM_HASTE_KS_COLS, NUM_HASTE_KS_PRE_COLS};

pub const HASTE_KS_PUBLIC_VALUES: usize = HASTE_RING_DIMENSION + 1 + HASTE_LWE_DIMENSION + 1;

pub struct HasteKsTraceData {
    pub witness: RowMajorMatrix<Goldilocks>,
    pub preprocessed: RowMajorMatrix<Goldilocks>,
    pub public_values: Vec<Goldilocks>,
}

pub fn generate_haste_ks_trace(
    blind_rotation_output: &GlweCiphertext,
    ksk: &KeySwitchingRLWEKey<HasteField>,
    claimed_output: &HasteLweCiphertext,
) -> Result<HasteKsTraceData, HasteCompatibilityError> {
    if claimed_output.a().len() != HASTE_LWE_DIMENSION {
        return Err(HasteCompatibilityError::OutputDimension {
            actual: claimed_output.a().len(),
        });
    }
    let key = validate_ksk(ksk)?;
    let permutation = haste_to_vfhe_ntt_permutation();
    let context = NttContext::new();

    let input_a = &blind_rotation_output.a.coeffs;
    let input_b0 = blind_rotation_output.b.coeffs[0] + GF(Q >> 3);

    let mut digits_by_level = vec![vec![GF::ZERO; HASTE_RING_DIMENSION]; HASTE_KSK_LEVELS];
    for (row, coefficient) in input_a.iter().enumerate() {
        let negated = (GF::ZERO - *coefficient).0;
        for level in 0..HASTE_KSK_LEVELS {
            digits_by_level[level][row] =
                GF((negated >> (level * HASTE_KSK_BASIS_BITS as usize)) & 31);
        }
    }

    let mut digits_ntt = digits_by_level.clone();
    for level in &mut digits_ntt {
        context.forward(level);
    }

    let mut out_a_ntt = vec![GF::ZERO; HASTE_RING_DIMENSION];
    let mut out_b_ntt = vec![input_b0; HASTE_RING_DIMENSION];
    for row in 0..HASTE_RING_DIMENSION {
        let haste_row = permutation[row];
        for level in 0..HASTE_KSK_LEVELS {
            let key_level = &key.data()[level];
            let digit = digits_ntt[level][row];
            out_a_ntt[row] =
                out_a_ntt[row] + digit * GF(key_level.a().as_slice()[haste_row].value());
            out_b_ntt[row] =
                out_b_ntt[row] + digit * GF(key_level.b().as_slice()[haste_row].value());
        }
    }

    let mut out_a_coeff = out_a_ntt.clone();
    let mut out_b_coeff = out_b_ntt.clone();
    context.inverse(&mut out_a_coeff);
    context.inverse(&mut out_b_coeff);

    let extracted_mask: Vec<GF> = (0..HASTE_LWE_DIMENSION)
        .map(|index| {
            if index == 0 {
                out_a_coeff[0]
            } else {
                GF::ZERO - out_a_coeff[HASTE_RING_DIMENSION - index]
            }
        })
        .collect();
    let claimed_mask: Vec<GF> = claimed_output
        .a()
        .iter()
        .map(|value| GF(value.value()))
        .collect();
    if extracted_mask != claimed_mask || out_b_coeff[0].0 != claimed_output.b().value() {
        return Err(HasteCompatibilityError::OutputCiphertextMismatch);
    }

    let public_values = build_public_values(input_a, input_b0, claimed_output);
    let preprocessed = generate_haste_ks_preprocessed(ksk, &public_values)?;
    let mut witness = vec![Goldilocks::ZERO; HASTE_RING_DIMENSION * NUM_HASTE_KS_COLS];

    for row in 0..HASTE_RING_DIMENSION {
        let offset = row * NUM_HASTE_KS_COLS;
        let mut column = 0;
        witness[offset + column] = Goldilocks::new(input_a[row].0);
        column += 1;

        for level in 0..HASTE_KSK_LEVELS {
            witness[offset + column] = Goldilocks::new(digits_by_level[level][row].0);
            column += 1;
        }

        let bits = (GF::ZERO - input_a[row]).0;
        let sigma_top = (32..64).filter(|bit| ((bits >> bit) & 1) == 0).count() as u64;
        let inv_hint = if sigma_top == 0 {
            GF::ZERO
        } else {
            GF(sigma_top).inv()
        };
        witness[offset + column] = Goldilocks::new(inv_hint.0);
        column += 1;

        for bit in 0..HASTE_KS_TOTAL_BITS {
            let bit_value = if bit < 64 { (bits >> bit) & 1 } else { 0 };
            witness[offset + column] = Goldilocks::new(bit_value);
            column += 1;
        }
        for level in 0..HASTE_KSK_LEVELS {
            witness[offset + column] = Goldilocks::new(digits_ntt[level][row].0);
            column += 1;
        }
        witness[offset + column] = Goldilocks::new(input_b0.0);
        column += 1;
        witness[offset + column] = Goldilocks::new(out_a_ntt[row].0);
        column += 1;
        witness[offset + column] = Goldilocks::new(out_b_ntt[row].0);
        column += 1;
        witness[offset + column] = Goldilocks::new(out_a_coeff[row].0);
        column += 1;
        witness[offset + column] = Goldilocks::new(out_b_coeff[row].0);
        column += 1;
        debug_assert_eq!(column, NUM_HASTE_KS_COLS);
    }

    Ok(HasteKsTraceData {
        witness: RowMajorMatrix::new(witness, NUM_HASTE_KS_COLS),
        preprocessed,
        public_values,
    })
}

pub fn generate_haste_ks_preprocessed(
    ksk: &KeySwitchingRLWEKey<HasteField>,
    public_values: &[Goldilocks],
) -> Result<RowMajorMatrix<Goldilocks>, HasteCompatibilityError> {
    assert_eq!(public_values.len(), HASTE_KS_PUBLIC_VALUES);
    let key = validate_ksk(ksk)?;
    let permutation = haste_to_vfhe_ntt_permutation();
    let output_start = HASTE_RING_DIMENSION + 1;
    let output_body = public_values[output_start + HASTE_LWE_DIMENSION];
    let mut preprocessed = vec![Goldilocks::ZERO; HASTE_RING_DIMENSION * NUM_HASTE_KS_PRE_COLS];

    for row in 0..HASTE_RING_DIMENSION {
        let offset = row * NUM_HASTE_KS_PRE_COLS;
        let haste_row = permutation[row];
        for level in 0..HASTE_KSK_LEVELS {
            let key_level = &key.data()[level];
            preprocessed[offset + level] =
                Goldilocks::new(key_level.a().as_slice()[haste_row].value());
            preprocessed[offset + HASTE_KSK_LEVELS + level] =
                Goldilocks::new(key_level.b().as_slice()[haste_row].value());
        }
        preprocessed[offset + 26] = public_values[row];
        preprocessed[offset + 27] = public_values[HASTE_RING_DIMENSION];

        let output_index = if row == 0 {
            Some(0)
        } else if row >= HASTE_RING_DIMENSION - (HASTE_LWE_DIMENSION - 1) {
            Some(HASTE_RING_DIMENSION - row)
        } else {
            None
        };
        if let Some(index) = output_index {
            preprocessed[offset + 28] = Goldilocks::ONE;
            let expected = public_values[output_start + index];
            preprocessed[offset + 29] = if index == 0 { expected } else { -expected };
        }
        if row == 0 {
            preprocessed[offset + 30] = Goldilocks::ONE;
            preprocessed[offset + 31] = output_body;
        }
    }

    Ok(RowMajorMatrix::new(preprocessed, NUM_HASTE_KS_PRE_COLS))
}

fn validate_ksk(
    ksk: &KeySwitchingRLWEKey<HasteField>,
) -> Result<&haste_lattice::NTTGadgetRLWE<HasteField>, HasteCompatibilityError> {
    let key = ksk.key();
    if key.len() != 1 {
        return Err(HasteCompatibilityError::KskDimension { actual: key.len() });
    }
    let first = &key[0];
    let basis = first.basis();
    if basis.bits() != HASTE_KSK_BASIS_BITS || basis.decompose_len() != HASTE_KSK_LEVELS {
        return Err(HasteCompatibilityError::KskBasis {
            bits: basis.bits(),
            levels: basis.decompose_len(),
        });
    }
    Ok(first)
}

fn build_public_values(
    input_a: &[GF],
    input_b0: GF,
    output: &HasteLweCiphertext,
) -> Vec<Goldilocks> {
    let mut values = Vec::with_capacity(HASTE_KS_PUBLIC_VALUES);
    values.extend(input_a.iter().map(|value| Goldilocks::new(value.0)));
    values.push(Goldilocks::new(input_b0.0));
    values.extend(
        output
            .a()
            .iter()
            .map(|value| Goldilocks::new(value.value())),
    );
    values.push(Goldilocks::new(output.b().value()));
    values
}

#[cfg(test)]
mod tests {
    use haste_algebra::Polynomial as HastePolynomial;
    use haste_fhe_core::RLWECiphertext;
    use haste_tfhe::bfhe::GOLDILOCKS_BINARY_128_BITS_PARAMETERS;
    use haste_tfhe::KeyGen;
    use p3_batch_stark::{
        prove_batch_with_northstar, verify_batch_with_northstar, ProverData, StarkInstance,
    };
    use p3_field::TwoAdicField;
    use tfhe_goldilocks::poly::Poly;

    use super::*;
    use crate::config::{make_test_config, Challenge, Val};
    use crate::haste_ks_air::HasteKsAir;
    use crate::haste_ks_columns::{HASTE_KS_NORTHSTAR_F_COLS, HASTE_KS_NORTHSTAR_G_COLS};
    use crate::northstar_sumcheck::{compute_northstar_witness, make_northstar_verifier_data};

    #[test]
    fn trace_matches_haste_rlwe_to_lwe_key_switch() {
        let secret_key = KeyGen::generate_secret_key(*GOLDILOCKS_BINARY_128_BITS_PARAMETERS);
        let ksk = KeySwitchingRLWEKey::generate(&secret_key);
        let haste_a: Vec<HasteField> = (0..HASTE_RING_DIMENSION)
            .map(|index| HasteField::new((index as u64).wrapping_mul(0x1_0000_0001)))
            .collect();
        let haste_b: Vec<HasteField> = (0..HASTE_RING_DIMENSION)
            .map(|index| HasteField::new((index as u64).wrapping_mul(0x9e37_79b9)))
            .collect();
        let haste_input = RLWECiphertext::new(
            HastePolynomial::new(haste_a.clone()),
            HastePolynomial::new(haste_b.clone()),
        );

        let mut corrected_input = haste_input;
        corrected_input.b_mut()[0] += HasteField::new(Q >> 3);
        let expected = ksk.key_switch_for_rlwe(corrected_input);

        let vfhe_input = GlweCiphertext {
            a: Poly::from_coeffs(haste_a.iter().map(|value| GF(value.value())).collect()),
            b: Poly::from_coeffs(haste_b.iter().map(|value| GF(value.value())).collect()),
        };
        let trace = generate_haste_ks_trace(&vfhe_input, &ksk, &expected)
            .expect("VFHE trace output must equal HasteBoots key switching");

        assert_eq!(trace.public_values.len(), HASTE_KS_PUBLIC_VALUES);

        let config = make_test_config();
        let air = HasteKsAir {
            preprocessed: trace.preprocessed.clone(),
        };
        let instances = vec![StarkInstance {
            air: &air,
            trace: &trace.witness,
            public_values: trace.public_values.clone(),
        }];
        let prover_data = ProverData::from_instances(&config, &instances);
        let psi = Val::two_adic_generator(11);
        let proof = prove_batch_with_northstar(
            &config,
            &instances,
            &prover_data,
            Some(|alpha: Challenge, eta: Challenge, rho: Challenge| {
                compute_northstar_witness(
                    &trace.witness,
                    &HASTE_KS_NORTHSTAR_F_COLS,
                    &HASTE_KS_NORTHSTAR_G_COLS,
                    alpha,
                    eta,
                    rho,
                    10,
                    1,
                    psi,
                )
            }),
        );
        drop(instances);
        let verifier_data = make_northstar_verifier_data(
            HASTE_KS_NORTHSTAR_F_COLS.to_vec(),
            HASTE_KS_NORTHSTAR_G_COLS.to_vec(),
            10,
            1,
            psi,
            Val::two_adic_generator(10),
        );
        verify_batch_with_northstar(
            &config,
            &[air],
            &proof,
            &[trace.public_values.clone()],
            &prover_data.common,
            &verifier_data.precompute::<Val>(),
        )
        .expect("Haste-compatible key-switch proof must verify");

        let mut tampered = expected.clone();
        tampered.a_mut()[0] += HasteField::new(1);
        assert!(matches!(
            generate_haste_ks_trace(&vfhe_input, &ksk, &tampered),
            Err(HasteCompatibilityError::OutputCiphertextMismatch)
        ));
    }
}
