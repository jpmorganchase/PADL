use core::fmt;

use std::collections::HashMap;

use haste_algebra::{transformation::AbstractNTT, Basis, Field, Goldilocks, NTTField, Polynomial};
use haste_fhe_core::{
    lwe_modulus_switch, KeySwitchingRLWEKey, LWECiphertext, RLWEBlindRotationKey,
};
use haste_lattice::NTTRGSW;

use tfhe_goldilocks::field::GF;
use tfhe_goldilocks::poly::Poly;

use crate::br_trace::{
    generate_haste_blind_rotate_trace, BlindRotateTraceData, BlindRotationKeyEntry,
};

pub const HASTE_LWE_DIMENSION: usize = 728;
pub const HASTE_RING_DIMENSION: usize = 1024;
pub const HASTE_PLAINTEXT_MODULUS: u64 = 4;
pub const HASTE_BSK_BASIS_BITS: u32 = 8;
pub const HASTE_BSK_LEVELS: usize = 8;
pub const HASTE_KSK_BASIS_BITS: u32 = 5;
pub const HASTE_KSK_LEVELS: usize = 13;
pub const HASTE_SWITCH_MODULUS: u64 = 2 * HASTE_RING_DIMENSION as u64;

pub type HasteField = Goldilocks;
pub type HasteLweCiphertext = LWECiphertext<HasteField>;
pub type HasteLut = Polynomial<HasteField>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HasteCompatibilityError {
    InputDimension { actual: usize },
    OutputDimension { actual: usize },
    LutDimension { actual: usize },
    TernaryBlindRotationKey,
    BskDimension { actual: usize },
    BskBasis { bits: u32, levels: usize },
    KskDimension { actual: usize },
    KskBasis { bits: u32, levels: usize },
    OutputCiphertextMismatch,
}

impl fmt::Display for HasteCompatibilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "incompatible HasteBoots PBS input: {self:?}")
    }
}

impl std::error::Error for HasteCompatibilityError {}

pub struct HastePbsStatement<'a> {
    pub input: &'a HasteLweCiphertext,
    pub output: &'a HasteLweCiphertext,
    pub lut: &'a HasteLut,
}

pub struct HasteEvaluationKeys<'a> {
    pub bsk: &'a RLWEBlindRotationKey<HasteField>,
    pub ksk: &'a KeySwitchingRLWEKey<HasteField>,
}

pub struct HasteModSwitchWitness {
    pub mask: Vec<u64>,
    pub body: u64,
}

pub struct HasteBskEntryView<'a> {
    entry: &'a NTTRGSW<HasteField>,
    haste_index_for_vfhe_index: &'a [usize],
}

impl BlindRotationKeyEntry for HasteBskEntryView<'_> {
    fn a_ntt(&self, row: usize, index: usize) -> GF {
        let (gadget, level) = if row < HASTE_BSK_LEVELS {
            (self.entry.c_neg_s_m(), row)
        } else {
            (self.entry.c_m(), row - HASTE_BSK_LEVELS)
        };
        let haste_index = self.haste_index_for_vfhe_index[index];
        GF(gadget.data()[level].a().as_slice()[haste_index].value())
    }

    fn b_ntt(&self, row: usize, index: usize) -> GF {
        let (gadget, level) = if row < HASTE_BSK_LEVELS {
            (self.entry.c_neg_s_m(), row)
        } else {
            (self.entry.c_m(), row - HASTE_BSK_LEVELS)
        };
        let haste_index = self.haste_index_for_vfhe_index[index];
        GF(gadget.data()[level].b().as_slice()[haste_index].value())
    }
}

pub fn haste_to_vfhe_ntt_permutation() -> Vec<usize> {
    let mut haste_monomial = vec![HasteField::new(0); HASTE_RING_DIMENSION];
    haste_monomial[1] = HasteField::new(1);
    HasteField::get_ntt_table(10)
        .expect("Goldilocks supports a 1024-point NTT")
        .transform_slice(&mut haste_monomial);

    let mut vfhe_monomial = vec![GF::ZERO; HASTE_RING_DIMENSION];
    vfhe_monomial[1] = GF::ONE;
    tfhe_goldilocks::ntt::NttContext::new().forward(&mut vfhe_monomial);

    let haste_indices: HashMap<u64, usize> = haste_monomial
        .iter()
        .enumerate()
        .map(|(index, value)| (value.value(), index))
        .collect();
    assert_eq!(haste_indices.len(), HASTE_RING_DIMENSION);
    vfhe_monomial
        .iter()
        .map(|value: &GF| {
            *haste_indices
                .get(&value.0)
                .expect("HasteBoots and VFHE NTT domains must contain the same roots")
        })
        .collect()
}

pub fn haste_bsk_views<'a>(
    bsk: &'a RLWEBlindRotationKey<HasteField>,
    permutation: &'a [usize],
) -> Result<Vec<HasteBskEntryView<'a>>, HasteCompatibilityError> {
    let entries = bsk
        .binary_key()
        .ok_or(HasteCompatibilityError::TernaryBlindRotationKey)?;
    Ok(entries
        .iter()
        .map(|entry| HasteBskEntryView {
            entry,
            haste_index_for_vfhe_index: permutation,
        })
        .collect())
}

pub fn validate_haste_profile(
    statement: &HastePbsStatement<'_>,
    keys: &HasteEvaluationKeys<'_>,
) -> Result<(), HasteCompatibilityError> {
    validate_haste_statement(statement)?;
    validate_haste_bsk(keys.bsk)?;
    validate_haste_ksk(keys.ksk)
}

pub fn validate_haste_statement(
    statement: &HastePbsStatement<'_>,
) -> Result<(), HasteCompatibilityError> {
    if statement.input.a().len() != HASTE_LWE_DIMENSION {
        return Err(HasteCompatibilityError::InputDimension {
            actual: statement.input.a().len(),
        });
    }
    if statement.output.a().len() != HASTE_LWE_DIMENSION {
        return Err(HasteCompatibilityError::OutputDimension {
            actual: statement.output.a().len(),
        });
    }
    if statement.lut.coeff_count() != HASTE_RING_DIMENSION {
        return Err(HasteCompatibilityError::LutDimension {
            actual: statement.lut.coeff_count(),
        });
    }
    Ok(())
}

pub fn validate_haste_bsk(
    bsk: &RLWEBlindRotationKey<HasteField>,
) -> Result<(), HasteCompatibilityError> {
    let bsk = bsk
        .binary_key()
        .ok_or(HasteCompatibilityError::TernaryBlindRotationKey)?;
    if bsk.len() != HASTE_LWE_DIMENSION {
        return Err(HasteCompatibilityError::BskDimension { actual: bsk.len() });
    }
    if let Some(first) = bsk.first() {
        let basis = first.c_m().basis();
        validate_basis(
            basis,
            HASTE_BSK_BASIS_BITS,
            HASTE_BSK_LEVELS,
            |bits, levels| HasteCompatibilityError::BskBasis { bits, levels },
        )?;
    }
    Ok(())
}

pub fn validate_haste_ksk(
    ksk: &KeySwitchingRLWEKey<HasteField>,
) -> Result<(), HasteCompatibilityError> {
    let ksk = ksk.key();
    if ksk.len() != 1 {
        return Err(HasteCompatibilityError::KskDimension { actual: ksk.len() });
    }
    if let Some(first) = ksk.first() {
        validate_basis(
            first.basis(),
            HASTE_KSK_BASIS_BITS,
            HASTE_KSK_LEVELS,
            |bits, levels| HasteCompatibilityError::KskBasis { bits, levels },
        )?;
    }

    Ok(())
}

fn validate_basis(
    basis: Basis<HasteField>,
    expected_bits: u32,
    expected_levels: usize,
    error: impl FnOnce(u32, usize) -> HasteCompatibilityError,
) -> Result<(), HasteCompatibilityError> {
    let bits = basis.bits();
    let levels = basis.decompose_len();
    if bits != expected_bits || levels != expected_levels {
        return Err(error(bits, levels));
    }
    Ok(())
}

pub fn generate_haste_mod_switch_witness(input: &HasteLweCiphertext) -> HasteModSwitchWitness {
    assert_eq!(input.a().len(), HASTE_LWE_DIMENSION);
    let switched = lwe_modulus_switch(input, HASTE_SWITCH_MODULUS);
    HasteModSwitchWitness {
        mask: switched.a().to_vec(),
        body: switched.b(),
    }
}

pub fn generate_haste_blind_rotation_witness(
    switched: &HasteModSwitchWitness,
    lut: &HasteLut,
    bsk: &RLWEBlindRotationKey<HasteField>,
) -> Result<BlindRotateTraceData, HasteCompatibilityError> {
    let entries = bsk
        .binary_key()
        .ok_or(HasteCompatibilityError::TernaryBlindRotationKey)?;
    if entries.len() != HASTE_LWE_DIMENSION {
        return Err(HasteCompatibilityError::BskDimension {
            actual: entries.len(),
        });
    }
    let switched_mask: Vec<u32> = switched.mask.iter().map(|&value| value as u32).collect();
    let test_vector = Poly::from_coeffs(
        lut.as_slice()
            .iter()
            .map(|value| GF(value.value()))
            .collect(),
    );
    let permutation = haste_to_vfhe_ntt_permutation();
    let bsk_views = haste_bsk_views(bsk, &permutation)?;
    Ok(generate_haste_blind_rotate_trace(
        &switched_mask,
        switched.body as u32,
        &test_vector,
        &bsk_views,
    ))
}

pub fn canonical_coefficients(ciphertext: &HasteLweCiphertext) -> Vec<u64> {
    ciphertext
        .a()
        .iter()
        .chain(core::iter::once(&ciphertext.b()))
        .map(|value| value.value())
        .collect()
}

#[cfg(test)]
mod tests {
    use haste_tfhe::bfhe::GOLDILOCKS_BINARY_128_BITS_PARAMETERS;
    use haste_tfhe::KeyGen;
    use tfhe_goldilocks::lwe::LweCiphertext;
    use tfhe_goldilocks::ntt::NttContext;

    use crate::ms_trace::generate_ms_trace;

    use super::*;

    #[test]
    fn haste_modulus_switch_matches_vfhe_trace_values() {
        let mask: Vec<HasteField> = (0..HASTE_LWE_DIMENSION)
            .map(|index| HasteField::new((index as u64).wrapping_mul(0x1_0000_0001)))
            .collect();
        let input = HasteLweCiphertext::new(mask, HasteField::new(HasteField::MODULUS_VALUE - 1));
        let haste = generate_haste_mod_switch_witness(&input);

        let vfhe_input = LweCiphertext {
            a: input.a().iter().map(|value| GF(value.value())).collect(),
            b: GF(input.b().value()),
        };
        let vfhe = generate_ms_trace(&vfhe_input);

        assert_eq!(
            haste.mask,
            vfhe.a_switched
                .iter()
                .map(|&value| value as u64)
                .collect::<Vec<_>>()
        );
        assert_eq!(haste.body, vfhe.b_switched as u64);
    }

    #[test]
    fn haste_and_vfhe_ntt_representations_match() {
        let coefficients: Vec<u64> = (0..HASTE_RING_DIMENSION)
            .map(|index| (index as u64).wrapping_mul(0x1_0000_0001))
            .collect();
        let mut haste_values: Vec<HasteField> =
            coefficients.iter().copied().map(HasteField::new).collect();
        HasteField::get_ntt_table(10)
            .unwrap()
            .transform_slice(&mut haste_values);

        let mut vfhe_values: Vec<GF> = coefficients.iter().copied().map(GF).collect();
        NttContext::new().forward(&mut vfhe_values);

        let permutation = haste_to_vfhe_ntt_permutation();
        for (index, vfhe) in vfhe_values.iter().enumerate() {
            let haste = haste_values[permutation[index]];
            assert_eq!(
                haste.value(),
                vfhe.0,
                "permuted NTT representations differ at evaluation point {index}"
            );
        }
    }

    #[test]
    fn haste_blind_rotation_matches_native_accumulator() {
        let secret_key = KeyGen::generate_secret_key(*GOLDILOCKS_BINARY_128_BITS_PARAMETERS);
        let bsk = RLWEBlindRotationKey::generate(&secret_key);
        let input = HasteLweCiphertext::new(
            (0..HASTE_LWE_DIMENSION)
                .map(|index| HasteField::new((index as u64).wrapping_mul(0x1_0000_0001)))
                .collect(),
            HasteField::new(HasteField::MODULUS_VALUE - 1),
        );
        let switched_lwe = lwe_modulus_switch(&input, HASTE_SWITCH_MODULUS);
        let switched = generate_haste_mod_switch_witness(&input);
        let lut = HasteLut::new(
            (0..HASTE_RING_DIMENSION)
                .map(|index| HasteField::new((index as u64).wrapping_mul(0x9e37_79b9)))
                .collect(),
        );

        let native = bsk.blind_rotate(
            lut.clone(),
            &switched_lwe,
            GOLDILOCKS_BINARY_128_BITS_PARAMETERS.blind_rotation_basis(),
        );
        let vfhe = generate_haste_blind_rotation_witness(&switched, &lut, &bsk)
            .expect("VFHE blind rotation must accept the HasteBoots profile");

        assert_eq!(
            native
                .a()
                .as_slice()
                .iter()
                .map(|value| value.value())
                .collect::<Vec<_>>(),
            vfhe.final_acc
                .a
                .coeffs
                .iter()
                .map(|value| value.0)
                .collect::<Vec<_>>(),
        );
        assert_eq!(
            native
                .b()
                .as_slice()
                .iter()
                .map(|value| value.value())
                .collect::<Vec<_>>(),
            vfhe.final_acc
                .b
                .coeffs
                .iter()
                .map(|value| value.0)
                .collect::<Vec<_>>(),
        );
    }
}
