use haste_algebra::Field as HasteFieldTrait;
use haste_fhe_core::{KeySwitchingRLWEKey, RLWEBlindRotationKey};
use p3_batch_stark::{
    prove_batch, prove_batch_with_northstar, verify_batch, verify_batch_with_northstar, BatchProof,
    CommonData, ProverData, StarkInstance,
};
use p3_field::{PrimeCharacteristicRing, TwoAdicField};
use p3_uni_stark::NorthstarPrecomputed;
use tfhe_goldilocks::field::GF;
use tfhe_goldilocks::glwe::GlweCiphertext;
use tfhe_goldilocks::lwe::LweCiphertext;
use tfhe_goldilocks::poly::Poly;

use crate::br_air::BlindRotateAir;
use crate::br_trace::{generate_br_preprocessed, generate_haste_br_public_values};
use crate::config::{Challenge, PbsStarkConfig, Val};
use crate::haste_compat::{
    generate_haste_blind_rotation_witness, generate_haste_mod_switch_witness, haste_bsk_views,
    haste_to_vfhe_ntt_permutation, validate_haste_bsk, validate_haste_ksk, validate_haste_profile,
    validate_haste_statement, HasteCompatibilityError, HasteEvaluationKeys, HasteField,
    HastePbsStatement, HASTE_RING_DIMENSION,
};
use crate::haste_ks_air::HasteKsAir;
use crate::haste_ks_columns::{HASTE_KS_NORTHSTAR_F_COLS, HASTE_KS_NORTHSTAR_G_COLS};
use crate::haste_ks_trace::{
    generate_haste_ks_preprocessed, generate_haste_ks_trace, HASTE_KS_PUBLIC_VALUES,
};
use crate::ms_air::ModSwitchAir;
use crate::ms_trace::generate_ms_trace;
use crate::northstar_sumcheck::{compute_northstar_witness, make_northstar_verifier_data};

const LOG_RING_DIMENSION: usize = 10;
const BR_F_COLS: [usize; 8] = [6, 7, 8, 9, 10, 11, 12, 13];
const BR_G_COLS: [usize; 8] = [24, 25, 26, 27, 28, 29, 30, 31];

pub struct HastePbsProof {
    pub modulus_switch: BatchProof<PbsStarkConfig>,
    pub blind_rotation: BatchProof<PbsStarkConfig>,
    pub key_switch: BatchProof<PbsStarkConfig>,
    pub final_accumulator: GlweCiphertext,
}

pub struct HastePbsVerifierPreprocessing {
    blind_rotation_air: BlindRotateAir,
    blind_rotation_common: CommonData<PbsStarkConfig>,
    blind_rotation_northstar: NorthstarPrecomputed<Val>,
}

pub fn prepare_haste_pbs_verifier(
    config: &PbsStarkConfig,
    bsk: &RLWEBlindRotationKey<HasteField>,
) -> Result<HastePbsVerifierPreprocessing, HasteCompatibilityError> {
    validate_haste_bsk(bsk)?;
    let permutation = haste_to_vfhe_ntt_permutation();
    let bsk_views = haste_bsk_views(bsk, &permutation)?;
    let (br_preprocessed, br_num_blocks) = generate_br_preprocessed(&bsk_views);
    let blind_rotation_air = BlindRotateAir {
        preprocessed: br_preprocessed,
        num_blocks: br_num_blocks,
        public_values: vec![Val::ZERO; br_num_blocks + 3 * HASTE_RING_DIMENSION],
    };
    let br_log_rows = p3_util::log2_strict_usize(br_num_blocks * HASTE_RING_DIMENSION);
    let blind_rotation_data = ProverData::from_airs_and_degrees(
        config,
        core::slice::from_ref(&blind_rotation_air),
        &[br_log_rows],
    );
    let br_psi = Val::two_adic_generator(LOG_RING_DIMENSION + 1);
    let blind_rotation_northstar = make_northstar_verifier_data(
        BR_F_COLS.to_vec(),
        BR_G_COLS.to_vec(),
        LOG_RING_DIMENSION,
        br_num_blocks,
        br_psi,
        Val::two_adic_generator(br_log_rows),
    )
    .precompute::<Val>();

    Ok(HastePbsVerifierPreprocessing {
        blind_rotation_air,
        blind_rotation_common: blind_rotation_data.common,
        blind_rotation_northstar,
    })
}

pub fn prove_haste_pbs(
    config: &PbsStarkConfig,
    statement: &HastePbsStatement<'_>,
    keys: &HasteEvaluationKeys<'_>,
) -> Result<HastePbsProof, HasteCompatibilityError> {
    validate_haste_profile(statement, keys)?;

    let input = to_vfhe_lwe(statement.input);
    let ms_trace = generate_ms_trace(&input);
    let ms_air = ModSwitchAir {
        preprocessed: ms_trace.preprocessed.clone(),
    };
    let ms_instances = [StarkInstance {
        air: &ms_air,
        trace: &ms_trace.witness,
        public_values: vec![],
    }];
    let ms_data = ProverData::from_instances(config, &ms_instances);
    let modulus_switch = prove_batch(config, &ms_instances, &ms_data);

    let switched = generate_haste_mod_switch_witness(statement.input);
    let br_trace = generate_haste_blind_rotation_witness(&switched, statement.lut, keys.bsk)?;
    let permutation = haste_to_vfhe_ntt_permutation();
    let bsk_views = haste_bsk_views(keys.bsk, &permutation)?;
    let (br_preprocessed, br_num_blocks) = generate_br_preprocessed(&bsk_views);
    let br_air = BlindRotateAir {
        preprocessed: br_preprocessed,
        num_blocks: br_num_blocks,
        public_values: br_trace.public_values.clone(),
    };
    let br_instances = [StarkInstance {
        air: &br_air,
        trace: &br_trace.witness,
        public_values: br_trace.public_values.clone(),
    }];
    let br_data = ProverData::from_instances(config, &br_instances);
    let br_psi = Val::two_adic_generator(LOG_RING_DIMENSION + 1);
    let blind_rotation = prove_batch_with_northstar(
        config,
        &br_instances,
        &br_data,
        Some(|alpha: Challenge, eta: Challenge, rho: Challenge| {
            compute_northstar_witness(
                &br_trace.witness,
                &BR_F_COLS,
                &BR_G_COLS,
                alpha,
                eta,
                rho,
                LOG_RING_DIMENSION,
                br_num_blocks,
                br_psi,
            )
        }),
    );

    let ks_trace = generate_haste_ks_trace(&br_trace.final_acc, keys.ksk, statement.output)?;
    let ks_air = HasteKsAir {
        preprocessed: ks_trace.preprocessed.clone(),
    };
    let ks_instances = [StarkInstance {
        air: &ks_air,
        trace: &ks_trace.witness,
        public_values: ks_trace.public_values.clone(),
    }];
    let ks_data = ProverData::from_instances(config, &ks_instances);
    let key_switch = prove_batch_with_northstar(
        config,
        &ks_instances,
        &ks_data,
        Some(|alpha: Challenge, eta: Challenge, rho: Challenge| {
            compute_northstar_witness(
                &ks_trace.witness,
                &HASTE_KS_NORTHSTAR_F_COLS,
                &HASTE_KS_NORTHSTAR_G_COLS,
                alpha,
                eta,
                rho,
                LOG_RING_DIMENSION,
                1,
                br_psi,
            )
        }),
    );

    Ok(HastePbsProof {
        modulus_switch,
        blind_rotation,
        key_switch,
        final_accumulator: br_trace.final_acc,
    })
}

pub fn verify_haste_pbs(
    config: &PbsStarkConfig,
    statement: &HastePbsStatement<'_>,
    keys: &HasteEvaluationKeys<'_>,
    proof: &HastePbsProof,
) -> Result<(), String> {
    validate_haste_profile(statement, keys).map_err(|error| error.to_string())?;
    let mut preprocessing =
        prepare_haste_pbs_verifier(config, keys.bsk).map_err(|error| error.to_string())?;
    verify_haste_pbs_with_preprocessing(config, statement, keys.ksk, &mut preprocessing, proof)
}

pub fn verify_haste_pbs_with_preprocessing(
    config: &PbsStarkConfig,
    statement: &HastePbsStatement<'_>,
    ksk: &KeySwitchingRLWEKey<HasteField>,
    preprocessing: &mut HastePbsVerifierPreprocessing,
    proof: &HastePbsProof,
) -> Result<(), String> {
    validate_haste_statement(statement).map_err(|error| error.to_string())?;
    validate_haste_ksk(ksk).map_err(|error| error.to_string())?;

    let input = to_vfhe_lwe(statement.input);
    let ms_trace = generate_ms_trace(&input);
    let ms_air = ModSwitchAir {
        preprocessed: ms_trace.preprocessed,
    };
    let ms_data = ProverData::from_airs_and_degrees(
        config,
        core::slice::from_ref(&ms_air),
        &[LOG_RING_DIMENSION],
    );
    verify_batch(
        config,
        core::slice::from_ref(&ms_air),
        &proof.modulus_switch,
        &[vec![]],
        &ms_data.common,
    )
    .map_err(|error| format!("modulus-switch verification failed: {error:?}"))?;

    let switched = generate_haste_mod_switch_witness(statement.input);
    let lut = to_vfhe_lut(statement.lut);
    let br_public_values = generate_haste_br_public_values(
        &switched
            .mask
            .iter()
            .map(|&value| value as u32)
            .collect::<Vec<_>>(),
        switched.body as u32,
        &lut,
        &proof.final_accumulator,
    );
    preprocessing.blind_rotation_air.public_values = br_public_values.clone();
    verify_batch_with_northstar(
        config,
        core::slice::from_ref(&preprocessing.blind_rotation_air),
        &proof.blind_rotation,
        &[br_public_values],
        &preprocessing.blind_rotation_common,
        &preprocessing.blind_rotation_northstar,
    )
    .map_err(|error| format!("blind-rotation verification failed: {error:?}"))?;

    let ks_public_values = haste_ks_public_values(&proof.final_accumulator, statement.output);
    let ks_air = HasteKsAir {
        preprocessed: generate_haste_ks_preprocessed(ksk, &ks_public_values)
            .map_err(|error| error.to_string())?,
    };
    let ks_data = ProverData::from_airs_and_degrees(
        config,
        core::slice::from_ref(&ks_air),
        &[LOG_RING_DIMENSION],
    );
    let ks_northstar = make_northstar_verifier_data(
        HASTE_KS_NORTHSTAR_F_COLS.to_vec(),
        HASTE_KS_NORTHSTAR_G_COLS.to_vec(),
        LOG_RING_DIMENSION,
        1,
        Val::two_adic_generator(LOG_RING_DIMENSION + 1),
        Val::two_adic_generator(LOG_RING_DIMENSION),
    );
    verify_batch_with_northstar(
        config,
        &[ks_air],
        &proof.key_switch,
        &[ks_public_values],
        &ks_data.common,
        &ks_northstar.precompute::<Val>(),
    )
    .map_err(|error| format!("key-switch verification failed: {error:?}"))
}

fn to_vfhe_lwe(input: &crate::haste_compat::HasteLweCiphertext) -> LweCiphertext {
    LweCiphertext {
        a: input.a().iter().map(|value| GF(value.value())).collect(),
        b: GF(input.b().value()),
    }
}

fn to_vfhe_lut(lut: &crate::haste_compat::HasteLut) -> Poly {
    Poly::from_coeffs(
        lut.as_slice()
            .iter()
            .map(|value| GF(value.value()))
            .collect(),
    )
}

fn haste_ks_public_values(
    accumulator: &GlweCiphertext,
    output: &crate::haste_compat::HasteLweCiphertext,
) -> Vec<Val> {
    let mut values = Vec::with_capacity(HASTE_KS_PUBLIC_VALUES);
    values.extend(accumulator.a.coeffs.iter().map(|value| Val::new(value.0)));
    values.push(Val::new(
        (accumulator.b.coeffs[0] + GF(tfhe_goldilocks::params::Q >> 3)).0,
    ));
    values.extend(output.a().iter().map(|value| Val::new(value.value())));
    values.push(Val::new(output.b().value()));
    values
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use haste_algebra::{Field, Polynomial};
    use haste_fhe_core::{lwe_modulus_switch, KeySwitchingRLWEKey, RLWEBlindRotationKey};
    use haste_tfhe::bfhe::GOLDILOCKS_BINARY_128_BITS_PARAMETERS;
    use haste_tfhe::KeyGen;

    use super::*;
    use crate::config::make_test_config;
    use crate::haste_compat::{
        HasteField, HasteLweCiphertext, HASTE_LWE_DIMENSION, HASTE_SWITCH_MODULUS,
    };

    #[test]
    fn proves_and_verifies_native_haste_pbs() {
        let setup_start = Instant::now();
        let secret_key = KeyGen::generate_secret_key(*GOLDILOCKS_BINARY_128_BITS_PARAMETERS);
        let bsk = RLWEBlindRotationKey::generate(&secret_key);
        let ksk = KeySwitchingRLWEKey::generate(&secret_key);
        let input = HasteLweCiphertext::new(
            (0..HASTE_LWE_DIMENSION)
                .map(|index| HasteField::new((index as u64).wrapping_mul(0x1_0000_0001)))
                .collect(),
            HasteField::new(HasteField::MODULUS_VALUE - 1),
        );
        let lut = Polynomial::new(
            (0..HASTE_RING_DIMENSION)
                .map(|index| HasteField::new((index as u64).wrapping_mul(0x9e37_79b9)))
                .collect(),
        );
        let switched = lwe_modulus_switch(&input, HASTE_SWITCH_MODULUS);
        let mut accumulator = bsk.blind_rotate(
            lut.clone(),
            &switched,
            GOLDILOCKS_BINARY_128_BITS_PARAMETERS.blind_rotation_basis(),
        );
        accumulator.b_mut()[0] += HasteField::new(tfhe_goldilocks::params::Q >> 3);
        let output = ksk.key_switch_for_rlwe(accumulator);
        let keys = HasteEvaluationKeys {
            bsk: &bsk,
            ksk: &ksk,
        };
        let statement = HastePbsStatement {
            input: &input,
            output: &output,
            lut: &lut,
        };
        let config = make_test_config();
        let setup_time = setup_start.elapsed();

        let verifier_preprocess_start = Instant::now();
        let mut verifier_preprocessing = prepare_haste_pbs_verifier(&config, &bsk)
            .expect("Haste BSK verifier preprocessing must succeed");
        let verifier_preprocess_time = verifier_preprocess_start.elapsed();

        let prove_start = Instant::now();
        let proof = prove_haste_pbs(&config, &statement, &keys)
            .expect("native HasteBoots inputs must be provable");
        let prove_time = prove_start.elapsed();
        let proof_bytes = postcard::to_allocvec(&proof.modulus_switch).unwrap().len()
            + postcard::to_allocvec(&proof.blind_rotation).unwrap().len()
            + postcard::to_allocvec(&proof.key_switch).unwrap().len();
        let verify_start = Instant::now();
        verify_haste_pbs_with_preprocessing(
            &config,
            &statement,
            &ksk,
            &mut verifier_preprocessing,
            &proof,
        )
        .expect("Haste-compatible PBS proof must verify");
        let verify_time = verify_start.elapsed();

        let mut tampered_output = output.clone();
        tampered_output.a_mut()[0] += HasteField::new(1);
        let tampered_statement = HastePbsStatement {
            input: &input,
            output: &tampered_output,
            lut: &lut,
        };
        let reject_start = Instant::now();
        assert!(verify_haste_pbs_with_preprocessing(
            &config,
            &tampered_statement,
            &ksk,
            &mut verifier_preprocessing,
            &proof,
        )
        .is_err());
        let reject_time = reject_start.elapsed();
        eprintln!(
            "HASTE_COMPAT_BENCH setup_ms={:.1} verifier_preprocess_ms={:.1} prove_ms={:.1} verify_ms={:.1} reject_ms={:.1} proof_bytes={proof_bytes}",
            setup_time.as_secs_f64() * 1000.0,
            verifier_preprocess_time.as_secs_f64() * 1000.0,
            prove_time.as_secs_f64() * 1000.0,
            verify_time.as_secs_f64() * 1000.0,
            reject_time.as_secs_f64() * 1000.0,
        );
    }
}
