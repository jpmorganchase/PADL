//! Approximate Proof of Asset (PoA) TODO: to check norms, to add Fiat Shamir, to add Rej. Sampling or Hint-MLWE cond.
use crate::commitment::ABDLOP;
use crate::matrix::Matrix;
use crate::polynomial::Poly;

use num_traits::{One, Zero};
use std::ops::Neg;

use crate::common::BASEMUL_DEGREE;
use crate::polynomial::{Poly_U128};

#[derive(Clone, Debug)]
pub struct ProofOfAsset {
    pub poa_w: Matrix<Poly>,
    pub poa_u_mult: Matrix<Poly>,
    pub u_lin: Matrix<Poly>,
    pub poa_z: Matrix<Poly>,

    pub random_phi: Poly,
    pub masked_h: Poly,
    pub challenge: Poly,

    /// The commitment cm1 used in the proof
    pub cm1: Matrix<Poly>,
}

/// Generate a Proof-of-Asset for an already-committed message.
///
/// Inputs:
/// - `bdlop`: public parameters
/// - `message`: plaintext polynomial being proven (must match the commitment)
/// - `original_commit`: commitment to `message`
/// - `original_r`: randomness used in `original_commit` (witness)
///
/// Output:
/// - `ProofOfAsset` containing all prover messages + cm1
pub fn gen_proof_of_asset(
    bdlop: &ABDLOP,
    message: &Poly,
    original_commit: &Matrix<Poly>,
    original_r: &Matrix<Poly>,
) -> ProofOfAsset {
    let (ck_top, ck_m1, ck_m2, ck_m3) = bdlop.ck.slice_into_4(bdlop.ck_binding_height_n);

    // --- split original commitment ---
    let (ori_ar, ori_com1_m, _ori_com2_sqrtm, _ori_com3_m) =
        original_commit.slice_into_4(bdlop.ck_binding_height_n);

    // --- prover randomness y ---
    let r_vec: Vec<Poly> = (0..bdlop.randomness_vector_dimension_k)
        .map(|_| Poly::random_binomial())
        .collect();
    let poa_y = Matrix::from_vec(r_vec);

    // --- commitments w and u_mult ---
    let poa_w = &ck_top * &poa_y;
    let poa_u_mult = &(&(&ck_m1 * &poa_y) * &(&ck_m1 * &poa_y)) + &(&ck_m2 * &poa_y);

    // --- build cm1 (aux commitment) ---
    let masking_g = Poly::random_constant_unmasked();

    let message_bin = message.bin_repr();
    let garbage_polynomial =
        (&ck_m1 * &poa_y).to_item_t() * (Poly::one() + (message_bin.clone() + message_bin.clone()).neg());

    // padding zeros for height n
    let mut padding_vec: Vec<Poly> = vec![Poly::zero(); bdlop.ck_binding_height_n];
    // append (bin(m), garbage, masking_g)
    padding_vec.push(message_bin);
    padding_vec.push(garbage_polynomial);
    padding_vec.push(masking_g.clone());
    let prepared_message = Matrix::from_vec(padding_vec);
    let cm1 = bdlop.commit_with_r(&prepared_message, original_r);
    let (_new_cm_ar, new_cm_bin, _new_cm_garbage, _new_cm_maskingg) =
        cm1.slice_into_4(bdlop.ck_binding_height_n);

    // --- linearisation values ---
    let random_phi = Poly::random();
    let random_phi_qt = random_phi.binary_compose_transpose_leftmultiply_self();

    let function_f = (message.bin_repr() * random_phi_qt.clone()) + (message.clone() * random_phi.clone()).neg();
    let masked_h = function_f + masking_g;

    // u_lin = (ck_m3 + ck_m1*QT(phi) - ck_m1*phi) * y
    let u_lin = &(ck_m3.clone() + &ck_m1 * &random_phi_qt + (&ck_m1 * &random_phi).neg()) * &poa_y;

    // --- challenge + response ---
    let challenge = Poly::random();
    let poa_z = poa_y + (original_r * &challenge);

    let _ = new_cm_bin;

    ProofOfAsset {
        poa_w,
        poa_u_mult,
        u_lin,
        poa_z,
        random_phi,
        masked_h,
        challenge,
        cm1,
    }
}
/// Verify a Proof-of-Asset.
///
/// Inputs:
/// - `bdlop`: public parameters
/// - `original_commit`: commitment to the message (public statement)
/// - `proof`: proof object (includes cm1)
///
/// Output:
/// - `true` iff verification passes
pub fn verify_proof_of_asset(
    bdlop: &ABDLOP,
    original_commit: &Matrix<Poly>,
    proof: &ProofOfAsset,
) -> bool {
    let (ck_top, ck_m1, ck_m2, ck_m3) = bdlop.ck.slice_into_4(bdlop.ck_binding_height_n);

    // split commitments
    let (ori_ar, ori_com1_m, _ori_com2_sqrtm, _ori_com3_m) =
        original_commit.slice_into_4(bdlop.ck_binding_height_n);

    let (_new_cm_ar, new_cm_bin, new_cm_garbage, new_cm_maskingg) =
        proof.cm1.slice_into_4(bdlop.ck_binding_height_n);

    let c = proof.challenge.clone();

    // (1) A z = w + A(r) * c   - A(r) is  in original commitment top slice?
    let az = &ck_top * &proof.poa_z;
    if az != (proof.poa_w.clone() + &ori_ar * &c) {
        return false;
    }

    let first_dl_coeff_arr = proof.masked_h.canonical_repr();

    for i in 0..BASEMUL_DEGREE{
        if first_dl_coeff_arr[i] != Poly_U128::zero()
        {
            return false;
        }
    }
    // (2) quadratic relation:
    // 0 ?= f'(f'+c) + f'_2 - u_mult
    let f_prime = &ck_m1 * &proof.poa_z + (&new_cm_bin * &c).neg();
    let f_prime_2 = &ck_m2 * &proof.poa_z + (&new_cm_garbage * &c).neg();

    let quad = f_prime.to_item_t() * (f_prime.to_item_t() + c.clone())
        + f_prime_2.to_item_t()
        + proof.poa_u_mult.to_item_t().neg();

    if quad != Poly::zero() {
        return false;
    }

    // (3) final linear equation
    let random_phi_qt = proof.random_phi.binary_compose_transpose_leftmultiply_self();

    let z_ulin =
        &(ck_m3 + &ck_m1 * &random_phi_qt + (&ck_m1 * &proof.random_phi).neg()) * &proof.poa_z;

    let com_f = &new_cm_bin * &random_phi_qt + (&ori_com1_m * &proof.random_phi).neg();

    let rhs =
        &(new_cm_maskingg + com_f + Matrix::from_vec(vec![proof.masked_h.clone().neg()])) * &c
            + proof.u_lin.clone();

    z_ulin == rhs
}

/* ============================
   Unit test
============================ */

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use crate::common::MODULUS_MINUS1_OVER2;
    use num_traits::pow;

    #[test]
    fn test_proof_of_asset_module_random_int_u64() {
        let (bdlop, _st1, _st2, _et1, _et2) = ABDLOP::new_random_instance();

        let message =  Poly::random_integer();
        let m_vec = bdlop.prepare_qpadl_message(message.clone());
        let (original_commit, original_r) = bdlop.commit(&m_vec);
        let proof = gen_proof_of_asset(&bdlop, &message, &original_commit, &original_r);
        assert!(verify_proof_of_asset(&bdlop, &original_commit, &proof));
    }

    #[test]
    fn test_proof_of_asset_module_positive_value_over_u64() {
        let (bdlop, _st1, _st2, _et1, _et2) = ABDLOP::new_random_instance();

        let mut rnd = rand::rng();
        let message_value: i128 = rnd.random_range(pow(2,64)..MODULUS_MINUS1_OVER2 as i128);
        let message = Poly::from_i128_constant(message_value);
        let m_vec = bdlop.prepare_qpadl_message(message.clone());
        let (original_commit, original_r) = bdlop.commit(&m_vec);
        let proof = gen_proof_of_asset(&bdlop, &message, &original_commit, &original_r);
        assert!(!verify_proof_of_asset(&bdlop, &original_commit, &proof));
    }
    #[test]
    fn test_proof_of_asset_module_negative_value() {
        let (bdlop, _st1, _st2, _et1, _et2) = ABDLOP::new_random_instance();
        let mut rnd = rand::rng();
        let message_value = rnd.random_range(0..MODULUS_MINUS1_OVER2) as i128;
        let message = Poly::from_i128_constant(-message_value);
        let m_vec = bdlop.prepare_qpadl_message(message.clone());
        let (original_commit, original_r) = bdlop.commit(&m_vec);
        let proof = gen_proof_of_asset(&bdlop, &message, &original_commit, &original_r);
        assert!(!verify_proof_of_asset(&bdlop, &original_commit, &proof));
    }
}
