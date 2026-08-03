use crate::commitment::ABDLOP;
use crate::matrix::Matrix;
use crate::polynomial::{Poly, PolyCanon, Poly_U128};
use crate::common_static::{MODULUS_SQRT_ZQ, MODULUS_SQRT_INV_ZQ};
use crate::common::{DEGREE, MODULUS_SQRT}; // adjust if path differs
use crate::common_trait::SigmaReflect;
use num_traits::{One, Zero};
use std::ops::Neg;

/// A "consistency proof"
///  (check that passing only necessary parameters in proof and arg...)
#[derive(Clone, Debug)]
pub struct ProofOfConsistency {
    // commitment under `abdlop` using randomness r1
    pub cm_proof: Matrix<Poly>,
    pub r_proof: Matrix<Poly>,

    // ABDLOP ZKP initial commitment
    pub w: Matrix<Poly>,
    pub y1: Matrix<Poly>,
    pub y2: Matrix<Poly>,
    pub y3: Poly,

    pub masking_g: Poly,
    pub bin_challenge_mat: Vec<Vec<Poly_U128>>, // big (debug); you can remove if not needed
    pub bin_challenge_mat_poly: Vec<Matrix<Poly>>,
    pub dj_vec: Vec<Poly>,
    pub dj_vec_prime: Vec<Poly>,
    pub z3: Poly,
    pub h_poly: Poly,
    pub challenge: Poly,
    pub z1: Matrix<Poly>,
    pub z2: Matrix<Poly>,
}

pub fn gen_proof_of_consistency(
    bdlop: &ABDLOP,     // original (qpadl) parameters used to produce cm1,r1
    abdlop: &ABDLOP,
    value: Poly,
    r1: &Matrix<Poly>,  // witness randomness used in original commitment
) -> ProofOfConsistency {
    // Split original commitment key + (later) original commitment
    let (ori_ck_top, ori_ck_m1, ori_ck_m2, ori_ck_m3) = bdlop.ck.slice_into_4(bdlop.ck_binding_height_n);

    // Split abdlop ck
    let (ck_top, ck_m1, ck_m2, ck_m3) = abdlop.ck.slice_into_4(abdlop.ck_binding_height_n);

    // Sample y3 and masking_g, commit (value,y3,masking_g) with shared randomness r1
    let y3 = Poly::random_discrete_gaussian(bdlop.std_dev_sigma);
    let masking_g = Poly::random_constant_unmasked();

    let prepared_message = abdlop.prepare_simple_message(vec![value.clone(), y3.clone(), masking_g.clone()]);
    let (cm_proof, r_proof) = abdlop.commit_full(&prepared_message, r1);

    // Binary challenge matrix
    let (bin_challenge_mat, bin_challenge_mat_poly) =
        Poly::random_binary_vector(bdlop.randomness_vector_dimension_k);

    // Compute z3 = y3 + <Ri, r1> (your rir1_poly)
    let r1_coeffs_flatten = r1
        .to_vec()
        .iter()
        .fold(vec![], |acc, x| [acc, x.clone().flatten()].concat());

    let mut poly_coeff = vec![Poly_U128::zero(); DEGREE];
    for i in 0..bin_challenge_mat.len() {
        poly_coeff[i] = PolyCanon::inner_product(bin_challenge_mat[i].clone(), r1_coeffs_flatten.clone());
    }
    let rir1_poly = Poly::new(poly_coeff.try_into().unwrap());
    let z3 = &y3 + &rir1_poly;

    // Linear combination challenges
    let dj_vec = Poly::random_zq_vec(DEGREE);
    let dj_vec_prime = Poly::random_zq_vec(DEGREE - 1);

    // Build e_j selector vectors (and sigma)
    let mut ej_vec = vec![];
    let mut ej_vec_sigma = vec![];
    for i in 0..DEGREE {
        let mut ez = [Poly_U128::zero(); DEGREE];
        ez[i] = Poly_U128::one();
        let ez_poly = Poly::new(ez);
        ej_vec.push(Matrix::from_vec_transpose(vec![ez_poly.clone()]));
        ej_vec_sigma.push(Matrix::from_vec_transpose(vec![ez_poly.sigma_reflect()]));
    }

    let bin_challenge_mat_poly_sigma: Vec<Matrix<Poly>> =
        bin_challenge_mat_poly.iter().map(|vec| vec.map(|poly| poly.sigma_reflect())).collect();

    // h_poly = x_rr + x_ey - x_ez + x_v + masking_g
    let x_ez_term = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_sigma, &Matrix::from_vec(vec![z3.clone()]));
    let x_ey_term = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_sigma, &Matrix::from_vec(vec![y3.clone()]));
    let x_rr_term = ABDLOP::compute_product_sum(&dj_vec, &bin_challenge_mat_poly_sigma, r1);
    let x_v_term = ABDLOP::compute_product_sum(&dj_vec_prime, &ej_vec_sigma[1..].to_vec(), &Matrix::from_vec(vec![value.clone()]));

    let h_poly = x_rr_term.clone() + x_ey_term.clone() + x_ez_term.neg() + x_v_term.clone() + masking_g.clone();

    // ABDLOP ZKP initial commit
    let (w, y1, y2) = abdlop.zkp_abdlop_initial_commit();

    // Final challenge
    let challenge = ABDLOP::get_challenge();

    // Final responses
    let z1 = &y1 + &(r1 * &challenge);
    let z2 = &y2 + &(&r_proof * &challenge);

    ProofOfConsistency {
        cm_proof,
        r_proof,
        w,
        y1,
        y2,
        y3,
        masking_g,
        bin_challenge_mat,
        bin_challenge_mat_poly,
        dj_vec,
        dj_vec_prime,
        z3,
        h_poly,
        challenge,
        z1,
        z2,
    }
}

pub fn verify_proof_of_consistency(
    bdlop: &ABDLOP,
    abdlop: &ABDLOP,
    cm1: &Matrix<Poly>,         // original commitment from bdlop.commit(...)
    proof: &ProofOfConsistency,
) -> bool {
    // Split original commitment bdlop, and keys
    let (ori_com0, ori_com1, ori_com2, ori_com3) = cm1.slice_into_4(bdlop.ck_binding_height_n);
    let (ori_ck_top, ori_ck_m1, ori_ck_m2, ori_ck_m3) = bdlop.ck.slice_into_4(bdlop.ck_binding_height_n);

    // Split abdlop ck and proof commitment
    let (ck_top, ck_m1, ck_m2, ck_m3) = abdlop.ck.slice_into_4(abdlop.ck_binding_height_n);
    let (cm_top, cm_m, cm_gp1, cm_gp2) = proof.cm_proof.slice_into_4(abdlop.ck_binding_height_n);

    // compute "leftover_y_*"
    let negative_by2 = (&ck_m1 * &proof.y2).neg();

    let leftover_y_0 = &ori_ck_top * &proof.y1;
    let leftover_y_1 = (&ori_ck_m1 * &proof.y1) + negative_by2.clone();

    let mut neg_sqrtq_by2 = negative_by2.clone();
    neg_sqrtq_by2 *= *MODULUS_SQRT_ZQ;
    let leftover_y_2 = (&ori_ck_m2 * &proof.y1) + neg_sqrtq_by2;

    let leftover_y_3 = (&ori_ck_m3 * &proof.y1) + negative_by2.clone();

    // (e): (ck_atjai*z1) + (ck_top*z2) == w + cm_top*c
    let lhs = (&abdlop.ck_atjai * &proof.z1) + (&ck_top * &proof.z2);
    let rhs = &proof.w + &(&cm_top * &proof.challenge);
    if lhs != rhs {
        return false;
    }

    // masked_message terms (exactly like test)
    let masked_message_cf1_minus_bz2 = (&cm_m * &proof.challenge) + (&ck_m1 * &proof.z2).neg();
    let mut sqrtq_masked_message_cf1_minus_bz2 = masked_message_cf1_minus_bz2.clone();
    sqrtq_masked_message_cf1_minus_bz2 *= *MODULUS_SQRT_ZQ;

    let masked_message_cu1_minus_bz2 = (&cm_gp1 * &proof.challenge) + (&ck_m2 * &proof.z2).neg();
    let masked_message_cu2_minus_bz2 = (&cm_gp2 * &proof.challenge) + (&ck_m3 * &proof.z2).neg();

    // (f-0..3) leftovers
    let compute_leftover_0 = (&ori_ck_top * &proof.z1) + (&ori_com0 * &proof.challenge).neg();
    if compute_leftover_0 != leftover_y_0 {
        return false;
    }

    let compute_leftover_1 =
        (&ori_ck_m1 * &proof.z1) + masked_message_cf1_minus_bz2.clone() + (&ori_com1 * &proof.challenge).neg();
    if compute_leftover_1 != leftover_y_1 {
        return false;
    }

    let compute_leftover_2 =
        (&ori_ck_m2 * &proof.z1) + sqrtq_masked_message_cf1_minus_bz2 + (&ori_com2 * &proof.challenge).neg();
    if compute_leftover_2 != leftover_y_2 {
        return false;
    }

    let compute_leftover_3 =
        (&ori_ck_m3 * &proof.z1) + masked_message_cf1_minus_bz2.clone() + (&ori_com3 * &proof.challenge).neg();
    if compute_leftover_3 != leftover_y_3 {
        return false;
    }

    // (f-4)
    // Rebuild e_j sigma vectors
    let mut ej_vec_sigma = vec![];
    for i in 0..DEGREE {
        let mut ez = [Poly_U128::zero(); DEGREE];
        ez[i] = Poly_U128::one();
        let ez_poly = Poly::new(ez);
        ej_vec_sigma.push(Matrix::from_vec_transpose(vec![ez_poly.sigma_reflect()]));
    }

    let bin_challenge_mat_poly_sigma: Vec<Matrix<Poly>> =
        proof.bin_challenge_mat_poly.iter().map(|vec| vec.map(|poly| poly.sigma_reflect())).collect();

    let leftover_y_4_1 = ABDLOP::compute_product_sum(&proof.dj_vec, &bin_challenge_mat_poly_sigma, &proof.y1);
    let leftover_y_4_2 = ABDLOP::compute_product_sum(
        &proof.dj_vec_prime,
        &ej_vec_sigma[1..].to_vec(),
        &negative_by2,
    );
    let leftover_y_4_3 = ABDLOP::compute_product_sum(
        &proof.dj_vec,
        &ej_vec_sigma,
        &(&ck_m2 * &proof.y2).neg(),
    );
    let leftover_y_4 =
        leftover_y_4_1 + leftover_y_4_2 + leftover_y_4_3 + (&ck_m3 * &proof.y2).neg().to_item_t();

    let z_4_1 = ABDLOP::compute_product_sum(&proof.dj_vec, &bin_challenge_mat_poly_sigma, &proof.z1);
    let z_4_2 = ABDLOP::compute_product_sum(
        &proof.dj_vec_prime,
        &ej_vec_sigma[1..].to_vec(),
        &Matrix::from_vec(vec![masked_message_cf1_minus_bz2.to_item_t()]),
    );
    let z_4_3 = ABDLOP::compute_product_sum(&proof.dj_vec, &ej_vec_sigma, &masked_message_cu1_minus_bz2);

    let ez_sigma = ABDLOP::compute_product_sum(&proof.dj_vec, &ej_vec_sigma, &Matrix::from_vec(vec![proof.z3.clone()]));
    let compute_leftover_4 = z_4_1
        + z_4_2
        + z_4_3
        + masked_message_cu2_minus_bz2.to_item_t()
        + ((proof.h_poly.clone() + ez_sigma) * proof.challenge.clone()).neg();

    if compute_leftover_4 != leftover_y_4 {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_of_consistency() {
        let (bdlop, _st1, _st2, _et1, _et2) = ABDLOP::new_random_instance();

        let value = Poly::random_integer();
        let m_vec = bdlop.prepare_qpadl_message(value.clone());
        let (cm1, r1) = bdlop.commit(&m_vec);

        let (abdlop, _, _, _, _) = ABDLOP::new_random_instance();

        let proof = gen_proof_of_consistency(&bdlop, &abdlop, value.clone(), &r1);

        assert!(verify_proof_of_consistency(&bdlop, &abdlop, &cm1, &proof));
    }
    #[test]
    fn test_proof_of_consistency_false() {
        let (bdlop, _st1, _st2, _et1, _et2) = ABDLOP::new_random_instance();

        let value = Poly::random_integer();
        let m_vec = bdlop.prepare_qpadl_message(value.clone());
        let (_cm1, r1) = bdlop.commit(&m_vec);
        let (cm1_, _r1_) = bdlop.commit(&m_vec);

        let (abdlop, _, _, _, _) = ABDLOP::new_random_instance();

        let proof = gen_proof_of_consistency(&bdlop, &abdlop, value.clone(), &r1);
        assert!(!verify_proof_of_consistency(&bdlop, &abdlop, &cm1_, &proof));
    }
}
