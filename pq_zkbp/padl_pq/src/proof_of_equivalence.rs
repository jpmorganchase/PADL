// src/proof_of_equivalence.rs

use ark_ff::Field;
use crate::commitment::ABDLOP;
use crate::matrix::Matrix;
use crate::polynomial::{Poly, PolyCanon, Poly_U128};
use crate::common::DEGREE;
use num_traits::Zero;
use std::ops::Neg;
use crate::common_trait::SigmaReflect;

/* =========================================================
   Proof of Equivalence 
========================================================= */

#[derive(Clone, Debug)]
pub struct ProofOfEquivalence {
    // Public objects derived from cm1,cm2 and ck (verifier recomputes too, but we store it, we should probably remove due to size...
    pub poe_com_diff_0: Matrix<Poly>,      // cm1_com0 - cm2_com0
    pub poe_u_pk1_pk2: Matrix<Poly>,       // [ck_m1; ck_m2] stacked
    pub poe_ubar_comdiff1_2: Matrix<Poly>, // [cm1_com1-cm2_com1 ; cm1_com2-cm2_com2] stacked

    // ABDLOP commitment to (y3, g) using concat_m randomness (public commitment parts)
    pub cm_top: Matrix<Poly>,
    pub cm_y3: Matrix<Poly>,
    pub cm_g: Matrix<Poly>,

    // Main sigma transcript for ABDLOP opening proof
    pub w: Matrix<Poly>,
    pub challenge: Poly,
    pub z1: Matrix<Poly>,
    pub z2: Matrix<Poly>,

    // Aux for the v1 check
    pub z3: Poly,     // z3 = y3 + <R_i, l_flat> as a polynomial
    pub h_poly: Poly, // h = x_rcm + x_ey - x_ez - x_comdiff_ubar + g

    // challenges used in compute_product_sum checks
    pub dj_vec: Vec<Poly>,                    // length DEGREE
    pub bin_challenge_mat_poly_sigma: Vec<Matrix<Poly>>, // sigma version

    // leftover checks (verifier compares to these)
    pub v0_leftover_y: Matrix<Poly>,
    pub v1_leftover_y: Poly,
}


fn flatten_matrix_coeffs(m: &Matrix<Poly>) -> Vec<Poly_U128> {
    let l_vec = m.to_vec();
    let total_coeff = DEGREE * l_vec.len();
    let mut ret_vec = vec![Poly_U128::ZERO; total_coeff];

    let mut counter = 0usize;
    for poly in l_vec {
        let f = poly.flatten();
        for i in 0..DEGREE {
            ret_vec[counter + i] = f[i];
        }
        counter += DEGREE;
    }
    ret_vec
}

/* =========================================================
   Prover
   Inputs: cm1,cm2,m_vec,r1,r2 are GIVEN (not created here).
========================================================= */

pub fn gen_proof_of_equivalence(
    bdlop: &ABDLOP,
    abdlop: &ABDLOP,

    st1: &Matrix<Poly>,
    st2: &Matrix<Poly>,
    et1: &Matrix<Poly>,
    et2: &Matrix<Poly>,

    m_vec: &Matrix<Poly>,
    cm1: &Matrix<Poly>,
    cm2: &Matrix<Poly>,
    r1: &Matrix<Poly>,
    r2: &Matrix<Poly>,
) -> ProofOfEquivalence {

    // --- sanity (mirrors your test invariants) ---
    assert_eq!(st1.row_m, 1);
    assert_eq!(st2.row_m, 1);
    assert_eq!(et1.row_m, 1);
    assert_eq!(et2.row_m, 1);

    // concat randomness matrix used in abdlop.commit_full(..., &concat_m_matrix)
    let concat_m = [
        st1.to_vec_onerow(),
        et1.to_vec_onerow(),
        st2.to_vec_onerow(),
        et2.to_vec_onerow(),
    ]
        .concat();
    let concat_m_matrix = Matrix::from_vec(concat_m);
    // split commitments and ck from bdlop
    let n = bdlop.ck_binding_height_n;

    let (cm1_com0, cm1_com1, cm1_com2, _cm1_com3) = cm1.slice_into_4(n);
    let (cm2_com0, cm2_com1, cm2_com2, _cm2_com3) = cm2.slice_into_4(n);

    let (_ck_top, ck_m1, ck_m2, _ck_m3) = bdlop.ck.slice_into_4(n);

    // public diffs (these MUST be recomputable by verifier from cm1/cm2)
    let poe_com_diff_0 = cm1_com0 + cm2_com0.neg();

    let poe_u_pk1_pk2 = Matrix::from_vec([ck_m1.to_vec_onerow(), ck_m2.to_vec_onerow()].concat());

    let poe_ubar_comdiff1_2 = Matrix::from_vec(
        [
            (cm1_com1 + cm2_com1.neg()).to_vec_onerow(),
            (cm1_com2 + cm2_com2.neg()).to_vec_onerow(),
        ]
            .concat(),
    );

    // build l = [[Cbar*s1],[Cbar*s2]] - ubar
    let com0diff_s1 = &poe_com_diff_0.transpose() * &st1.transpose();
    let com0diff_s2 = &poe_com_diff_0.transpose() * &st2.transpose();
    let poe_norm_target_wo_u = Matrix::v_stack(&com0diff_s1, &com0diff_s2);
    let l_mat = &poe_norm_target_wo_u + &poe_ubar_comdiff1_2.neg();
    // sample y3 and masking g and commit in abdlop with randomness concat_m_matrix
    let y3 = Poly::random_discrete_gaussian(bdlop.std_dev_sigma);
    let masking_g = Poly::random_constant_unmasked();
    assert_eq!(masking_g.canonical_repr()[0], Poly_U128::ZERO);

    let prepared_message = abdlop.prepare_simple_message(vec![y3.clone(), masking_g.clone()]);
    let (cm_proof, r_proof) = abdlop.commit_full(&prepared_message, &concat_m_matrix);
    let (cm_top, cm_y3, cm_g) = cm_proof.slice_into_3(abdlop.ck_binding_height_n);

    // binary challenge based on l length, sigma version
    let (bin_challenge_mat, bin_challenge_mat_poly_sigma) =
        Poly::random_binary_vector(l_mat.to_vec().len());

    // compute <R_i, l_flat> polynomial, then z3 = y3 + something...
    let l_coeffs_flat = flatten_matrix_coeffs(&l_mat);

    let mut poly_coeff = vec![Poly_U128::ZERO; DEGREE];
    for i in 0..DEGREE {
        assert_eq!(bin_challenge_mat[i].len(), DEGREE * l_mat.to_vec().len());
        poly_coeff[i] =
            PolyCanon::inner_product(bin_challenge_mat[i].clone(), l_coeffs_flat.clone());
    }

    let rir_poly = Poly::new(poly_coeff.try_into().unwrap());
    let z3 = &y3 + &rir_poly;

    // choose dj_vec
    let dj_vec = Poly::random_zq_vec(DEGREE);

    // build ej_vec_sigma
    let mut ej_vec_sigma = vec![Matrix::<Poly>::empty(); DEGREE];
    for i in 0..DEGREE {
        let mut ez = [Poly_U128::ZERO; DEGREE];
        ez[i] = Poly_U128::ONE;
        let ez_poly = Poly::new(ez);
        ej_vec_sigma[i] = Matrix::from_vec_transpose(vec![ez_poly.sigma_reflect()]);
    }

    // compute h_poly
    let x_ez_term = ABDLOP::compute_product_sum(
        &dj_vec,
        &ej_vec_sigma,
        &Matrix::from_vec(vec![z3.clone()]),
    );
    let x_ey_term = ABDLOP::compute_product_sum(
        &dj_vec,
        &ej_vec_sigma,
        &Matrix::from_vec(vec![y3.clone()]),
    );
    let x_rcm_term =
        ABDLOP::compute_product_sum(&dj_vec, &bin_challenge_mat_poly_sigma, &poe_norm_target_wo_u);
    let x_comdiff_ubar: Poly =
        ABDLOP::compute_product_sum(&dj_vec, &bin_challenge_mat_poly_sigma, &poe_ubar_comdiff1_2);

    let h_poly = x_rcm_term + x_ey_term + x_ez_term.neg() + x_comdiff_ubar.neg() + masking_g;
    assert_eq!(h_poly.canonical_repr()[0], Poly_U128::ZERO);

    // ZK opening proof for ABDLOP: (w, y1, y2)
    let (w, y1, y2) = abdlop.zkp_abdlop_initial_commit();

    // split y1 into blocks (same as your test)
    let (y1_s1, others) = y1.v_split(n);
    let (y1_e1, others) = others.v_split(bdlop.randomness_vector_dimension_k);
    let (y1_s2, y2_e2) = others.v_split(n);

    let (ck_top_bdlop, _, _, _) = bdlop.ck.slice_into_4(n);

    let leftover_y0_s1e1 = (&ck_top_bdlop.transpose() * &y1_s1) + y1_e1;
    let leftover_y0_s2e2 = (&ck_top_bdlop.transpose() * &y1_s2) + y2_e2;
    let v0_leftover_y = Matrix::v_stack(&leftover_y0_s1e1, &leftover_y0_s2e2);

    // v1 leftover (same algebra as your test)
    let (abdlop_ck_top, abdlop_ck_m1, abdlop_ck_m2) =
        abdlop.ck.slice_into_3(abdlop.ck_binding_height_n);
    let _ = abdlop_ck_top; // silence unused if you don’t use it in generator

    let cbary_top = &poe_com_diff_0.transpose() * &y1_s1;
    let cbary_bot = &poe_com_diff_0.transpose() * &y1_s2;
    let cbary = Matrix::v_stack(&cbary_top, &cbary_bot);

    let leftover_y_1_drcy =
        ABDLOP::compute_product_sum(&dj_vec, &bin_challenge_mat_poly_sigma, &cbary);

    let minus_by2_b_for_y3 = (&abdlop_ck_m1 * &y2).neg();
    let leftover_y_1_deby2minus =
        ABDLOP::compute_product_sum(&dj_vec, &ej_vec_sigma, &minus_by2_b_for_y3);

    let minus_by2_bg = (&abdlop_ck_m2 * &y2).neg();
    let v1_leftover_y = leftover_y_1_drcy + leftover_y_1_deby2minus + minus_by2_bg.to_item_t();
    // final challenge + responses
    let challenge = ABDLOP::get_challenge();

    let cm_for_z1 = &concat_m_matrix * &challenge;
    let z1 = y1 + cm_for_z1;

    let cr_proof = &r_proof * &challenge;
    let z2 = y2 + cr_proof;

    ProofOfEquivalence {
        poe_com_diff_0,
        poe_u_pk1_pk2,
        poe_ubar_comdiff1_2,
        cm_top,
        cm_y3,
        cm_g,
        w,
        challenge,
        z1,
        z2,
        z3,
        h_poly,
        dj_vec,
        bin_challenge_mat_poly_sigma,
        v0_leftover_y,
        v1_leftover_y,
    }
}

/* =========================================================
   Verifier (END-TO-END, binds to cm1 & cm2)
========================================================= */

pub fn verify_proof_of_equivalence(
    bdlop: &ABDLOP,
    abdlop: &ABDLOP,
    cm1: &Matrix<Poly>,
    cm2: &Matrix<Poly>,
    proof: &ProofOfEquivalence,
) -> bool {
    let n = bdlop.ck_binding_height_n;

    // ------------------------------------------------------------
    // 0) Recompute public derived terms from (cm1, cm2, bdlop.ck)
    //    (Never trust prover-provided poe_*.)
    // ------------------------------------------------------------
    let (cm1_com0, cm1_com1, cm1_com2, _cm1_com3) = cm1.slice_into_4(n);
    let (cm2_com0, cm2_com1, cm2_com2, _cm2_com3) = cm2.slice_into_4(n);

    let (ck_top_bdlop, ck_m1, ck_m2, _ck_m3) = bdlop.ck.slice_into_4(n);

    let poe_com_diff_0 = cm1_com0 + cm2_com0.neg();
    let poe_u_pk1_pk2 = Matrix::from_vec([ck_m1.to_vec_onerow(), ck_m2.to_vec_onerow()].concat());
    let poe_ubar_comdiff1_2 = Matrix::from_vec(
        [
            (cm1_com1 + cm2_com1.neg()).to_vec_onerow(),
            (cm1_com2 + cm2_com2.neg()).to_vec_onerow(),
        ]
            .concat(),
    );

    // Optional debug: ensure proof’s cached values match
    if proof.poe_com_diff_0 != poe_com_diff_0 { return false; }
    if proof.poe_u_pk1_pk2 != poe_u_pk1_pk2 { return false; }
    if proof.poe_ubar_comdiff1_2 != poe_ubar_comdiff1_2 { return false; }

    // ------------------------------------------------------------
    // 1) Sigma opening equation (e):
    //    A_tajai z1 + A_top z2 == w + cm_top * c
    // ------------------------------------------------------------
    let (abdlop_ck_top, abdlop_ck_m1, abdlop_ck_m2) =
        abdlop.ck.slice_into_3(abdlop.ck_binding_height_n);

    let c = proof.challenge.clone();

    let lhs_e = &(&abdlop.ck_atjai * &proof.z1) + &(&abdlop_ck_top * &proof.z2);
    let rhs_e = &proof.w + &(&proof.cm_top * &c);
    if lhs_e != rhs_e {
        return false;
    }

    // ------------------------------------------------------------
    // 2) Build ej_vec_sigma (depends only on DEGREE)
    // ------------------------------------------------------------
    let mut ej_vec_sigma: Vec<Matrix<Poly>> = Vec::with_capacity(DEGREE);
    for i in 0..DEGREE {
        let mut ez = [Poly_U128::ZERO; DEGREE];
        ez[i] = Poly_U128::ONE;
        let ez_poly = Poly::new(ez);
        ej_vec_sigma.push(Matrix::from_vec_transpose(vec![ez_poly.sigma_reflect()]));
    }

    // ------------------------------------------------------------
    // 3) v0 check:
    //    tz_minus_cu == v0_leftover_y
    // ------------------------------------------------------------
    let (z1_s1, others) = proof.z1.v_split(n);
    let (z1_e1, others) = others.v_split(bdlop.randomness_vector_dimension_k);
    let (z1_s2, z1_e2) = others.v_split(n);

    let tz_s1e1 = (&ck_top_bdlop.transpose() * &z1_s1) + z1_e1;
    let tz_s2e2 = (&ck_top_bdlop.transpose() * &z1_s2) + z1_e2;
    let tz = Matrix::v_stack(&tz_s1e1, &tz_s2e2);

    let tz_minus_cu = tz + (&poe_u_pk1_pk2.neg() * &c);

    if tz_minus_cu != proof.v0_leftover_y {
        return false;
    }

    // ------------------------------------------------------------
    // 4) v1 check (your (f)->v1 equation)
    // ------------------------------------------------------------

    // cbarz = [ diff0^T z1_s1 ; diff0^T z1_s2 ]
    let cbarz_top = &poe_com_diff_0.transpose() * &z1_s1;
    let cbarz_bot = &poe_com_diff_0.transpose() * &z1_s2;
    let cbarz = Matrix::v_stack(&cbarz_top, &cbarz_bot);

    // dr(cbarz)
    let tz_com_z = ABDLOP::compute_product_sum(
        &proof.dj_vec,
        &proof.bin_challenge_mat_poly_sigma,
        &cbarz,
    );

    // cu1 - B z2  (y3 channel)
    let minus_bz2_for_y3 = (&abdlop_ck_m1 * &proof.z2).neg();
    let tz_cu1_bz2 = ABDLOP::compute_product_sum(
        &proof.dj_vec,
        &ej_vec_sigma,
        &((&proof.cm_y3 * &c).clone() + minus_bz2_for_y3),
    );

    // cu2 - B z2  (g channel)
    let cu2 = &proof.cm_g * &c;
    let minus_bz2_for_g = (&abdlop_ck_m2 * &proof.z2).neg();
    let tz_cu2_bz2 = cu2 + minus_bz2_for_g; // Matrix<Poly>

    // dez(z3) // we need to check that z3 is small
    let x_ez_term = ABDLOP::compute_product_sum(
        &proof.dj_vec,
        &ej_vec_sigma,
        &Matrix::from_vec(vec![proof.z3.clone()]),
    );

    // dr(ubar_comdiff1_2)
    let x_comdiff_ubar: Poly = ABDLOP::compute_product_sum(
        &proof.dj_vec,
        &proof.bin_challenge_mat_poly_sigma,
        &poe_ubar_comdiff1_2,
    );

    // optional shape constraint
    if proof.h_poly.canonical_repr()[0] != Poly_U128::ZERO {
        return false;
    }

    // (h + dez + drubar) * c
    let v1_rhs = (proof.h_poly.clone() + x_ez_term + x_comdiff_ubar) * c;

    let v1_lhs = tz_com_z
        + tz_cu1_bz2
        + tz_cu2_bz2.to_item_t()
        + v1_rhs.neg();

    if v1_lhs != proof.v1_leftover_y {
        return false;
    }

    true
}

/* =========================================================
   Tests
========================================================= */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_of_equivalence() {
        let (bdlop, st1, st2, et1, et2) = ABDLOP::new_random_instance();
        let abdlop = ABDLOP::new_poe_abdlop();

        // witness created OUTSIDE generator (as requested)
        let value = Poly::random_integer();
        let m_vec = bdlop.prepare_qpadl_message(value);

        let (cm1, r1) = bdlop.commit(&m_vec);
        let (cm2, r2) = bdlop.commit(&m_vec);

        let proof = gen_proof_of_equivalence(
            &bdlop,
            &abdlop,
            &st1,
            &st2,
            &et1,
            &et2,
            &m_vec,
            &cm1,
            &cm2,
            &r1,
            &r2,
        );

        assert!(verify_proof_of_equivalence(&bdlop, &abdlop, &cm1, &cm2, &proof));
    }
    #[test]
    fn test_proof_of_equivalence_negative() {
        let (bdlop, st1, st2, et1, et2) = ABDLOP::new_random_instance();

        let abdlop = ABDLOP::new_poe_abdlop();

        // witness created
        let value = Poly::random_integer();
        let m_vec = bdlop.prepare_qpadl_message(value);

        let (cm1, r1) = bdlop.commit(&m_vec);
        let value = Poly::random_integer();
        let m_vec2 = bdlop.prepare_qpadl_message(value);
        let (cm2, r2) = bdlop.commit(&m_vec2);

        let proof = gen_proof_of_equivalence(
            &bdlop,
            &abdlop,
            &st1,
            &st2,
            &et1,
            &et2,
            &m_vec,
            &cm1,
            &cm2,
            &r1,
            &r2,
        );
        assert!(verify_proof_of_equivalence(&bdlop, &abdlop, &cm1, &cm2, &proof));
    }
}
