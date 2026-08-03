use ark_ff::Field;
use crate::commitment::ABDLOP;
use crate::matrix::Matrix;
use crate::polynomial::Poly;
use crate::polynomial::Poly_U128;
use crate::common::DEGREE;
use crate::sampler::Sampler;

use num_traits::Zero;
use std::ops::Neg;

use sha3::{Digest as Sha3_Digest, Sha3_256};
/// =========================================================
/// Proof of Balance:
/// Given com_vec = [C1, ..., Cn], prove knowledge of y s.t.
///   z = y + (r_sum)*c
/// and that com_sum := Σ Ci satisfies:
///   ck_top*z = w + (com_sum.ar)*c
///   ck_m3 *z = u + (com_sum.com3)*c
///
/// - here  we use challenge as hash (com_sum,w,u).
/// =========================================================
#[derive(Clone, Debug)]
pub struct ProofOfBalance {
    // transcript
    pub w: Matrix<Poly>,
    pub u: Matrix<Poly>,
    pub z: Matrix<Poly>,

    // (optional) keep challenge public for debugging; verifier recomputes anyway
    pub challenge: Poly,
}

/// Sum a vector of commitments (as matrices) into one commitment matrix.
pub fn sum_commitments(com_vec: &Vec<Matrix<Poly>>) -> Matrix<Poly> {
    assert!(!com_vec.is_empty());
    let mut acc = Matrix::from_vec(vec![Poly::zero(); com_vec[0].row_m]);
    for c in com_vec {
        acc = &acc + c;
    }
    acc
}

fn fs_challenge(
    com_sum: &Matrix<Poly>,
    w: &Matrix<Poly>,
    u: &Matrix<Poly>,
) -> Poly {
    let mut hasher = Sha3_256::new();

    let com_sum_s = serde_json::to_string(com_sum).expect("serialize com_sum");
    let w_s = serde_json::to_string(w).expect("serialize w");
    let u_s = serde_json::to_string(u).expect("serialize u");

    hasher.update(com_sum_s.as_bytes());
    hasher.update(w_s.as_bytes());
    hasher.update(u_s.as_bytes());

    let digest = hasher.finalize();
    let mut coeffs = [Poly_U128::ZERO; DEGREE];
    for i in 0..DEGREE {
        // take 1 bit from digest cyclically
        let b = digest[i % digest.len()];
        let bit = (b >> (i % 8)) & 1;
        coeffs[i] = if bit == 1 { Poly_U128::ONE } else { Poly_U128::ZERO };
    }
    Poly::new(coeffs)
}

/// =========================================================
/// Prover
/// Inputs are GIVEN by caller:
///  - com_vec: commitments to sum
///  - r1_sum: witness randomness for com_sum's ar-part (i.e., sum of r_i)
///  - bdlop: instance (do we need to pass, maybe we can only pass parameters)
////// =========================================================
pub fn gen_proof_of_balance(
    com_vec: &Vec<Matrix<Poly>>,
    r_sum: &Matrix<Poly>,
    bdlop: &ABDLOP,
) -> ProofOfBalance {
    let com_sum = sum_commitments(com_vec);

    // split ck
    let (ck_top, _ck_m1, _ck_m2, ck_m3) = bdlop.ck.slice_into_4(bdlop.ck_binding_height_n);

    loop {
        // y ~ binomial
        let y = Matrix::from_vec(
            (0..bdlop.randomness_vector_dimension_k)
                .map(|_| Poly::random_binomial())
                .collect(),
        );

        let w = &ck_top * &y;
        let u = &ck_m3 * &y;
        let challenge = Poly::random_binomial();
        // trying fiatshamir hashing here instead but obv it shouldnt be here... (com_sum,w,u)
        let challenge = fs_challenge(&com_sum, &w, &u);

        // z = y + r_sum * c
        let cr = r_sum * &challenge;
        let z = &y + &cr;

        // // rejection sampling
        // if Sampler::reject_0(&z, &cr, 27000f64) {
        //     continue;
        // }

        return ProofOfBalance { w, u, z, challenge };
    }
}

/// =========================================================
/// Verifier
/// Public inputs: com_vec, bdlop, and the proof.
/// Verifier recomputes com_sum and the FS challenge from transcript.
/// =========================================================
pub fn verify_proof_of_balance(
    com_vec: &Vec<Matrix<Poly>>,
    bdlop: &ABDLOP,
    proof: &ProofOfBalance,
) -> bool {
    if com_vec.is_empty() {
        return false;
    }

    let com_sum = sum_commitments(com_vec);

    // recompute FS challenge
    let c = fs_challenge(&com_sum, &proof.w, &proof.u);

    if c != proof.challenge {
        return false;
    }

    let (ck_top, _ck_m1, _ck_m2, ck_m3) = bdlop.ck.slice_into_4(bdlop.ck_binding_height_n);

    // split
    let (ori_ar, _ori_com1_m, _ori_com2_sqrtm, ori_com3_m) =
        com_sum.slice_into_4(bdlop.ck_binding_height_n);

    // 1) ck_top * z == w + ar*c
    let lhs1 = &ck_top * &proof.z;
    let rhs1 = &proof.w + &(&ori_ar * &c);
    if lhs1 != rhs1 {
        return false;
    }

    // 2) ck_m3 * z == u + com3*c
    let lhs2 = &ck_m3 * &proof.z;
    let rhs2 = &proof.u + &(&ori_com3_m * &c);
    if lhs2 != rhs2 {
        return false;
    }
    true
}

/// =========================================================
/// Tests
/// =========================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::ABDLOP;

    #[test]
    fn test_proof_of_balance() {

        let (bdlop, _st1, _st2, _et1, _et2) = ABDLOP::new_random_instance();
        // create a few commitments with known randomness, and verify PoB
        let mut r1_sum = Matrix::from_vec(vec![Poly::zero(); bdlop.randomness_vector_dimension_k]);
        // ,Vec<Matrix<Poly>>
        let mut value_sum  = Poly::zero();
        let mut cm_vec: (Vec<Matrix<Poly>>) = (0..15).into_iter().map(|_item| {
            let value =  Poly::random_integer();
            let m_vec = bdlop.prepare_qpadl_message(value.clone());
            let (cm1, r1) = bdlop.commit(&m_vec);
            r1_sum = &r1_sum + &r1;
            value_sum = &value_sum + &value;
            (cm1)
        }
        ).collect();
        // we need to zero the sum for balance..
        let value = value_sum.neg();
        let m_vec = bdlop.prepare_qpadl_message(value.clone());
        let (cm1, r1) = bdlop.commit(&m_vec);
        r1_sum = &r1_sum + &r1;
        cm_vec.push(cm1);
        let proof = gen_proof_of_balance(&cm_vec, &r1_sum, &bdlop);
        let res = verify_proof_of_balance(&cm_vec, &bdlop, &proof);
        assert!(res);
    }
}
