use crate::commitment::ABDLOP;
use crate::matrix::Matrix;
use crate::polynomial::Poly;

///  ABDLOP "proof of opening"
#[derive(Clone, Debug)]
pub struct ProofOfOpening {
    pub w: Matrix<Poly>,
    pub y1: Matrix<Poly>,
    pub y2: Matrix<Poly>,
    pub challenge: Poly,
    pub z1: Matrix<Poly>,
    pub z2: Matrix<Poly>,
    pub cm_top: Matrix<Poly>, //is it already in the input?
}
/// - commit_full(m_vec, r1) -> (cm_proof, r_proof)
/// - zkp_abdlop_initial_commit() -> (w,y1,y2)
/// - challenge = get_challenge()
/// - z1 = y1 + r1*c
/// - z2 = y2 + r_proof*c
pub fn gen_proof_of_opening(
    abdlop: &ABDLOP,
    r: &Matrix<Poly>,
    s: &Matrix<Poly>,
    cm_abdlop: &Matrix<Poly>
) -> ProofOfOpening {
    // split abdlop ck
    // commitment to same message using shared randomness r1
    //let (cm_proof, r_proof) = abdlop.commit_full(m_vec, r1);
    let (cm_top, _) = cm_abdlop.slice_into_2(abdlop.ck_binding_height_n);

    // ZK opening protocol (honest transcript)
    let (w, y1, y2) = abdlop.zkp_abdlop_initial_commit();
    let challenge = ABDLOP::get_challenge();

    let z1 = &y1 + &(r * challenge.clone());
    let z2 = &y2 + &(s * challenge.clone());

    //  rejection sampling  here or hint-mlwe.

    // We store cm_top now, not necessarilly needed?.
    ProofOfOpening {
        w,
        y1,
        y2,
        challenge,
        z1,
        z2,
        cm_top,
    }
}

/// Verify the ABDLOP proof-of-opening equation:
///    (ck_atjai * z1) + (ck_top * z2)  ==  w + (cm_top * c)
pub fn verify_proof_of_opening(abdlop: &ABDLOP, proof: &ProofOfOpening) -> bool {
    let (ck_top, _) = abdlop.ck.slice_into_2(abdlop.ck_binding_height_n);

    let lhs = (&abdlop.ck_atjai * &proof.z1) + (&ck_top * &proof.z2);
    // println!("{}",proof.challenge);
    let rhs = &proof.w + &(&proof.cm_top * proof.challenge.clone());

    lhs == rhs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::ABDLOP;
    use crate::polynomial::Poly;

    #[test]
    fn test_abdlop_proof_of_opening() {
        let (bdlop, _st1, _st2, _et1, _et2) = ABDLOP::new_random_instance();
        let message = Poly::random();
        let m_vec = bdlop.prepare_qpadl_message(message.clone());
        let (_cm1, r1) = bdlop.commit(&m_vec);

        let (abdlop, _, _, _, _) = ABDLOP::new_random_instance();
        let (cm_proof, s) = abdlop.commit_full(&m_vec, &r1);
        let proof = gen_proof_of_opening(&abdlop, &r1, &s, &cm_proof);
        assert!(verify_proof_of_opening(&abdlop, &proof));
    }
    #[test]
    fn test_abdlop_proof_of_opening_false() {
        let (bdlop, _st1, _st2, _et1, _et2) = ABDLOP::new_random_instance();
        let message = Poly::random();
        let m_vec = bdlop.prepare_qpadl_message(message.clone());
        let (_cm1, r1) = bdlop.commit(&m_vec);

        let (abdlop, _, _, _, _) = ABDLOP::new_random_instance();
        let (cm_proof, s) = abdlop.commit_full(&m_vec, &r1);
        let message = Poly::random();
        let (_cm1, r2) = bdlop.commit(&m_vec);
        let proof = gen_proof_of_opening(&abdlop, &r2, &s, &cm_proof);
        assert!(!verify_proof_of_opening(&abdlop, &proof));
    }
}
