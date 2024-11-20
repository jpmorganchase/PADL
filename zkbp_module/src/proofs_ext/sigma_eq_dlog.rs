/*
    This file is addition to Curv library
    Copyright 2024 by GTAR-JPMorganChase
*/

use serde::{Deserialize, Serialize};
use crate::cryptographic_primitives::hashing::{Digest, DigestExt};
use crate::elliptic::curves::{Curve, Point, Scalar};
use crate::marker::HashChoice;
use super::ProofError;

/// This is implementation of Schnorr's identification protocol for elliptic curve groups or a
/// sigma protocol for Proof of knowledge of the discrete log of an Elliptic-curve point:
/// C.P. Schnorr. Efficient Identification and Signatures for Smart Cards. In
/// CRYPTO 1989, Springer (LNCS 435), pages 239–252, 1990.
/// <https://pdfs.semanticscholar.org/8d69/c06d48b618a090dd19185aea7a13def894a5.pdf>.
///
/// The protocol is using Fiat-Shamir Transform: Amos Fiat and Adi Shamir.
/// How to prove yourself: Practical solutions to identification and signature problems.
/// In Advances in Cryptology - CRYPTO ’86, Santa Barbara, California, USA, 1986, Proceedings,
/// pages 186–194, 1986.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DLogEqProof<E: Curve, H: Digest + Clone> {
    pub pk_l: Point<E>,
    pub pk_r: Point<E>,
    pub pk_t_rand_commitment_l: Point<E>,
    pub pk_t_rand_commitment_r: Point<E>,
    pub challenge_response_l: Scalar<E>,
    pub challenge_response_r: Scalar<E>,
    pub challenge : Scalar<E>,
    #[serde(skip)]
    pub hash_choice: HashChoice<H>,
}


impl<E: Curve, H: Digest + Clone> DLogEqProof<E, H> {
    pub fn prove(sk: &Scalar<E>,g_l: &Point<E>, g_r: &Point<E>) -> DLogEqProof<E, H> {
        //k
        let sk_t_rand_commitment = Scalar::random();

        //G^k
        let pk_t_rand_commitment_l = g_l * &sk_t_rand_commitment;
        let pk_t_rand_commitment_r = g_r * &sk_t_rand_commitment;

        //public key
        let pk_l = g_l * sk;
        let pk_r = g_r * sk;

        let challenge = H::new()
            .chain_point(&pk_t_rand_commitment_l)
            .chain_point(&pk_t_rand_commitment_r)
            .chain_point(g_l)
            .chain_point(g_r)
            .chain_point(&pk_l)
            .chain_point(&pk_r)
            .result_scalar();

        let challenge_mul_sk = &challenge * sk;
        let challenge_response_l = &sk_t_rand_commitment - &challenge_mul_sk; //r-c*sk
        let challenge_response_r = &sk_t_rand_commitment - &challenge_mul_sk; //r-c*sk same

        DLogEqProof {
            pk_l,
            pk_r,
            pk_t_rand_commitment_l,
            pk_t_rand_commitment_r,
            challenge_response_l,
            challenge_response_r,
            challenge,
            hash_choice: HashChoice::new(),
        }
    }

    pub fn verify(proof: &DLogEqProof<E, H>, g_l: &Point<E>, g_r: &Point<E>) -> Result<(), ProofError> {

        let challenge = H::new()
            .chain_point(&proof.pk_t_rand_commitment_l)
            .chain_point(&proof.pk_t_rand_commitment_r)
            .chain_point(g_l)
            .chain_point(g_r)
            .chain_point(&proof.pk_l)
            .chain_point(&proof.pk_r)
            .result_scalar();

        let pk_challenge_l = &proof.pk_l * &challenge;
        let pk_challenge_r = &proof.pk_r * &challenge;

        let pk_verifier_l = g_l * &proof.challenge_response_l + pk_challenge_l; // gl^(r-c*sk) * gl^sk^c =? gl^r
        let pk_verifier_r = g_r * &proof.challenge_response_r + pk_challenge_r; // gr^(r-c*sk)*gr^(r-c*sk) =? gr^r

        if (pk_verifier_l == proof.pk_t_rand_commitment_l)&&(pk_verifier_r == proof.pk_t_rand_commitment_r)
            &&(challenge==proof.challenge)&&(g_l!=g_r)
        {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    crate::test_for_all_curves_and_hashes!(test_dlog_eq_proof);

    fn test_dlog_eq_proof<E: Curve, H: Digest + Clone>() {
        let witness = Scalar::random();
        let g_l = Point::<E>::generator().to_point();
        let g_r = Point::<E>::base_point2();
        let dlog_eq_proof = DLogEqProof::<E, H>::prove(&witness, &g_l, g_r);
        assert!(DLogEqProof::verify(&dlog_eq_proof, &g_l, g_r).is_ok());
    }
}
