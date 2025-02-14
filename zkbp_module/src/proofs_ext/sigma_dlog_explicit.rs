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
pub struct DLogProofExplicit<E: Curve, H: Digest + Clone> {
    pub pk: Point<E>,
    pub pk_t_rand_commitment: Point<E>,
    pub challenge_response: Scalar<E>,
    #[serde(skip)]
    pub hash_choice: HashChoice<H>,
}


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DLogProofExplicitMulWitness<E: Curve> {
    pub chalrsph2r: Point<E>, //g ^ s
    pub challengepk: Point<E> //pk ^ c
}

impl<E: Curve, H: Digest + Clone> DLogProofExplicit<E, H> {
    pub fn prove(sk: &Scalar<E>, generator: &Point<E>) -> DLogProofExplicit<E, H> {
        //let generator = Point::<E>::generator();
        
        let sk_t_rand_commitment = Scalar::random();
        let pk_t_rand_commitment = generator * &sk_t_rand_commitment;

        let pk = generator * sk;

        let challenge = H::new()
            .chain_point(&pk_t_rand_commitment)
            .chain_point(generator)
            .chain_point(&pk)
            .result_scalar();

        let challenge_mul_sk = challenge * sk;
        let challenge_response = &sk_t_rand_commitment - &challenge_mul_sk;
        
        DLogProofExplicit {
            pk,
            pk_t_rand_commitment,
            challenge_response,
            hash_choice: HashChoice::new(),
        }
    }

    pub fn verify(proof: &DLogProofExplicit<E, H>, generator: &Point<E>,  y: &Point<E>) -> Result<(), ProofError> {
       // let generator = Point::<E>::generator();

        let challenge = H::new()
            .chain_point(&proof.pk_t_rand_commitment)
            .chain_point(generator)
            .chain_point(&proof.pk)
            .result_scalar();

        let pk_challenge = &proof.pk * &challenge;

        let pk_verifier = generator * &proof.challenge_response + pk_challenge;

        if pk_verifier == proof.pk_t_rand_commitment && &proof.pk == y{
            Ok(())
        } else {
            Err(ProofError)
        }
    }

    pub fn generate_mul_witness(proof: &DLogProofExplicit<E,H>, generator: &Point<E>) ->  DLogProofExplicitMulWitness<E>{
        let challenge = H::new()
        .chain_point(&proof.pk_t_rand_commitment)
        .chain_point(generator)
        .chain_point(&proof.pk)
        .result_scalar();

        let chalrsph2r =  generator * &proof.challenge_response; //g ^ s
        let challengepk = &proof.pk * &challenge; //pk ^ c
   
        DLogProofExplicitMulWitness{
            chalrsph2r,
            challengepk
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::test_for_all_curves_and_hashes!(test_dlog_explicit_proof);
    fn test_dlog_explicit_proof<E: Curve, H: Digest + Clone>() {
        let witness = Scalar::random();
        let generator = Point::<E>::generator();
        //let generator2 = Point::<E>::generator().to_point();
        //let generator3 = Point::<E>::base_point2();
        let y = generator * &witness;
        let dlog_proof = DLogProofExplicit::<E, H>::prove(&witness,&generator);
        assert!(DLogProofExplicit::verify(&dlog_proof,&generator,&y).is_ok());
    }
}
