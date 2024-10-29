/*
   This file is addition to Curv library
    Copyright 2024 by GTAR-JPMorganChase
*/

//  Prover									Verifier
//  ======                                  ========
//  selects v and r for commitments
//  CM = vG + rH; CMTok = rPK				learns CM, CMTok
//  selects random u1, u2
//  T1 = u1G + u2H
//  T2 = u2PK
//  c = HASH(G, H, T1, T2, PK, CM, CMTok)
//  s1 = u1 + c * v
//  s2 = u2 + c * r
//
//  T1, T2, c, s1, s2 ----------------->
//                                          c ?= HASH(G, H, T1, T2, PK, CM, CMTok)
//                                          s1G + s2H ?= T1 + cCM
//                                          s2PK ?= T2 + cCMTok
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
pub struct ConsistencyProof<E: Curve, H: Digest + Clone> {
    pub t1: Point<E>,
    pub t2: Point<E>,
    pub s1: Scalar<E>,
    pub s2: Scalar<E>,
    pub challenge : Scalar<E>,
    #[serde(skip)]
    pub hash_choice: HashChoice<H>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ConsistencyProofMulWitness<E: Curve> {
    pub chalcm: Point<E>,
    pub chaltk: Point<E>,
    pub s2pubkey: Point<E>,
    pub s1g: Point<E>,
    pub s2h: Point<E>
}

impl<E: Curve, H: Digest + Clone> ConsistencyProof<E, H> {

    pub fn prove(val: &Scalar<E>, r: &Scalar<E>, g: &Point<E>, h: &Point<E>, cm_ped: &Point<E>, pubkey: &Point<E>, cmtok: &Point<E>) -> ConsistencyProof<E, H>
    {

        //  CM = vG + rH; CMTok = rPK
        let cm = h * r + g * val;
        if &cm != cm_ped
        {
            assert!(false);
        }

        let u1 = Scalar::random();

        let u2 = Scalar::random();

        if u1 == u2
        {
            assert!(false);
        }

        let t1 = &u1 * g + &u2 * h;
        let t2 = &u2 * pubkey;

        let challenge = H::new()
            .chain_point(g)
            .chain_point(h)
            .chain_point(&t1)
            .chain_point(&t2)
            .chain_point(pubkey)
            .chain_point(cm_ped)
            .chain_point(cmtok)
            .result_scalar();

        let s1 = &u1 + &challenge * val;
        let s2 = &u2 + &challenge * r;

        ConsistencyProof {
            t1,
            t2,
            s1,
            s2,
            challenge,
            hash_choice: HashChoice::new(),
        }
    }

    pub fn verify(proof: &ConsistencyProof<E, H>, g: &Point<E>, h: &Point<E>, cm: &Point<E>, pubkey: &Point<E>, cmtok: &Point<E>) -> Result<(), ProofError> {

        let challenge = H::new()
            .chain_point(g)
            .chain_point(h)
            .chain_point(&proof.t1)
            .chain_point(&proof.t2)
            .chain_point(pubkey)
            .chain_point(cm)
            .chain_point(cmtok)
            .result_scalar();

        let s1g_s2h = &proof.s1 * g + &proof.s2 * h;
        let t1_ccm = &proof.t1  + &challenge * cm;

        let s2pk = &proof.s2 * pubkey;
        let t2_c_cmtok = &proof.t2  + cmtok*&challenge;


        if (s1g_s2h == t1_ccm)&&(s2pk == t2_c_cmtok) && (challenge == proof.challenge)
        {
            Ok(())
        } else {
            Err(ProofError)
        }
    }

    pub fn generate_mul_witness(proof: &ConsistencyProof<E,H>, cm_val: &Scalar<E>, r: &Scalar<E>, g: &Point<E>, h: &Point<E>, pubkey: &Point<E>, tk: &Point<E>) ->  ConsistencyProofMulWitness<E>{
        let cm = h * r + g * cm_val;

        let chalcm = &proof.challenge * cm;
        let chaltk =  tk*&proof.challenge;
        let s2pubkey = &proof.s2 * pubkey;
        let s1g = &proof.s1 * g;
        let s2h = &proof.s2 * h;
   
        ConsistencyProofMulWitness{
            chalcm,
            chaltk,
            s2pubkey,
            s1g,   
            s2h
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    crate::test_for_all_curves_and_hashes!(test_consistency_proof);

    fn test_consistency_proof<E: Curve, H: Digest + Clone>() {
        let r = Scalar::random();
        let g = Point::<E>::generator().to_point();
        let h = Point::<E>::base_point2();
        let v = Scalar::<E>::from(1000);
        let pubkey = h * Scalar::<E>::random();
        let cm_ped = &g * &v + h * &r;
        let cmtok = &pubkey * &r*Scalar::<E>::from(1);
        let consistency_proof = ConsistencyProof::<E, H>::prove(&v, &r, &g, &h, &cm_ped, &pubkey, &cmtok);

        assert!(ConsistencyProof::verify(&consistency_proof, &g, &h, &cm_ped, &pubkey, &cmtok).is_ok());
    }
}
