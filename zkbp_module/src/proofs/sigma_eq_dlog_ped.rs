/*
    This file is addition to Curv library
    Copyright 2024 by GTAR-JPMorganChase
*/

use serde::{Deserialize, Serialize};
use crate::cryptographic_primitives::hashing::{Digest, DigestExt};
use crate::elliptic::curves::{Curve, Point, Scalar};
use crate::marker::HashChoice;
use super::ProofError;

// Proof implemented from https://www.iacr.org/archive/eurocrypt2000/1807/18070437-new.pdf (2.2)

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DLogEqProofPed<E: Curve, H: Digest + Clone> {
    pub cm1: Point<E>,
    pub cm2: Point<E>,
    pub cm3: Point<E>,
    pub token: Point<E>,
    pub r1: Scalar<E>,
    pub r2: Scalar<E>,
    pub challenge : Scalar<E>,
    pub challenge_response_D: Scalar<E>,
    pub challenge_response_D1: Scalar<E>,
    pub challenge_response_D2: Scalar<E>,
    #[serde(skip)]
    pub hash_choice: HashChoice<H>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DLogEqProofPedMulWitness<E: Curve> {
    pub chalRspDg: Point<E>,
    pub chalRspD1h: Point<E>,
    pub challengecm2: Point<E>,
    pub chalRspDcm2: Point<E>,
    pub chalRspD2h: Point<E>,
    pub challengecm3: Point<E>
}

impl<E: Curve, H: Digest + Clone> DLogEqProofPed<E, H> {
    pub fn prove(x: &Scalar<E>, g_1: &Point<E>, h: &Point<E>, pk: &Point<E>) -> DLogEqProofPed<E, H> {
        //k
        let r1 = Scalar::random();
        let cm1 = g_1 * (x * x) + h * &r1;  //E
        let token = pk * &r1;

        let r2 = Scalar::random();
        let r3 = &r1 - &r2 * x;

        let cm2 = g_1 * x + h * &r2; //F
        let cm3 = &cm2 * x + h * &r3;   //E


        // PK(F: g*x + h* r2, E: F*x+h*r3)

        let n1 = Scalar::random();
        let n2 = Scalar::random();
        let omega = Scalar::random();

        let w1 = g_1 * &omega + h * &n1;
        let w2 = &cm2 * &omega + h * &n2;

        let challenge = H::new()
            .chain_point(&w1)
            .chain_point(&w2)
            .result_scalar();

        let challenge_response_D = omega + &challenge * x;
        let challenge_response_D1 = &n1 + &challenge * &r2;
        let challenge_response_D2 = &n2 + &challenge * &r3;

        DLogEqProofPed {
            cm1,
            cm2,
            cm3,
            token,
            r1,
            r2,
            challenge,
            challenge_response_D,
            challenge_response_D1,
            challenge_response_D2,
            hash_choice: HashChoice::new(),
        }
    }

    pub fn verify(proof: &DLogEqProofPed<E, H>, g_1: &Point<E>, h: &Point<E>) -> Result<(), ProofError> {

        let w1 = g_1 * &proof.challenge_response_D + h * &proof.challenge_response_D1 - &proof.cm2 * &proof.challenge;
        let w2 = &proof.cm2 * &proof.challenge_response_D + h * &proof.challenge_response_D2 - &proof.cm3 * &proof.challenge;

        let challenge = H::new()
            .chain_point(&w1)
            .chain_point(&w2)
            .result_scalar();

        if (challenge==proof.challenge)
        {
            Ok(())
        } else {
            Err(ProofError)
        }
    }

    pub fn generate_mul_witness(proof: &DLogEqProofPed<E,H>, g: &Point<E>, h: &Point<E>) ->  DLogEqProofPedMulWitness<E>{
        let chalRspDg = &proof.challenge_response_D*g;
        let chalRspD1h = &proof.challenge_response_D1 * h;
        let challengecm2 = &proof.challenge * &proof.cm2;
        let chalRspDcm2 = &proof.challenge_response_D * &proof.cm2;
        let chalRspD2h = &proof.challenge_response_D2 * h;
        let challengecm3 = &proof.challenge * &proof.cm3;
   
        DLogEqProofPedMulWitness{
            chalRspDg,
            chalRspD1h,
            challengecm2,
            chalRspDcm2,
            chalRspD2h,   
            challengecm3
        }
    }
}
