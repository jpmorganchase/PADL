#![allow(non_snake_case)]
/*
    This file is extending Curv library  (https://github.com/KZen-networks/curv)
     2024 GTAR
*/
use std::cmp::min;
use std::convert::TryInto;
use std::io::Read;
use std::ptr;
use std::sync::atomic;
use ark_bn254;
use ark_std::rand::Rng;
use ark_std::rand; // Random number generator
use rand_core::OsRng;
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::{Field, BigInteger, PrimeField,BigInt as arkBigInt};
use ark_bn254::{G1Projective, G1Affine, G2Projective, G2Affine, Fq};
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize, SerializationError};

use ark_std::UniformRand;
use generic_array::GenericArray;
use p256::elliptic_curve::rand_core;
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::arithmetic::*;
use crate::elliptic::curves::traits::*;

use super::traits::{ECPoint, ECScalar};

lazy_static::lazy_static! {
    static ref GROUP_ORDER: BigInt = BigInt::from_bytes(&SK::MODULUS.to_bytes_be());

static ref GENERATOR: Bn254Point  ={
        let point1 = G1Projective::generator().into_affine();
        let mut serialized_point: Vec<u8> = Vec::new();
        point1.serialize_compressed(&mut serialized_point).unwrap();
        // Print the serialized point as bytes

        // Construct the point structure
        Bn254Point {
            purpose: "base_point",
            ge: point1.into(),
        }
    };

    static ref BASE_POINT2: Bn254Point = {
        // Generate the base point and double it
        let scalar = SK::from(2); // Scalar represented as a field element
        let g1_gen = G1Projective::generator().into_affine();
        let result_point = g1_gen.mul_bigint(scalar.into_bigint()).into_affine();
        let point2 = result_point;

        // Serialize the point into a vector of bytes (compressed)
        let mut serialized_point: Vec<u8> = Vec::new();
        point2.serialize_compressed(&mut serialized_point).unwrap();
        // Construct the point structure
        Bn254Point {
            purpose: "base_point2",
            ge: point2.into(),
        }
    };
}
pub type SK = ark_bn254::Fr;
pub type PK = G1Affine;


pub mod hash_to_curve {
    use crate::elliptic::curves::wrappers::{Point, Scalar};
    use crate::{arithmetic::traits::*, BigInt};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::PrimeField;
    use crate::elliptic::curves::bn254::{Bn254, Bn254Point};
    use ark_bn254::{G1Projective, G1Affine, G2Projective, G2Affine, Fq};


    /// Takes uniformly distributed bytes and produces ark_bn254 point with unknown logarithm
    pub fn generate_random_point(bytes: &[u8]) -> Point<Bn254> {
        let compressed_point_len = 32;
        let truncated = if bytes.len() > compressed_point_len {
            &bytes[0..compressed_point_len]
        } else {
            bytes
        };
        if let Ok(point) = Point::from_bytes(&truncated) {
            return point;
        }
        let bn = BigInt::from_bytes(&truncated);
        let two = BigInt::from(2);
        let bn_times_two = BigInt::mod_mul(&bn, &two, Scalar::<Bn254>::group_order());
        let bytes = BigInt::to_bytes(&bn_times_two);
        generate_random_point(&bytes)
    }

    #[cfg(test)]
    mod tests {
        use super::generate_random_point;
        use sha2::Sha512;
        use crate::elliptic::curves::traits::*;
        use crate::arithmetic::Converter;
        use crate::cryptographic_primitives::hashing::{Digest, DigestExt};
        use crate::BigInt;

        #[test]
        fn generates_point() {
            // Just prove that recursion terminates (for this input..)
            let _ = crate::elliptic::curves::bn254::hash_to_curve::generate_random_point(&[1u8; 32]);
        }

        #[test]
        fn generates_different_points() {
            let label = BigInt::from(1);
            let hash = Sha512::new().chain_bigint(&label).result_bigint();
            let point1 = generate_random_point(&Converter::to_bytes(&hash));
            let point2 = crate::elliptic::curves::bn254::hash_to_curve::generate_random_point(&[3u8; 32]);
            assert_ne!(point1, point2)
        }
    }
}
/// ARK BN254 curve implementation based on ARK BN library
///
/// ## Implementation notes
/// * x coordinate
///
///   Underlying library intentionally doesn't expose x coordinate of curve point, therefore
///   `.x_coord()`, `.coords()` methods always return `None`, `from_coords()` constructor always
///   returns `Err(NotOnCurve)`
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Bn254 {}
#[derive(Clone, Debug)]
pub struct Bn254Scalar {
    #[allow(dead_code)]
    purpose: &'static str,
    fe: SK,
}
#[derive(Clone, Debug, Copy)]
pub struct Bn254Point {
    #[allow(dead_code)]
    purpose: &'static str,
    ge: PK,
}
pub type GE = Bn254Point;
pub type FE = Bn254Scalar;

impl Curve for Bn254 {
    type Point = GE;
    type Scalar = FE;

    const CURVE_NAME: &'static str = "bn254";
}

impl ECScalar for Bn254Scalar {
    type Underlying = SK;
    type ScalarLength = typenum::U32;

    fn random() -> Bn254Scalar {

        let mut rng = OsRng;
        let random_scalar = SK::rand(&mut rng);
        Bn254Scalar {
            purpose: "random scalar",
            fe: *Zeroizing::new(random_scalar)
        }
    }

    fn zero() -> Bn254Scalar {
        Bn254Scalar {
            purpose: "zero",
            fe: SK::zero().into(),
        }
    }

    fn from_bigint(n: &BigInt) -> Bn254Scalar {
        let n = n.modulus(Self::group_order());
        let bytes = n.to_bytes();
        // Convert `BigUint` to `ark_ff::BigInt<N>`
        let ark_big_int = SK::from_be_bytes_mod_order(&bytes);

        Bn254Scalar {
            purpose: "from_bigint",
            fe: ark_big_int
        }
    }

    fn to_bigint(&self) -> BigInt {
        let bytes = self.fe.into_bigint().to_bytes_be(); // Convert to bytes
        BigInt::from_bytes(&bytes)
    }

    fn serialize(&self) -> GenericArray<u8, Self::ScalarLength> {
        let mut serialized_point: Vec<u8> = Vec::new();
        self.fe.serialize_compressed(&mut serialized_point).unwrap();
        GenericArray::clone_from_slice(&serialized_point)
        //GenericArray::from(self.fe.into_bigint().to_bytes_le())
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializationError> {
        if bytes.len() != 64 && bytes.len() != 32 {
            return Err(DeserializationError);
        }
        let sk = if bytes.len() == 32 {
            // Attempt to deserialize as a compressed point and handle potential errors
            SK::deserialize_compressed(bytes).map_err(|_| DeserializationError)?
        } else {
            // Attempt to deserialize as an uncompressed point and handle potential errors
            SK::deserialize_uncompressed(bytes).map_err(|_| DeserializationError)?
        };
        Ok(Bn254Scalar {
            purpose: "deserialized Scalar",
            fe: sk,
        })
    }


    fn add(&self, other: &Self) -> Bn254Scalar {
        Bn254Scalar {
            purpose: "add",
            fe: (self.fe + other.fe).into(),
        }
    }

    fn mul(&self, other: &Self) -> Bn254Scalar {
        Bn254Scalar {
            purpose: "mul",
            fe: (self.fe * other.fe).into(),
        }
    }

    fn sub(&self, other: &Self) -> Bn254Scalar {
        Bn254Scalar {
            purpose: "sub",
            fe: (self.fe - other.fe).into(),
        }
    }

    fn neg(&self) -> Self {
        Bn254Scalar {
            purpose: "neg",
            fe: (-self.fe).into(),
        }
    }

    fn invert(&self) -> Option<Bn254Scalar> {
        Some(Bn254Scalar {
            purpose: "invert",
            fe: Option::<SK>::from(self.fe.inverse())?.into(),
        })
    }

    fn add_assign(&mut self, other: &Self) {
        self.fe += other.fe;
    }
    fn mul_assign(&mut self, other: &Self) {
        self.fe *= other.fe;
    }
    fn sub_assign(&mut self, other: &Self) {
        self.fe -= other.fe;
    }

    fn group_order() -> &'static BigInt {
        &GROUP_ORDER
    }

    fn underlying_ref(&self) -> &Self::Underlying {
        &self.fe
    }
    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.fe
    }
    fn from_underlying(fe: Self::Underlying) -> Bn254Scalar {
        Bn254Scalar {
            purpose: "from_underlying",
            fe: fe.into(),
        }
    }
}

impl PartialEq for Bn254Scalar {
    fn eq(&self, other: &Bn254Scalar) -> bool {
        self.fe == other.fe
    }
}

impl ECPoint for Bn254Point {
    type Scalar = Bn254Scalar;
    type Underlying = PK;

    type CompressedPointLength = typenum::U32;
    type UncompressedPointLength = typenum::U64;

    fn zero() -> Bn254Point {
        Bn254Point {
            purpose: "zero",
            ge: PK::zero().into(),
        }
    }

    fn is_zero(&self) -> bool {
        self.ge.is_zero()
    }

    fn generator() -> &'static Bn254Point {
        &GENERATOR
    }

    fn base_point2() -> &'static Bn254Point {
        &BASE_POINT2
    }

    fn from_coords(_x: &BigInt, _y: &BigInt) -> Result<Bn254Point, NotOnCurve> {
        unimplemented!()
        // Underlying library intentionally hides x coordinate. There's no way to match if `x`
        // correspond to given `y`.
        // Err(NotOnCurve)
    }

    fn x_coord(&self) -> Option<BigInt> {
        Some(BigInt::from_bytes(&self.ge.x.into_bigint().to_bytes_be()))
    }

    fn y_coord(&self) -> Option<BigInt> {
        Some(BigInt::from_bytes(&self.ge.y.into_bigint().to_bytes_be()))
        }

    fn coords(&self) -> Option<PointCoords> {
        None
    }

    fn serialize_compressed(&self) -> GenericArray<u8, Self::CompressedPointLength> {
        let mut serialized_point: Vec<u8> = Vec::new();
        self.ge.serialize_compressed(&mut serialized_point).unwrap();
        GenericArray::clone_from_slice(&serialized_point)
    }

    fn serialize_uncompressed(&self) -> GenericArray<u8, Self::UncompressedPointLength> {
        let mut serialized_point: Vec<u8> = Vec::new();
        self.ge.serialize_uncompressed(&mut serialized_point).unwrap();
        GenericArray::clone_from_slice(&serialized_point)
    }

    fn deserialize(bytes: &[u8]) -> Result<Bn254Point, DeserializationError> {
        if bytes.len() != 64 && bytes.len() != 32 {
            return Err(DeserializationError);
        }
        let pk = if bytes.len() == 32 {
            // Attempt to deserialize as a compressed point and handle potential errors
            PK::deserialize_compressed(bytes).map_err(|_| DeserializationError)?
        } else {
            // Attempt to deserialize as an uncompressed point and handle potential errors
            PK::deserialize_uncompressed(bytes).map_err(|_| DeserializationError)?
        };
        Ok(Bn254Point {
            purpose: "deserialized point",
            ge: pk,
        })
    }
    fn check_point_order_equals_group_order(&self) -> bool {
        !self.is_zero()
    }

    fn scalar_mul(&self, fe: &Self::Scalar) -> Bn254Point {
        Bn254Point {
            purpose: "scalar_mul",
            ge: (self.ge * fe.fe).into(),
        }
    }

    fn add_point(&self, other: &Self) -> Bn254Point {
        Bn254Point {
            purpose: "add_point",
            ge: (self.ge + other.ge).into(),
        }
    }

    fn sub_point(&self, other: &Self) -> Bn254Point {
        Bn254Point {
            purpose: "sub_point",
            ge: (self.ge - other.ge).into(),
        }
    }

    fn neg_point(&self) -> Bn254Point {
        Bn254Point {
            purpose: "neg_point",
            ge: (-self.ge).into(),
        }
    }

    fn scalar_mul_assign(&mut self, scalar: &Self::Scalar) {
        self.ge=(self.ge * scalar.fe).into()
    }
    fn add_point_assign(&mut self, other: &Self) {
        self.ge=(self.ge + &other.ge).into()
    }
    fn sub_point_assign(&mut self, other: &Self) {
        self.ge= (self.ge - &other.ge).into()
    }
    fn underlying_ref(&self) -> &Self::Underlying {
        &self.ge
    }
    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.ge
    }
    fn from_underlying(ge: Self::Underlying) -> Bn254Point {
        Bn254Point {
            purpose: "from_underlying",
            ge,
        }
    }
}

impl PartialEq for Bn254Point {
    fn eq(&self, other: &Bn254Point) -> bool {
        self.ge == other.ge
    }
}

impl Zeroize for Bn254Point {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(&mut self.ge, PK::default()) };
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}
