#![allow(non_snake_case)]
// use core::slice::SlicePattern;
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
// use ark_ec::{hashing::{curve_maps::wb::{WBConfig,WBMap}}};
// use ark_ec::hashing::curve_maps::wb::WBMap;
// use crate::elliptic::curves::bn254::WBMap;

use ark_std::UniformRand;
use generic_array::GenericArray;
use p256::elliptic_curve::rand_core;
use serde::Serialize;
use sha2::{Digest, Sha256};
use typenum::False;
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
    use crate::elliptic::curves::traits::ECPoint;
    use crate::{arithmetic::traits::*, BigInt};
    use ark_ec::hashing::map_to_curve_hasher::MapToCurveBasedHasher;
    use ark_ec::short_weierstrass::{Affine, Projective};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ec::{hashing::HashToCurve};
    use ark_ff::field_hashers::DefaultFieldHasher;
    use ark_ff::PrimeField;
    use ark_ff::BigInt as ArkBigInt;
    use serde_bytes::deserialize;
    // use pairing_plus::bls12_381::G1Affine;
    use crate::elliptic::curves::bn254::{Bn254, Bn254Point};
    use ark_bn254::{G1Projective, G2Projective, G2Affine, Fq, G1Affine};
    use ark_ec::hashing::curve_maps::swu::SWUMap;
    use ark_serialize::CanonicalSerialize;
    use std::ops::BitAnd;
    use ark_ff::Field;

    /// Takes uniformly distributed bytes and produces ark_bn254 point with unknown logarithm
    pub fn generate_random_point(bytes: &[u8]) -> Point<Bn254> {
        // let compressed_point_len = 32;
        // let truncated = if bytes.len() > compressed_point_len {
        //     &bytes[0..compressed_point_len]
        // } else {
        //     bytes
        // };
        // if let Ok(point) = Point::from_bytes(&truncated) {
        //     return point;
        // }
        // let bn = BigInt::from_bytes(&truncated);
        // let two = BigInt::from(2);
        // let bn_times_two = BigInt::mod_mul(&bn, &two, Scalar::<Bn254>::group_order());
        // let bytes = BigInt::to_bytes(&bn_times_two);
        // generate_random_point(&bytes)
        // HashToCurve::<G1Projective>::new(&[1]).unwrap().hash(bytes).unwrap()

        // use sha2_old::Sha256;
        // let hasher = MapToCurveBasedHasher::<Projective<ark_bn254::g1::Config>, DefaultFieldHasher<Sha256>, SWUMap<ark_bn254::g1::Config>>::new(&[1]);
        // hasher.hash(bytes).unwrap()

        let mut buf = [0u8; 64];
        SVDW.map_to_curve_g1_unchecked(<Fq as PrimeField>::from_be_bytes_mod_order(bytes)).serialize_uncompressed(buf.as_mut_slice()).unwrap();
        // Bn254Point::deserialize(buf.as_slice()).unwrap()
        let mut buf_r =buf.as_slice().to_vec();
        buf_r.reverse();
        Point::<Bn254>::from_bytes(&buf_r).unwrap()
    }

    //ref: imeplentation from https://github.com/version513/energon/pull/2/commits/35439875ed4f0e386e1b0c0339497159fe2419ad
    struct SvdW {
        b: Fq,
        z: Fq,
        c1: Fq,
        c2: Fq,
        c3: Fq,
        c4: Fq,
    }
    /// ref: https://github.com/ConsenSys/gnark-crypto/blob/master/ecc/bn254/hash_to_g1.go
    const SVDW: SvdW = SvdW {
        // A = 0
        // B = 3,
        b: Fq::new_unchecked(ArkBigInt::new([
            8797723225643362519,
            2263834496217719225,
            3696305541684646532,
            3035258219084094862,
        ])),
        z: Fq::new_unchecked(ArkBigInt::new([
            15230403791020821917,
            754611498739239741,
            7381016538464732716,
            1011752739694698287,
        ])),
        c1: Fq::new_unchecked(ArkBigInt::new([
            1248766071674976557,
            10548065924188627562,
            16242874202584236114,
            560012691975822483,
        ])),
        c2: Fq::new_unchecked(ArkBigInt::new([
            12997850613838968789,
            14304628359724097447,
            2950087706404981016,
            1237622763554136189,
        ])),
        c3: Fq::new_unchecked(ArkBigInt::new([
            8972444824031832946,
            5898165201680709844,
            10690697896010808308,
            824354360198587078,
        ])),
        c4: Fq::new_unchecked(ArkBigInt ::new([
            12077013577332951089,
            1872782865047492001,
            13514471836495169457,
            415649166299893576,
        ])),
    };

    impl SvdW{
        /// A straight-line implementation of the Shallue and van de Woestijne method,
        /// ref: https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-shallue-van-de-woestijne-met
        fn map_to_curve_g1_unchecked(&self, u: Fq) -> G1Affine {

            let tv1 = u * u;
            let tv1 = tv1 * self.c1;
            let tv2 = Fq::ONE + tv1;
            let tv1 = Fq::ONE - tv1;
            let tv3 = tv1 * tv2;
            let tv3 = tv3.inverse().expect("should not fail");
            let tv4 = u * tv1;
            let tv4 = tv4 * tv3;
            let tv4 = tv4 * self.c3;
            let x1 = self.c2 - tv4;

            // step 11: gx1 = x1^2
            // step 12: gx1 = gx1 + A
            // step 13: gx1 = gx1 * x1
            //              = x1^3
            let gx1 = x1 * x1 * x1;
            let gx1 = gx1 + self.b;
            let e1 = gx1.legendre().is_qr();
            let x2 = self.c2 + tv4;

            // step 17: gx2 = x2^2
            // step 18: gx2 = gx2 + A
            // step 19: gx2 = gx2 * x2
            //              = x2^3
            let gx2 = x2 * x2 * x2;
            let gx2 = gx2 + self.b;

            // step 21:  e2 = is_square(gx2) AND NOT e1
            let e2 = gx2.legendre().is_qr() & !e1;
            let x3 = tv2 * tv2;
            let x3 = x3 * tv3;
            let x3 = x3 * x3;
            let x3 = x3 * self.c4;
            let x3 = x3 + self.z;

            // step 27: x = CMOV(x3, x1, e1)   # x = x1 if gx1 is square, else x = x3
            let mut x = if e1 { x1 } else { x3 };

            // step 28: x = CMOV(x, x2, e2)    # x = x2 if gx2 is square and gx1 is not
            if e2 {
                x = x2
            };

            // step 29:  gx = x^2
            // step 30:  gx = gx + A
            // step 31:  gx = gx * x
            //              = x^3
            let gx = x * x * x;
            let gx = gx + self.b;

            // step 33: y = sqrt(gx)
            let mut y = gx.sqrt().expect("should not fail");

            // step 34:  e3 = sgn0(u) == sgn0(y)
            // step 35:   y = CMOV(-y, y, e3)
            let mut u_b = Vec::with_capacity(32);
            let mut y_b = Vec::with_capacity(32);
            <Fq as CanonicalSerialize>::serialize_compressed(&u, &mut u_b).expect("should not fail");
            <Fq as CanonicalSerialize>::serialize_compressed(&y, &mut y_b).expect("should not fail");

            // select correct sign of y
            y = if u_b[0].bitand(1) == y_b[0].bitand(1) {
                y
            } else {
                -y
            };
            ark_bn254::G1Affine::new(x, y)
        }
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
        // this bigint is bigint from Ark Package.
        let bytes = self.fe.into_bigint().to_bytes_be(); // Convert to bytes
        BigInt::from_bytes(&bytes)
    }

    fn serialize(&self) -> GenericArray<u8, Self::ScalarLength> {
        // let mut serialized_point: Vec<u8> = Vec::new();
        // self.fe.serialize_compressed(&mut serialized_point).unwrap();
        // GenericArray::clone_from_slice(&serialized_point)
        GenericArray::clone_from_slice(&self.fe.into_bigint().to_bytes_be())
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializationError> {
//         println!("Deserialized byte");
//         println!("original: {:?}",G1Affine::generator());
//         println!("negation: {:?}",&self::GENERATOR.neg_point());
//         println!("adding negation:{:?}",self::GENERATOR.add_point(&self::GENERATOR.neg_point()));
//         println!("Ordeer: {}",Self::group_order());
        if bytes.len() != 64 && bytes.len() != 32 {
            return Err(DeserializationError);
        }
        if bytes.len() == 32 {
            // SK::deserialize_compressed(bytes).map_err(|_| DeserializationError)?
            // SK::from_be_bytes_mod_order(bytes)
            // return Ok(Bn254Scalar {
            //     purpose: "deserialized Scalar",
            //     fe: SK::from_be_bytes_mod_order(bytes)})
            // let scalar = arkBigInt::<4>::deserialize_uncompressed_unchecked(mybytes.as_slice()).unwrap();
            // let mut mybytes = Vec::from(&bytes[..]);
            // mybytes.reverse();
            // let scalar = SK::from_le_bytes_mod_order(&mybytes[..]);
            let scalar = SK::from_be_bytes_mod_order(&bytes[..]);

           // println!("{:?}", scalar);
            return Ok(Bn254Scalar {
                purpose: "deserialized Scalar",
                fe: scalar.into()})
            // return Ok(Bn254Scalar::from_bigint(&BigInt::from_bytes(&bytes)))
        }
        let sk =
            {
                assert!(false);
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
        let x = Bn254Scalar::from_bigint(_x);
        let y = Bn254Scalar::from_bigint(_y);
        let point = ark_bn254::G1Affine::new(Fq::from(x.fe.into_bigint()), Fq::from(y.fe.into_bigint()));
        Ok(Bn254Point {
            purpose: "point_from_coords",
            ge: point.into(),
        })
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
        // assert!(false);
        let mut serialized_point: Vec<u8> = Vec::new();
        self.ge.serialize_compressed(&mut serialized_point).unwrap();
        let ser = GenericArray::clone_from_slice(&serialized_point);
        let mut ser_be = ser.clone();
        ser_be.reverse();
        ser_be
    }

    fn serialize_uncompressed(&self) -> GenericArray<u8, Self::UncompressedPointLength> {
        let mut serialized_point: Vec<u8> = Vec::new();
        self.ge.serialize_uncompressed(&mut serialized_point).unwrap();
        let length = serialized_point.len();
        serialized_point[length-1] = serialized_point[length-1] & 0x7f; //Workaround for serialization inconsistency.
        let ser = GenericArray::clone_from_slice(&serialized_point);
        let mut ser_be = ser.clone();
        ser_be.reverse();
        ser_be
    }

    fn deserialize(bytes: &[u8]) -> Result<Bn254Point, DeserializationError> {
        if bytes.len() != 64 && bytes.len() != 32 {
            return Err(DeserializationError);
        }

        let mut bytes_le: Vec<u8> = bytes.to_vec(); // Convert the slice to a mutable Vec<u8>
        bytes_le.reverse(); // Reverse the Vec in-place

        let pk = if bytes.len() == 32 {
            // Attempt to deserialize as a compressed point and handle potential errors
            PK::deserialize_compressed(&*bytes_le).map_err(|_| DeserializationError)?
        } else {
            // Attempt to deserialize as an uncompressed point and handle potential errors
            PK::deserialize_uncompressed(&*bytes_le).map_err(|_| DeserializationError)?
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