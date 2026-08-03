
use core::fmt;
use std::mem::{self};
use std::ops::{Mul,Add, Neg, MulAssign};
use std::str::FromStr;
use num_traits::abs;
use rand::Rng;
use rand::rngs::StdRng;
use rand::SeedableRng;
use crate::common::DEGREE;
// use rand::distr::{Bernoulli};
// use rand::distr::Distribution;
// use rand::seq::IndexedRandom;
use crate::{common::*, common_static};
use crate::common_static::*;
use crate::matrix::Matrix;
use num_traits::{Zero,One};
use rug::Integer;
use crate::common_trait::{Norm, SigmaReflect};
use sha3::digest::XofReader;

use std::fmt::Display;

use crate::sampler::SAMPLER;
use crate::sampler_ddll::SAMPLER as SAMPLER_DDLL;
use crate::sampler_ddll::SAMPLER_MEDIUM as SAMPLER_DDLL_MEDIUM;

use rayon::prelude::*;

use ark_ff::Field;
use ark_ff::PrimeField;
use ark_ff::BigInteger;
use serde::{Serialize, Deserialize};

const SEC_PARAM: usize = 256; //k==256 for 128 security.

fn zq_to_u128(a: Zq) -> Option<u128> {
    let big = a.into_bigint();
    if big.num_bits() > 128 {
        return None;
    }
    // Reconstruct u128 from 64-bit limbs
    let limbs = big.as_ref(); // &[u64]
    let mut value = 0u128;
    for (i, limb) in limbs.iter().enumerate() {
        value |= (*limb as u128) << (64 * i);
    }
    Some(value)
}
fn zq_to_i128(a: Zq) -> i128 {
    let zq_u128 = zq_to_u128(a).unwrap();
    //It is still positive
    let zq_i128 = zq_u128 as i128;
    let ret = match zq_i128 > MODULUS_MINUS1_OVER2 as i128{
        true => zq_i128 - MODULUS_I128,
        _ => zq_i128
    };
    ret
}
fn zq_to_i128_custom(a: Zq,custom_mod: i128) -> i128 {
    let zq_u128 = zq_to_u128(a).unwrap();
    //It is still positive
    let zq_i128 = zq_u128 as i128;
    let custom_mod_minus1_over2 = (custom_mod-1)/2;
    let ret = match zq_i128 > custom_mod_minus1_over2 as i128{
        true => zq_i128 - custom_mod,
        _ => zq_i128
    };
    ret
}
pub type Poly_U128 = common_static::Zq;
pub type Poly_I128 = i128;

// struct SharedPtr<T>(*mut T);
// unsafe impl<T> Sync for SharedPtr<T> {}
// unsafe impl<T> Send for SharedPtr<T> {}

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use serde_json;
fn ark_se<S, A: CanonicalSerialize>(a: &A, s: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
      let mut bytes = vec![];
      a.serialize_with_mode(&mut bytes, Compress::Yes).map_err(serde::ser::Error::custom)?;
      s.serialize_bytes(&bytes)
}
fn ark_de<'de, D, A: CanonicalDeserialize>(data: D) -> Result<A, D::Error> where D: serde::de::Deserializer<'de> {
      let s: Vec<u8> = serde::de::Deserialize::deserialize(data)?;
      let a = A::deserialize_with_mode(s.as_slice(), Compress::Yes, Validate::Yes);
      a.map_err(serde::de::Error::custom)
}

// This struct does not derive Copy to avoid copy on function invokacation using Poly as parameter i.e. it is moved.  
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Poly{
    // Coefficient by default should be in NTT domain. Coeffient is as a_0x^0, a_1x^1 s.t. coeff[0] = a_0, ...
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub coeff : [Zq; DEGREE] 
}


impl Display for Poly{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut res_str = format!("i_{}: {};\n",0, self.coeff[0].to_string());
        for i in 1..DEGREE{
            res_str += &(format!("i_{}: {};\n",i, self.coeff[i].to_string()));
            // res_str += &(", ".to_owned() + &self.coeff[i].to_string());
        }
        write!(f, "{}", res_str)
    }
    
    // fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> { todo!() }
}

impl<'a> Mul<Self> for &'a Poly { 
    type Output = Poly;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut temp: [Zq; DEGREE] = [Zq::ZERO; DEGREE];
        // assert_eq!(BASEMUL_DEGREE, 2);

        // //NOTE: Currently only support BASEMUL_DEGREE==2
        // (&mut temp).par_chunks_exact_mut(2)
        // .zip((0..(DEGREE/BASEMUL_DEGREE)).into_par_iter())
        // .for_each(|(temp_item, i)| {
        //     let final_red_amount = self.coeff[i*BASEMUL_DEGREE + 1] * (&rhs.coeff[i*BASEMUL_DEGREE + 1]) * (&BM_TWIDDLE_NON_ZQ[i]); 
        //     let zero_place = self.coeff[i*BASEMUL_DEGREE] * (&rhs.coeff[i*BASEMUL_DEGREE]);
        //     temp_item[0] = zero_place + final_red_amount;
        //     temp_item[1] = (
        //         self.coeff[i*BASEMUL_DEGREE + 1] * (&rhs.coeff[i*BASEMUL_DEGREE]) + (
        //         &self.coeff[i*BASEMUL_DEGREE] * (&rhs.coeff[i*BASEMUL_DEGREE + 1]))
        //     );
        //     // temp[i*BASEMUL_DEGREE] = zero_place + final_red_amount;
        //     // temp[i*BASEMUL_DEGREE + 1] = (
        //     //     self.coeff[i*BASEMUL_DEGREE + 1] * (&rhs.coeff[i*BASEMUL_DEGREE]) + (
        //     //     &self.coeff[i*BASEMUL_DEGREE] * (&rhs.coeff[i*BASEMUL_DEGREE + 1]))
        //     // );
        // });

        for i in 0..(DEGREE/BASEMUL_DEGREE){
            // Perform base multiplication here. We do schoolbook.
            // Then we do polynomial modulo reduction
            let final_red_amount = self.coeff[i*BASEMUL_DEGREE + 1] * (&rhs.coeff[i*BASEMUL_DEGREE + 1]) * (&BM_TWIDDLE_NON_ZQ[i]); 
            let zero_place = self.coeff[i*BASEMUL_DEGREE] * (&rhs.coeff[i*BASEMUL_DEGREE]);
            temp[i*BASEMUL_DEGREE] = zero_place + final_red_amount;
            temp[i*BASEMUL_DEGREE + 1] = (
                self.coeff[i*BASEMUL_DEGREE + 1] * (&rhs.coeff[i*BASEMUL_DEGREE]) + (
                &self.coeff[i*BASEMUL_DEGREE] * (&rhs.coeff[i*BASEMUL_DEGREE + 1]))
            );
        }

        Poly { coeff: temp}
    }
}
impl Mul<Self> for Poly{
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        &self * &rhs
    }
}
//TODO: NOT TESTED:
// impl Mul<u64> for Poly{
//     type Output = Self;
//     fn mul(self, rhs: u64) -> Self::Output {
//         let mut coeff = [0;DEGREE];
//         for i in 0..DEGREE{
//             coeff[i] =  Poly::mont_redc(self.coeff[i] as u128 * Poly::montgomerize(rhs) as u128);
//         }
//         Poly::new(coeff)
//     }
// }

impl MulAssign<Zq> for Poly{
    /// We assume RHS is already modulo.
    fn mul_assign(&mut self, rhs: Zq) {
        for i in 0..DEGREE{
            self.coeff[i] =  self.coeff[i] * (&rhs);
        }
    }
}

impl<'a> Add for &'a Poly { 
    type Output = Poly;

    fn add(self, rhs: Self) -> Self::Output {
        let mut temp: [Zq; DEGREE] = [Zq::ZERO; DEGREE];
        for i in 0..DEGREE{
            temp[i] =(self.coeff[i]) + (&rhs.coeff[i]);
        }
        Poly { coeff: temp}
    }
}
impl Add for Poly { 
    type Output = Poly;

    fn add(self, rhs: Self) -> Self::Output {
        &self + &rhs
    }
}

impl<'a> Neg for &'a Poly{
    type Output = Poly;

    fn neg(self) -> Self::Output {
        let mut ret_coeff = [Zq::zero();DEGREE];
        for i in 0..DEGREE{
            ret_coeff[i] = - self.coeff[i];
        }
        // The ret_coeff is already in NTT form => Directly construct a Poly object without new.
        Poly {coeff: ret_coeff}
    }
}

impl One for Poly{
    fn one() -> Self {
        let mut val = [Zq::zero();DEGREE];
        val[0] = Zq::one();
        Poly::new(val)
    }

    fn is_one(&self) -> bool {
        self.into_canonical_poly().coeff.iter().enumerate().fold(true, |acc, (index,&x)| {
            match index {
                0 => acc && x==i128::one(),
                _ => acc && x==i128::zero()
            }
        })
    }
}

impl Zero for Poly{
    fn zero() -> Self {
        // Poly::new([U128::zero();DEGREE])
        Poly{
            coeff: ([Zq::zero();DEGREE])
        }
    }

    fn is_zero(&self) -> bool {
        self.into_canonical_poly().coeff.iter().fold(true, |acc, &x| acc && x==i128::zero() )
    }
}

impl Norm for Poly{
    fn norm_l2_square(&self) -> i128 { self.into_canonical_poly().l2_norm_sqr() }
    fn norm_l2_int_square(&self) -> rug::Integer { self.into_canonical_poly().l2_norm_sqr_highprecision() }
    fn norm_linf(&self) -> u128 { self.into_canonical_poly().linf_norm() }
}

impl SigmaReflect for Poly{
    /// Formula for sigma_-1 :=  x^-k = - x^{N-k} mod x^N +1
    fn sigma_reflect(&self)-> Self{
        let new_coeff = self.into_canonical_poly().coeff;
        let mut target_coeff =[i128::zero();DEGREE];
        // Formula for sigma_-1 :=  x^-k = - x^{N-k} mod x^N +1
        // IE, 0 stay at 0, all other reflect as i => N-i with coefficient a being -a, ax^k => -a x^{N-k}
        target_coeff[0] = new_coeff[0];
        for i in 1..DEGREE{
            target_coeff[DEGREE-i] = new_coeff[i].wrapping_neg();
            // target_coeff[DEGREE-i] = I128::zero().checked_sub(&new_coeff[i]).unwrap();
        }
        Poly::new(PolyCanon::sign_to_mod(&target_coeff))
    }
}

impl Poly{
    /// Accept non-modulo: This will actually perform modulo.
    pub fn new(arr: [Zq; DEGREE]) -> Self{
        let mut arr_m = arr.clone();
        for idx in 0..arr.len(){
            // This assume q is one bit only one bit less maximum
            // arr_m[idx] = match arr[idx] < **MODULUS_U128 {
            //     true => arr[idx],
            //     _ => {
            //         arr[idx].checked_sub(&MODULUS_U128).unwrap()
            //     }
            // }
            // arr_m[idx] = (arr[idx] % *MODULUS_U128) //always correct
            arr_m[idx] = arr[idx] //We assume it is always correctly modulo.
        }
        Self {
            coeff: arr_m
        }.ntt_fwd()
    }

    pub fn sigma_reflect_i128(i128_arr : &[i128;DEGREE]) -> Poly{
        let new_coeff = i128_arr;
        let mut target_coeff =[i128::zero();DEGREE];
        // Formula for sigma_-1 :=  x^-k = - x^{N-k} mod x^N +1
        // IE, 0 stay at 0, all other reflect as i => N-i with coefficient a being -a, ax^k => -a x^{N-k}
        target_coeff[0] = new_coeff[0];
        for i in 1..DEGREE{
            target_coeff[DEGREE-i] = new_coeff[i].wrapping_neg();
            // target_coeff[DEGREE-i] = I128::zero().checked_sub(&new_coeff[i]).unwrap();
        }
        Poly::new(PolyCanon::sign_to_mod(&target_coeff))
    }

    /// Uniform random polynomial 
    pub fn random() -> Self{
        let mut rand= rand::rng();
        let arr1: Vec<Zq> = (0..DEGREE).map(|_| Zq::from(rand.random_range(0..MODULUS))).collect();
        // let arr1: Vec<U128> = (0..DEGREE).map(|_| (U128::from_u128(rand.random::<u128>()))).collect();
        Poly::new(arr1.try_into().unwrap())
    }

    /// Uniform random polynomial that is at least >=u64 at one of the slots
    pub fn random_u128_guarantee() -> Self{
        let mut rand= rand::rng();
        let arr1: Vec<Zq> = (0..DEGREE).map(|index| {
            if index == 0{
                return  Zq::from(rand.random_range((u64::MAX as u128)+1..MODULUS))
            }
            Zq::from(rand.random_range(0..u64::MAX-1))
        }).collect();
        // let arr1: Vec<U128> = (0..DEGREE).map(|_| (U128::from_u128(rand.random::<u128>()))).collect();
        Poly::new(arr1.try_into().unwrap())
    }

    /// Uniform random polynomial u64 MAX
    pub fn random_u64() -> Self{
        let mut rand= rand::rng();
        let arr1: Vec<Zq> = (0..DEGREE).map(|_| Zq::from(rand.random_range(0..u64::MAX-1))).collect();
        // let arr1: Vec<U128> = (0..DEGREE).map(|_| (U128::from_u128(rand.random::<u128>()))).collect();
        Poly::new(arr1.try_into().unwrap())
    }

    pub fn random_withmax(max_range :u128) -> Self{
        let mut rand= rand::rng();
        let arr1: Vec<Zq> = (0..DEGREE).map(|_| Zq::from(rand.random_range(0..max_range))).collect();
        // let arr1: Vec<U128> = (0..DEGREE).map(|_| (U128::from_u128(rand.random::<u128>()))).collect();
        println!("{:?}a",arr1);
        Poly::new(arr1.try_into().unwrap())
    }

    pub fn random_fixed_negative() -> Self{
        let mut rand= rand::rng();
        let mut arr1: Vec<Zq> = (0..DEGREE).map(|_| Zq::from(0)).collect();
        arr1[0] =  Zq::from(-12345);
        arr1[1] =  Zq::from(-8);
        // let arr1: Vec<U128> = (0..DEGREE).map(|_| (U128::from_u128(rand.random::<u128>()))).collect();
        Poly::new(arr1.try_into().unwrap())
    }

    /// Uniform random polynomial in u64 ranges
    pub fn random_integer() -> Self{
        let mut rand= rand::rng();
        let mut arr1 = [Zq::zero();DEGREE];
        arr1[0] = Zq::from(rand.random::<u64>());
        Poly::new(arr1.try_into().unwrap())
    }

    pub fn from_i128_constant(v: i128) -> Self {
        let mut coeffs = [Zq::zero();DEGREE];
        coeffs[0] = Zq::from(v);
        Poly::new(coeffs)
    }

    /// Build a polynomial from a vector of i128 coefficients (fills from index 0).
    pub fn from_i128_vec(vs: &[i128]) -> Self {
        assert!(
            vs.len() <= DEGREE,
            "from_i128_vec: input length exceeds DEGREE"
        );
        let mut coeffs: Vec<Zq> = vec![Zq::zero(); DEGREE];
        for (i, v) in vs.iter().enumerate() {
            coeffs[i] = Zq::from(*v);
        }
        Poly::new(coeffs.try_into().unwrap())
    }

    pub fn from_u128(v: u128) -> Self {
        let mut coeffs = [Zq::zero();DEGREE];
        coeffs[0] = Zq::from(v);
        Poly::new(coeffs)
    }
    pub fn from_zq(v: Zq) -> Self {
        let mut coeffs = [Zq::zero();DEGREE];
        coeffs[0] = v;
        Poly::new(coeffs)
    }


    pub fn random_negative_integer() -> Self{
        let mut rand= rand::rng();
        let mut arr1 = [Zq::zero();DEGREE];
        arr1[0] = Zq::from(rand.random_range(((MODULUS-1)/2)+1..MODULUS-1 ));
        Poly::new(arr1.try_into().unwrap())
    }

    /// Uniform random polynomial in u64 ranges
    pub fn random_integer_at_slot(slot_i: usize ) -> Self{
            let mut rand= rand::rng();
            let mut arr1 = [Zq::zero();DEGREE];
            arr1[slot_i] = Zq::from_str("1").unwrap();
            // arr1[slot_i] = Zq::from(rand.random::<u64>());
            Poly::new(arr1.try_into().unwrap())
    }

    //Uniform random polynomial
    pub fn random_constant_unmasked() -> Self{
        let mut rand= rand::rng();
        let mut arr1: Vec<Zq> = (0..DEGREE).map(|_| Zq::from(rand.random_range(0..MODULUS))).collect();
        for i in 0..BASEMUL_DEGREE{
            arr1[i]= Zq::zero();
        }
        Poly::new(arr1.try_into().unwrap())
    }

    // //Uniform random polynomial
    pub fn random_discrete_gaussian(std_dev: u32) -> Self{
        // let mut rngoldthread = RngOld();
        match std_dev{
            common_static::SIGMA_SMALL => Poly::new( SAMPLER.sample_discrete_gaussian_icdt_poly(std_dev) ),
            common_static::SIGMA_LARGE => Self::random_discrete_gaussian_u128(std_dev as u128),
            common_static::SIGMA_VERYLARGE_u32 => Self::random_discrete_gaussian_u128(std_dev as u128),
            _ => {
                assert!(false);
                Poly::random()
            }
        }
        // Poly::random_binomial()
    }

    pub fn random_discrete_gaussian_u128(std_dev: u128) -> Self{
        match std_dev{
            SIGMA_LARGE_U128=>SAMPLER_DDLL_MEDIUM.sample_discrete_gaussian_icdt_poly(std_dev),
            SIGMA_VERYLARGE =>SAMPLER_DDLL.sample_discrete_gaussian_icdt_poly(std_dev),
            _ => {
                assert!(false);
                SAMPLER_DDLL.sample_discrete_gaussian_icdt_poly(std_dev)
            }
        }
    }

    ///Sample from -1,0,1 with +-1 5/16 and 0 6/12 probability where it is stable where sigma_-1(c)=c
    pub fn random_binomial() -> Self{
        let mut rand= rand::rng();
        
        // let bern = Bernoulli::new(0.5).unwrap();
        // let arr1: Vec<u64> = (0..DEGREE).map(|_| ( (bern.sample(&mut rand) as i32 + bern.sample(&mut rand) as i32 - bern.sample(&mut rand) as i32 - bern.sample(&mut rand) as i32).rem_euclid(3)) as u64 ).collect();

        let set: Vec<Zq> = vec![Zq::zero(),Zq::zero(),Zq::zero(),Zq::zero(),Zq::zero(),Zq::zero(),Zq::one(),Zq::one(),Zq::one(),Zq::one(),Zq::one(),*NEGATIVE_ONE_ZQ,*NEGATIVE_ONE_ZQ,*NEGATIVE_ONE_ZQ,*NEGATIVE_ONE_ZQ,*NEGATIVE_ONE_ZQ];
        let mut arr1: [Zq;DEGREE] = [Zq::ZERO; DEGREE];
        arr1[0] = set[rand.random_range(0..16)]; //This stay unchanged anyway
        arr1[DEGREE / 2] = Zq::zero();  //This has to be zero else it wont negate nicely
        for i in 1..(DEGREE / 2) {
            arr1[i] = set[rand.random_range(0..16)];
            arr1[DEGREE - i] = -arr1[i];
        }
        let challenge = Poly::new(arr1.try_into().unwrap());
        // println!("sigma_c:{:?}, \nc:{:?}",challenge.sigma_reflect().canonical_repr(),challenge.canonical_repr());
        assert_eq!(challenge.sigma_reflect(), challenge); //Stable under sigma_-1

        challenge
    }
    ///Sample from -1,0,1 with +-1 5/16 and 0 6/12 probability.
    pub fn random_binomial_fs<R: XofReader>(reader: &mut R) -> Self{
        let mut temp: [u8;DEGREE/2] = [0;DEGREE/2];
        reader.read(&mut temp);

        let set: Vec<Zq> = vec![Zq::zero(),Zq::zero(),Zq::zero(),Zq::zero(),Zq::zero(),Zq::zero(),Zq::one(),Zq::one(),Zq::one(),Zq::one(),Zq::one(),*NEGATIVE_ONE_ZQ,*NEGATIVE_ONE_ZQ,*NEGATIVE_ONE_ZQ,*NEGATIVE_ONE_ZQ,*NEGATIVE_ONE_ZQ];
        let mut arr1: Vec<Zq> = (0..DEGREE/2).flat_map(|index| {
            let byte = temp[index];
            let low_nibble = byte & 0x0F;
            let high_nibble = byte >> 4;
            [set[low_nibble as usize], set[high_nibble as usize]]
        }).collect();
        for index in (DEGREE/2+1)..DEGREE {
            arr1[index] = -arr1[DEGREE-index];
        }
        arr1[DEGREE / 2] = Zq::zero(); 
        let challenge = Poly::new(arr1.try_into().unwrap());
        assert_eq!(challenge.sigma_reflect(), challenge); //Stable under sigma_-1

        challenge
    }

    // //Binomial distribution for approximate range proof
    pub fn random_binary_vector(size_of_r_in_ar: usize) -> (Vec<Vec<Zq>>, Vec<Matrix<Poly>>){
        // let mut rand= rand::rng();
        let mut res: Vec<Vec<Zq>> = vec![vec![];DEGREE];  
        let mut res_poly = vec![Matrix::empty();DEGREE];
        // Outer 256 
        (&mut res, &mut res_poly).into_par_iter().enumerate().for_each(|(_par_index, (res_item, res_poly_item)) | {
            let mut rng = StdRng::from_os_rng();

            let mut array_a_i = Vec::with_capacity(size_of_r_in_ar*DEGREE);
            let mut array_b_i = Vec::with_capacity(size_of_r_in_ar*DEGREE);
            for _ in 0..size_of_r_in_ar{
                let sample_a: [bool;DEGREE] = rng.random();
                let sample_b: [bool;DEGREE] = rng.random();
                array_a_i.extend_from_slice(&sample_a);
                array_b_i.extend_from_slice(&sample_b);
            }

            let (arr1, arr2): (Vec<Zq>, Vec<i128>) = (0..size_of_r_in_ar*DEGREE).map(|_index| {
                let a_i: bool = array_a_i[_index];
                let b_i: bool = array_b_i[_index];
                
                // Truth Table
                // a , b, a - b
                // 0,  0 , 0
                // 0,  1 , MODULUS-1
                // 1,  0 , 1
                // 1,  1 , 0
                (LOOK_UP_VEC_ZQ[a_i as usize][b_i as usize], LOOK_UP_VEC_ZQ_I128[a_i as usize][b_i as usize])
                // LOOK_UP_VEC[0][0]
            }).collect();
            // let mut arr_1_poly: Vec<Poly> = Vec::with_capacity(size_of_r_in_ar);
            let mut arr_2_poly: Vec<Poly> = Vec::with_capacity(size_of_r_in_ar);
            for i in 0..size_of_r_in_ar{
                // arr_1_poly.push(Poly::new(arr1[i*DEGREE..(i+1)*DEGREE].try_into().unwrap()));
                arr_2_poly.push(Poly::sigma_reflect_i128(&arr2[i*DEGREE..(i+1)*DEGREE].try_into().unwrap()))
                // arr_2_poly.push(Poly {coeff: [Zq::ZERO;DEGREE]})
            }
            *res_item = arr1;
            *res_poly_item = Matrix::from_vec_transpose(arr_2_poly);
        });

        (res,res_poly)
    }

    pub fn random_binary_vector_fs<R: XofReader>(size_of_r_in_ar: usize, reader: &mut R) -> (Vec<Vec<Zq>>, Vec<Matrix<Poly>>){
        let mut res: Vec<Vec<Zq>> = vec![vec![];SEC_PARAM];  
        let mut res_poly = vec![Matrix::empty();SEC_PARAM];

        debug_assert!(DEGREE%8 == 0); //For fn extract_bits
        debug_assert!(DEGREE >= 256); //TODO: see res,res poly need to have 256 rows. We assume these packed into one polynomial.

        fn extract_bits(input: [u8; SEC_PARAM*DEGREE*2/8]) -> ([bool; SEC_PARAM*DEGREE], [bool; SEC_PARAM*DEGREE]) {
            let mut first_half = [false; SEC_PARAM*DEGREE];
            let mut second_half = [false; SEC_PARAM*DEGREE];
        
            let half_len = SEC_PARAM*DEGREE*2/ 8 / 2;
            // Process the first half of the byte array
            for i in 0..half_len {
                for bit in 0..8 {
                    // Extracts bits from Most Significant (7) to Least Significant (0)
                    first_half[i * 8 + bit] = ((input[i] >> (7 - bit)) & 1) == 1;
                }
            }
            // Process the second half of the byte array
            for i in 0..half_len {
                for bit in 0..8 {
                    second_half[i * 8 + bit] = ((input[i + half_len] >> (7 - bit)) & 1) == 1;
                }
            }
        
            (first_half, second_half)
        }

        let mut array_a_i = Vec::with_capacity(SEC_PARAM*size_of_r_in_ar*DEGREE);
        let mut array_b_i = Vec::with_capacity(SEC_PARAM*size_of_r_in_ar*DEGREE);
        for _ in 0..size_of_r_in_ar{
            let mut temp_buffer :[u8; SEC_PARAM*DEGREE*2/8] = [0; SEC_PARAM*DEGREE*2/8];
            reader.read(&mut temp_buffer);
            let (sample_a, sample_b) = extract_bits(temp_buffer);
            array_a_i.extend_from_slice(&sample_a);
            array_b_i.extend_from_slice(&sample_b);
        }
        let array_a_shared = array_a_i;
        let array_b_shared =array_b_i;

        //The following is the parallel version
        // let temp_buffer_vec : Vec<[u8; SEC_PARAM*DEGREE*2/8]> = (0..size_of_r_in_ar).map(|_index| {
        //     let mut temp_buffer :[u8; SEC_PARAM*DEGREE*2/8] = [0; SEC_PARAM*DEGREE*2/8];
        //     reader.read(&mut temp_buffer);
        //     temp_buffer
        // }).collect();
        // // let sample_ab_vec: Vec<([bool; SEC_PARAM*DEGREE], [bool; SEC_PARAM*DEGREE])>
        // let (sample_a_vec, sample_b_vec): (Vec<[bool; SEC_PARAM*DEGREE]>, Vec<[bool; SEC_PARAM*DEGREE]>) = temp_buffer_vec.into_par_iter().map(|temp_buffer| {
        //     let (sample_a, sample_b) = extract_bits(temp_buffer);
        //     // array_a_i.extend_from_slice(&sample_a);
        //     // array_b_i.extend_from_slice(&sample_b);
        //     (sample_a, sample_b)
        // }).unzip();
        // let array_a_shared = sample_a_vec.as_flattened();
        // let array_b_shared = sample_b_vec.as_flattened();
        // // let (sample_a_vec, sample_b_vec) = sample_ab_vec.iter().unzip();

        // Outer 256 
        (&mut res, &mut res_poly).into_par_iter().enumerate().for_each(|(par_index, (res_item, res_poly_item)) | {

            let (arr1, arr2): (Vec<Zq>, Vec<i128>) = (0..size_of_r_in_ar*DEGREE).map(|index| {
                let a_i: bool = array_a_shared[(par_index*size_of_r_in_ar*DEGREE) + index];
                let b_i: bool = array_b_shared[(par_index*size_of_r_in_ar*DEGREE) + index];
                
                // Truth Table
                // a , b, a - b
                // 0,  0 , 0
                // 0,  1 , MODULUS-1
                // 1,  0 , 1
                // 1,  1 , 0
                (LOOK_UP_VEC_ZQ[a_i as usize][b_i as usize], LOOK_UP_VEC_ZQ_I128[a_i as usize][b_i as usize])
            }).collect();
            // let mut arr_1_poly: Vec<Poly> = Vec::with_capacity(size_of_r_in_ar);
            let mut arr_2_poly: Vec<Poly> = Vec::with_capacity(size_of_r_in_ar);
            for i in 0..size_of_r_in_ar{
                // arr_1_poly.push(Poly::new(arr1[i*DEGREE..(i+1)*DEGREE].try_into().unwrap()));
                arr_2_poly.push(Poly::sigma_reflect_i128(&arr2[i*DEGREE..(i+1)*DEGREE].try_into().unwrap()))
                // arr_2_poly.push(Poly {coeff: [Zq::ZERO;DEGREE]})
            }
            *res_item = arr1;
            *res_poly_item = Matrix::from_vec_transpose(arr_2_poly);
        });

        (res,res_poly)
    }

    pub fn random_binary_vector_fs_split1<R: XofReader>(size_of_r_in_ar: usize, reader: &mut R) -> (Vec<Vec<Zq>>, Vec<Vec<i128>>){
        let mut res: Vec<Vec<Zq>> = vec![vec![];SEC_PARAM];  
        let mut res_poly: Vec<Vec<i128>> = vec![vec![];SEC_PARAM];

        debug_assert!(DEGREE%8 == 0); //For fn extract_bits
        debug_assert!(DEGREE >= 256); //TODO: see res,res poly need to have 256 rows. We assume these packed into one polynomial.

        fn extract_bits(input: [u8; SEC_PARAM*DEGREE*2/8]) -> ([bool; SEC_PARAM*DEGREE], [bool; SEC_PARAM*DEGREE]) {
            let mut first_half = [false; SEC_PARAM*DEGREE];
            let mut second_half = [false; SEC_PARAM*DEGREE];
        
            let half_len = SEC_PARAM*DEGREE*2/ 8 / 2;
            // Process the first half of the byte array
            for i in 0..half_len {
                for bit in 0..8 {
                    // Extracts bits from Most Significant (7) to Least Significant (0)
                    first_half[i * 8 + bit] = ((input[i] >> (7 - bit)) & 1) == 1;
                }
            }
            // Process the second half of the byte array
            for i in 0..half_len {
                for bit in 0..8 {
                    second_half[i * 8 + bit] = ((input[i + half_len] >> (7 - bit)) & 1) == 1;
                }
            }
        
            (first_half, second_half)
        }

        let mut array_a_i = Vec::with_capacity(SEC_PARAM*size_of_r_in_ar*DEGREE);
        let mut array_b_i = Vec::with_capacity(SEC_PARAM*size_of_r_in_ar*DEGREE);
        for _ in 0..size_of_r_in_ar{
            let mut temp_buffer :[u8; SEC_PARAM*DEGREE*2/8] = [0; SEC_PARAM*DEGREE*2/8];
            reader.read(&mut temp_buffer);
            let (sample_a, sample_b) = extract_bits(temp_buffer);
            array_a_i.extend_from_slice(&sample_a);
            array_b_i.extend_from_slice(&sample_b);
        }
        let array_a_shared = array_a_i;
        let array_b_shared =array_b_i;

        // Outer 256 
        (&mut res, &mut res_poly).into_par_iter().enumerate().for_each(|(par_index, (res_item, res_poly_item)) | {
            let (arr1, arr2): (Vec<Zq>, Vec<i128>) = (0..size_of_r_in_ar*DEGREE).map(|index| {
                let a_i: bool = array_a_shared[(par_index*size_of_r_in_ar*DEGREE) + index];
                let b_i: bool = array_b_shared[(par_index*size_of_r_in_ar*DEGREE) + index];
                (LOOK_UP_VEC_ZQ[a_i as usize][b_i as usize], LOOK_UP_VEC_ZQ_I128[a_i as usize][b_i as usize])
            }).collect();
            *res_item = arr1;
            *res_poly_item = arr2;
        });
        (res,res_poly)
    }
    pub fn random_binary_vector_fs_split2(size_of_r_in_ar: usize, res_poly_item_temp : Vec<Vec<i128>>) -> (Vec<Matrix<Poly>>){
        let mut res_poly = vec![Matrix::empty();SEC_PARAM];
        (&mut res_poly,res_poly_item_temp).into_par_iter().enumerate().for_each(|(_par_index, (res_poly_item, arr2)) | {
            let mut arr_2_poly: Vec<Poly> = Vec::with_capacity(size_of_r_in_ar);
            for i in 0..size_of_r_in_ar{
                arr_2_poly.push(Poly::sigma_reflect_i128(&arr2[i*DEGREE..(i+1)*DEGREE].try_into().unwrap()))
            }
            *res_poly_item = Matrix::from_vec_transpose(arr_2_poly);
        });
        res_poly
    }

    //TODO: not used
    // Not (Z_q[x] mod X^N+1) ^ (array_size) 
    /// A random vector of scalar elements Z_q. 
    // pub fn random_zq_vec_scalar(array_size: usize) -> Vec<U128>{
    //     let mut rand= rand::rng();
    //     let arr1: Vec<U128> = (0..array_size).map(|_| {
    //         // let r64 = rand.random_range(..MODULUS) as u64;
    //         // let mut coeff_vec = [0;DEGREE];
    //         // coeff_vec[0] = r64;
    //         // Poly::new(coeff_vec)
    //         U128::from_u128(rand.random_range(..MODULUS))
    //     }
    //     ).collect();
    //     arr1
    // }

    pub fn random_zq_vec(array_size: usize) -> Vec<Poly>{
        let mut rand= rand::rng();
        let arr1: Vec<Poly> = (0..array_size).map(|_| {
            // let r64 = rand.random_range(..MODULUS) as u64;
            // let mut coeff_vec = [U128::zero();DEGREE];
            // coeff_vec[0] = U128::from_u128(rand.random_range(..MODULUS));
            
            let int_u128 =Zq::from(rand.random_range(..MODULUS));
            let mut coeff_vec = [Zq::ZERO;DEGREE];
            let step =DEGREE/L as usize;
            for i in 0..(L as usize){
                coeff_vec[i*step] = int_u128;
            }
            Poly { coeff: coeff_vec } //Sample directly into NTT domain of single integer Zq
            // Poly::new(coeff_vec)
        }
        ).collect();
        arr1
    }

    pub fn random_zq_vec_fs<R: XofReader>(array_size: usize, reader :&mut R) -> Vec<Poly>{
        let mut temp: [u8; 128/8] = [0;128/8];
        let arr1: Vec<Poly> = (0..array_size).map(|_| {
            reader.read(&mut temp);
            let int_u128 =Zq::from( Zq::from(i128::from_be_bytes(temp)));
            let mut coeff_vec = [Zq::ZERO;DEGREE];
            let step =DEGREE/L as usize;
            for i in 0..(L as usize){
                coeff_vec[i*step] = int_u128;
            }
            Poly { coeff: coeff_vec } //Sample directly into NTT domain of single integer Zq
        }
        ).collect();
        arr1
    }

    // /// It is actually standard coefficient form Zq[X]. 
    pub fn canonical_repr(&self) -> [Zq; DEGREE]{
        self.ntt_inv()
    }
    pub fn into_canonical_poly(&self) -> PolyCanon{
        let arr = self.ntt_inv();
        PolyCanon::new(&arr)
    }

    //Cooley-Tukey Butterfly NTT [Incomplete-NTT]
    fn ntt_fwd(mut self) -> Self{
        let mut twiddle_counter = 0;
        let logn = FULL_LAYERS;
        // let mut_ptr = Ptr(self.coeff.as_mut_ptr());
        // let shared = SharedPtr(self.coeff.as_mut_ptr());
        // let shared = &shared; 

        for i in 0..NUM_LAYERS{
            let distance = 2usize.pow(logn - 1u32 -i); 
            for j in 0..2usize.pow(i){
                let twiddle = CT_TWIDDLE_NON_ZQ[twiddle_counter];
                twiddle_counter+=1;
                // println!("j:{}; ", j);
                // (0..distance).into_par_iter().for_each(|k| {
                //     let idx0 = 2*j*distance + k;
                //     let idx1 = idx0 + distance;

                //     // println!("idx0:{}, idx1:{}, distance: {}", idx0, idx1, distance);

                //     let tmp = self.coeff[idx1].mul_mod_vartime(&twiddle, &MODULUS_U128);
                //     unsafe{
                //         *(shared.0.add(idx1)) = self.coeff[idx0].sub_mod(&tmp, &MODULUS_U128);
                //         *(shared.0.add(idx0)) =  self.coeff[idx0].add_mod(&tmp, &MODULUS_U128);
                //     }
                //     // self.coeff[idx1] = self.coeff[idx0].sub_mod(&tmp, &MODULUS_U128);
                //     // self.coeff[idx0] = self.coeff[idx0].add_mod(&tmp, &MODULUS_U128);
                // });
                for k in 0..distance{
                    let idx0 = 2*j*distance + k;
                    let idx1 = idx0 + distance;

                    // println!("idx0:{}, idx1:{}, distance: {}", idx0, idx1, distance);

                    let tmp = self.coeff[idx1] * (&twiddle);
                    self.coeff[idx1] = self.coeff[idx0]- (&tmp);
                    self.coeff[idx0] = self.coeff[idx0] + (&tmp);
                }
            }
        }

        self
    }

    /// Perfomring ntt_inv return a new copy rather than mutating coeff in Poly that is assumed to be in NTT domain.
    fn ntt_inv(&self) -> [Zq; DEGREE]{
        let mut ret: [Zq; DEGREE] = self.coeff.clone();
        let logn = FULL_LAYERS;
        let mut twiddle_counter = 0;
        for i in (logn-NUM_LAYERS)..(logn){
            let distance = 2usize.pow(i);
            for j in 0..(2usize.pow(logn-1-i)){
                let twiddle = GS_TWIDDLE_NON_ZQ[twiddle_counter];
                twiddle_counter+=1;
                for k in 0..distance{
                    let idx0 = 2*j*distance + k;
                    let idx1 = idx0 + distance;

                    let cur_temp = ret[idx0] + (&ret[idx1]);
                    let internal_tmp = ret[idx0] - (&ret[idx1]);
                    ret[idx1]  = internal_tmp * (&twiddle);
                    ret[idx0] = cur_temp;
                }
            }
        }

        // Scaling
        for i in 0..DEGREE{
            ret[i] = (ret[i]) * *(NINV_NON_ZQ);
        }

        ret
    }

    pub fn bin_repr_coeff_compact(&self, beta_bits: usize)-> Vec<Self>{
        assert_eq!(beta_bits, 64);
        // assert_eq!(DEGREE,256);

        ///This takes [coeff1,coeff2,coeff3,coeff4] => Poly
        fn decompose_u128_vec_to_binary_vec(n_vec: Vec<u128>, beta_bits: usize)-> Poly{
            assert_eq!(n_vec.len(),DEGREE/beta_bits);
            let mut bits = Vec::with_capacity(DEGREE);
            for n in n_vec{
                for i in 0..beta_bits{
                    bits.push(Zq::from((n>>i) &1));
                }
            }
            assert_eq!(bits.len(), DEGREE);
            Poly::new(bits.try_into().unwrap())
        }

        let coeff_std = self.canonical_repr();
        let mut all_value_l_slots = Vec::new(); 
        for i in 0..DEGREE*beta_bits/DEGREE{
            let mut temp_vec = vec![0u128;DEGREE/beta_bits];
            for j in 0..DEGREE/beta_bits{
                let mut str =coeff_std[i*(DEGREE/beta_bits)+j].to_string();
                if str ==""{
                    str = "0".to_string(); 
                }
                temp_vec[j] = u128::from_str_radix(&str,10).unwrap();
            }
            all_value_l_slots.push(decompose_u128_vec_to_binary_vec(temp_vec, beta_bits));
        }
        all_value_l_slots
    }
    pub fn bin_compose_compact(compact_bin_poly_vec: &Vec<Poly>, beta_bits: usize, power_series: Vec<Poly>, sigma_one_series: Vec<Poly>, ref_value: Poly)-> Poly{
        assert_eq!(DEGREE/beta_bits*compact_bin_poly_vec.len(), DEGREE);

        let num_section_per_poly = DEGREE/beta_bits;
        assert_eq!(4,num_section_per_poly);
        let mut new_coeff = [Zq::zero();DEGREE];
        for i in 0..beta_bits{ // dbeta/d = beta
            for j in 0..num_section_per_poly{ //4
                new_coeff[i*num_section_per_poly+j] = (compact_bin_poly_vec[i].clone() * power_series[j].sigma_reflect()).canonical_repr()[0];

                // println!("coeff: {}", new_coeff[i*num_section_per_poly+j].to_string());
                // println!("ref_coff:{} ", ref_value.canonical_repr()[i*num_section_per_poly+j]);
                // println!("one * value: {}",  (one_series[i*num_section_per_poly+j].sigma_reflect()* ref_value.clone()).canonical_repr()[0].to_string());
                assert_eq!(((compact_bin_poly_vec[i].clone() * power_series[j].sigma_reflect()) + (&sigma_one_series[i*num_section_per_poly+j] * &ref_value).neg()).canonical_repr()[0], Zq::zero());
            }
        }
        Poly::new(new_coeff)
    }
    pub fn mask_section(&self, cur_section: usize,section_length: usize) -> Self{
        let poly_coeff = self.canonical_repr();
        let mut res_coeff = [Zq::zero();DEGREE];
        for i in cur_section*section_length..(cur_section+1)*section_length{
            res_coeff[i] = poly_coeff[i];
        }
        Poly::new(res_coeff)
    }


    pub fn bin_repr_coeff_domain(&self)-> Self{
        fn decompose_u128_to_binary_vec(n: u128)-> Vec<Zq>{
            let mut bits = Vec::with_capacity(DEGREE);
            for i in 0..128{
                bits.push(Zq::from((n>>i) &1));
                // for _ in 0..BASEMUL_DEGREE-1{
                //     bits.push(Zq::zero());
                // }
            }
            // for j in 0..128{
            //     bits.push(Zq::from(0));
            // }
            for _ in 64*BASEMUL_DEGREE..DEGREE{
                bits.push(Zq::zero());
            }
            assert_eq!(bits.len(), DEGREE);
            bits
        }

        let coeff_std = self.canonical_repr();
        for index in 1..DEGREE{
            assert!(coeff_std[index] == Zq::zero()); //Only support integer
        }
        // println!("{}", coeff_std[0].to_string());
        let all_value_l_slots = decompose_u128_to_binary_vec(u128::from_str_radix(&coeff_std[0].to_string(),10).unwrap());

        Poly::new(all_value_l_slots.try_into().unwrap())
    }
    /// Binary representation in the NTT domain
    /// Only support 64-bits
    pub fn bin_repr(&self)-> Self{
        fn decompose_u128_to_binary_vec(n: u128)-> Vec<Zq>{
            assert_eq!(DEGREE>=(64*BASEMUL_DEGREE as usize), true);
            let mut bits = Vec::with_capacity(DEGREE);
            for i in 0..128{
                bits.push(Zq::from((n>>i) &1));
                for _ in 0..BASEMUL_DEGREE-1{
                    bits.push(Zq::zero());
                }
            }
            for _ in 128*BASEMUL_DEGREE..DEGREE{
                bits.push(Zq::zero());
            }
            assert_eq!(bits.len(), DEGREE);
            bits
        }

        let coeff_std = self.canonical_repr();
        for index in 1..DEGREE{
            assert!(coeff_std[index] == Zq::zero()); //Only support integer
        }
        // println!("{}", coeff_std[0].to_string());
        let all_value_l_slots = decompose_u128_to_binary_vec(u128::from_str_radix(&coeff_std[0].to_string(),10).unwrap());

        Poly {
            coeff : all_value_l_slots.try_into().unwrap()
        }
    }
    /// This function assumes (and partially checks) that (a_1, a_2, ...) := a mod x^d/l+ e^2j+1 s.t. a_1 <=1 and a_(>=1) == 0 and that we support up to 2**63 only
    fn binary_compose(arr: Vec<Zq>) -> Zq{
        // Binary compose using power of two
        let mut acc = Zq::zero();
        //64 bits only
        let mut multiplicant = Zq::one();
        let two = Zq::one() + Zq::one();
        for i in 0..64{
            assert_eq!(arr[i*BASEMUL_DEGREE]<= Zq::one(), true); //Binary
            for j in 1..BASEMUL_DEGREE{
                assert_eq!(arr[(i*BASEMUL_DEGREE)+j]==Zq::zero(), true);
            }
            acc = acc + (&arr[i*BASEMUL_DEGREE] * (&multiplicant));
            multiplicant *= two;
        }
        acc
    }
    /// This function compute Poly(a) -> Poly(Q^T . a) where Q is the repeated row vector [1 2 4 ....].
    pub fn binary_compose_transpose_leftmultiply_self(&self) -> Self{
        // Similar to binary compose, only support u64.
        let mut temp_coeff = self.coeff.clone();
        let mut temp_poly = self.clone();
        let two = Zq::one() + Zq::one();
        for each_coeff_power in 0..64{
            // let change = raise_all_to_power(&self.coeff, each_coeff_power as u64); //first approach somewhat not working
            // for j in 0..BASEMUL_DEGREE{
            //     temp_coeff[each_coeff_power*BASEMUL_DEGREE+j] = change[j].clone();
            // }

            //Second aproach
            for j in 0..BASEMUL_DEGREE{
                let mut change = Zq::zero();
                for k in 0..DEGREE/BASEMUL_DEGREE{
                    change = change + (&temp_poly.coeff[k*BASEMUL_DEGREE+j] );
                }
                temp_coeff[(each_coeff_power*BASEMUL_DEGREE)+j] = change;
                // println!("temp_coeff:{:?}", change)
            }
            temp_poly *= two; //Raise to the correct power
        }

        assert_eq!((L as usize)*BASEMUL_DEGREE, DEGREE);
        //We check integer is representable using 64bits
        for extra_index in 64*BASEMUL_DEGREE..DEGREE{
            temp_coeff[extra_index] = Zq::zero();
        }

        Poly { coeff: temp_coeff }
    }

    /// Returns self.coeff: Vec<Zq> (in standard coefficient format)
    pub fn flatten(self) -> Vec<Zq> {
        self.canonical_repr().to_vec()
    }
    pub fn flatten_ref(&self) -> Vec<Zq> {
        self.canonical_repr().to_vec()
    }

}

// /// Coefficient form with -(q-1//2) to (q-1)//2 range
pub struct PolyCanon{
    // Coefficient is in standard form, with ascending power [0] = x0, ..., and in range ( -q/2,  +q/2 ) 
    pub coeff : [i128; DEGREE] 
}

impl PolyCanon{
    pub fn l1_norm(&self) -> i128{
        // l1 means summing up all coefficients
        let mut sum = self.coeff[0].abs();
        for i in &self.coeff[1..]{
            sum += i.abs();
        }
        sum
    }
    pub fn l2_norm_sqr(&self) -> i128{
        let mut sqr_sum = match self.coeff[0].abs().checked_mul(self.coeff[0].abs()) {
            None => MODULUS_I128-1,
            Some(value) => value 
        };
        for i in &self.coeff[1..]{
            sqr_sum = match sqr_sum.checked_add(match i.abs().checked_mul(i.abs()){
                None => MODULUS_I128-1,
                Some(value) => value 
            }){
                None => MODULUS_I128-1,
                Some(value) => value   
            }
        }
        // (sqr_sum as f64).sqrt()
        sqr_sum
    }
    pub fn l2_norm_sqr_highprecision(&self) -> Integer{
        let mut sqr_sum = Integer::ZERO;
        for i in &self.coeff[..]{
            sqr_sum += Integer::from(i.abs()) * Integer::from(i.abs());
            // sqr_sum += Integer::from_str(&i.to_string()).unwrap().abs().pow(2);
        }
        sqr_sum
    }
    pub fn linf_norm(&self) -> u128{
        // Linf norm say take the max out of all coefficients
        let mut max = self.coeff[0].abs();
        for i in &self.coeff[1..]{
            if i.abs() > max{
                max = i.abs();
            }
        }
        max as u128
    }

    // Convert from Modulo Field to [-(q-1)/2, +(q-1)/2] field 
    fn new(arr: &[Zq; DEGREE]) -> Self{
        let res_arr = PolyCanon::mod_to_sign(arr);
        PolyCanon {
            coeff: res_arr
        }
    }
    
    pub fn mod_to_sign(arr: &[Zq; DEGREE]) -> [i128; DEGREE]{
        let mut ret_arr = [i128::zero(); DEGREE];
        let mut counter = 0;
        for item in arr{
            let item_t = *item;
            ret_arr[counter] = match item_t > *MODULUS_MINUS1_OVER2_ZQ{
                // true => item_t.as_int().checked_sub(&MODULUS_I128_STATIC).unwrap(),
                // _ => item_t.as_int()
                true => zq_to_i128(item_t),
                _ => zq_to_i128(item_t)
            };
            counter+=1;
        };
        ret_arr
    }
    pub fn mod_to_sign_custom(arr: &[Zq; DEGREE], custom_mod: i128 ) -> [i128; DEGREE]{
        let mut ret_arr = [i128::zero(); DEGREE];
        let mut counter = 0;
        // let two = Zq::one()+Zq::one();
        // let custom_mod_i128 = zq_to_i128(custom_mod);
        // let custom_minus_one_over_two = (custom_mod_i128-1)/2;
        // println!("sqrt_q-1 // 2: {}",u128::from_str_radix(&custom_minus_one_over_two.to_string(),16).unwrap());
        for item in arr{
            let item_t = *item;
            // ret_arr[counter] = match item_t > custom_minus_one_over_two{
            //     true => item_t.as_int().checked_sub(&custom_mod.as_int()).unwrap(),
            //     _ => item_t.as_int()
            //     true => zq_to_i128(item_t),
            //     _ => zq_to_i128(item_t)
            // };
            ret_arr[counter] = zq_to_i128_custom(item_t, custom_mod);
            counter+=1;
        };
        ret_arr
    }
    pub fn sign_to_mod(arr: &[i128; DEGREE]) -> [Zq; DEGREE]{
        let mut ret_arr = [Zq::zero(); DEGREE];
        let mut counter = 0;
        for item in arr{
            let item_t = *item;
            ret_arr[counter] = Zq::from(item_t);
            // ret_arr[counter] = match item_t < i128::zero(){
            //     true => *item_t.wrapping_add(&MODULUS_I128_STATIC).as_uint(),
            //     _ => Zq::from(item_t)
            // };
            counter+=1;
        }
        ret_arr
    }
    pub fn sign_to_mod_u128(signed_val: i128) -> u128{
        u128::from_str_radix(&Zq::from(signed_val).to_string(), 10).unwrap()
    }

    // Polynomial Multiplication using Schoolbook given a provided modulus (for test purpose only), all other algorithms use constant MODULUS
    pub fn mul_naive(lhs: &[Zq;DEGREE],rhs: &[Zq;DEGREE]) -> [Zq; DEGREE]{
        let mut temp: [Zq; DEGREE*2] = [Zq::zero();DEGREE*2];
        let mut ret: [Zq;DEGREE] = [Zq::zero(); DEGREE];

        for i in 0..DEGREE{
            for j in 0..DEGREE{
                // let (low, high) = (self.coeff[i].widening_mul(other.coeff[j]));
                let res = (lhs[i]) * (&rhs[j]);
                temp[i+j] = temp[i+j] + (&res);
            }
        }
        // Temp is correctly modulo s.t. first bit is never set

        //Reduction for x^n + 1
        for i in DEGREE..(DEGREE*2)-1{
            ret[i-DEGREE] = temp[i-DEGREE] - (&temp[i]);
        }
        ret[DEGREE-1] = temp[DEGREE-1];

        ret
    }

    pub fn inner_product_modq(self, other:Self) -> Zq{    
        let coeff_1 = PolyCanon::sign_to_mod(&self.coeff);
        // println!("{:?}", coeff_1);
        let coeff_2 = PolyCanon::sign_to_mod(&other.coeff);
        // println!("{:?}", coeff_2);
        // println!("{:?}", other.coeff);

        let sum = coeff_1.iter().zip(coeff_2.iter()).map(|(x,y)| (*x) * (y)).reduce(
            |acc, x| (acc + (&x))
        ).unwrap();
        sum
    }

    pub fn inner_product(arr1: Vec<Zq>, arr2: Vec<Zq>) -> Zq{
        let sum = arr1.iter().zip(arr2.iter()).map(|(x,y)| (*x) * (y)).reduce(
            |acc, x| acc + (&x)
        ).unwrap();
        sum
    }
}


#[cfg(test)]
mod tests{
    // use std::pin::Pin;
    use num_bigint::BigInt;
    use num_traits::FromPrimitive;

    use super::*;
    const TEST_COUNT: u64 = 100;
    // const DATA_TEST: [u64; DEGREE] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    use lazy_static::lazy_static;
    lazy_static!{
        pub static ref DATA0: [Zq; DEGREE] = (0..DEGREE).map(|_| Zq::zero()).collect::<Vec<Zq>>().try_into().unwrap();
        pub static ref DATA1: [Zq; DEGREE] = (0..DEGREE).map(|_| Zq::one()).collect::<Vec<Zq>>().try_into().unwrap();
        pub static ref DATA2: [Zq; DEGREE] = (0..DEGREE).map(|i| Zq::from(i as u128)).collect::<Vec<Zq>>().try_into().unwrap();
    }
    #[test]
    fn test_config(){
        assert_eq!(BASEMUL_DEGREE,2); //Currently we implemented degree 1 polynomial multiplication. Modifying that should allow us to higher.
    }

    // #[test]
    // fn test_poly_from_ntt_coeff(){
    //     let p = Poly::new_inverse_ntt(DATA2);
    //     let coeff_ntt = Poly::demont(p.coeff);
    //     assert_eq!(coeff_ntt,DATA2);
    // }
    

    #[test]
    fn test_mul_poly(){
        let p = Poly::new(*DATA2);
        let q = Poly::new(*DATA2);
        let res = p*q;
        let res_ref=  PolyCanon::mul_naive(&DATA2, &DATA2);
        assert_eq!(res.canonical_repr(), res_ref);
        // println!("{:?}", res.canonical_repr());
        // println!("{:?}", res_ref);

        let mut rand= rand::rng();
        let arr1: Vec<Zq> = (0..DEGREE).map(|_index| (Zq::from(rand.random_range(0..MODULUS) ))).collect();
        let arr2: Vec<Zq> = (0..DEGREE).map(|_index| (Zq::from(rand.random_range(0..MODULUS)))).collect();
        let p = Poly::new(arr1[..].try_into().unwrap());
        let q = Poly::new(arr2[..].try_into().unwrap());
        let res= &p*&q;
        assert_eq!(res.canonical_repr(),PolyCanon::mul_naive(&arr1[..].try_into().unwrap(), &arr2[..].try_into().unwrap()));

        let res= p*q;
        assert_eq!(res.canonical_repr(),PolyCanon::mul_naive(&arr1[..].try_into().unwrap(), &arr2[..].try_into().unwrap()));
    }

    #[test]
    fn test_add(){
        let p1 = Poly::new(*DATA1);
        let p2 = Poly::new(*DATA2);
        let data12_sum: Vec<Zq> = DATA1.iter().zip(*DATA2).map(|(x1,x2)| (x1 + &x2)).collect();
        let p3 = Poly::new(data12_sum.try_into().unwrap());
        assert_eq!((p1+p2), p3);

        let p1_r = Poly::random();
        let p2_r = Poly::random();
        let p12r_sum: Vec<Zq> = p1_r.canonical_repr().iter().zip(p2_r.canonical_repr()).map(|(x1,x2)| (x1 + (&x2))).collect();
        let p3_r = Poly::new(p12r_sum.try_into().unwrap());
        assert_eq!((p1_r+p2_r), p3_r);
    }

    #[test]
    fn test_neg(){
        let p1_r = Poly::random();
        assert_eq!( p1_r.neg() + p1_r, Poly::zero());
    }

    #[test]
    fn test_zero(){
        let p = Poly::new([Zq::zero();DEGREE]);
        assert_eq!(p.is_zero(), true);
        assert_eq!(Poly::zero().is_zero(), true);
    }
    #[test]
    fn test_one(){
        let mut val = [Zq::zero();DEGREE];
        val[0] = Zq::one();
        let p = Poly::new(val);
        assert_eq!(p.is_one(), true);
        assert_eq!(Poly::one().is_one(), true);
    }
    

    #[test]
    fn test_mulassign(){
        let mut rand= rand::rng();
        let arr1: Vec<Zq> = (0..DEGREE).map(|_| (Zq::from(rand.random_range(0..MODULUS)))).collect();
        let mut p1 = Poly::new(arr1.clone().try_into().unwrap());
        
        let mut rand= rand::rng();
        let scale_factor: Zq = Zq::from(rand.random_range(0..MODULUS));
        let scale_p1: Vec<Zq> = arr1.iter().map(| x1 | ( (*x1) * (&scale_factor))).collect();

        p1 *= scale_factor;
        let p1_scaled = p1.canonical_repr();
        assert_eq!(p1_scaled.to_vec(), scale_p1);
    }

    #[test]
    fn test_ntt(){
        let p = Poly::new(*DATA0);
        assert_eq!(p.canonical_repr(), *DATA0);

        let p = Poly::new(*DATA1);
        assert_eq!(p.canonical_repr(), *DATA1);

        let p = Poly::new(*DATA2);
        assert_eq!(p.canonical_repr(), *DATA2);

        let mut rand= rand::rng();
        let arr: Vec<Zq> = (0..DEGREE).map(|_index| (Zq::from(rand.random::<u64>()))).collect();
        let p = Poly::new(arr[..].try_into().unwrap());
        assert_eq!(p.canonical_repr(), arr[..]);

        let mut rand= rand::rng();
        let arr: Vec<Zq> = (0..DEGREE).map(|_index| (Zq::from(rand.random_range(0..MODULUS)))).collect();
        let p = Poly::new(arr[..].try_into().unwrap());
        assert_eq!(p.canonical_repr(), arr[..]);
    }

    #[test]
    fn test_signed_modulo_conversion(){
        // Test function are reversible using random value
        let mut rand= rand::rng();
        let arr: Vec<Zq> = (0..DEGREE).map(|_index| (Zq::from(rand.random_range(0..MODULUS)))).collect();

        println!("{:?}",PolyCanon::mod_to_sign(&arr[..].try_into().unwrap()));
        assert_eq!(PolyCanon::sign_to_mod(&PolyCanon::mod_to_sign(&arr[..].try_into().unwrap())), arr[..]);
        
        let _p = Poly::new(arr[..].try_into().unwrap());
    }

    #[test]
    fn test_norm(){
        let mut testdata: Vec<Zq> = vec![Zq::from(1),Zq::from(2),Zq::from(3),Zq::from(4),Zq::from(5),Zq::from(6),Zq::from(7),Zq::from(8),Zq::from(9),Zq::from(10)];
        testdata.extend_from_slice(&[Zq::zero();DEGREE-10]);
        let pc = PolyCanon::new(&testdata[..].try_into().unwrap());
        assert_eq!(pc.l1_norm(), i128::from(55));
        assert_eq!(pc.l2_norm_sqr(), i128::from(385));
        assert_eq!(pc.linf_norm(), u128::from(10u32));

        //Negative 
        let mut testdata: Vec<Zq> = vec![Zq::from(MODULUS-1),Zq::from(MODULUS-2),Zq::from(MODULUS-3),Zq::from(MODULUS-4),Zq::from(MODULUS-5),Zq::from(MODULUS-6),Zq::from(MODULUS-7),Zq::from(MODULUS-8),Zq::from(MODULUS-9),Zq::from(MODULUS-10)];
        testdata.extend_from_slice(&[Zq::zero();DEGREE-10]);
        let pc = PolyCanon::new(&testdata[..].try_into().unwrap());
        assert_eq!(pc.l1_norm(), i128::from(55));
        assert_eq!(pc.l2_norm_sqr(), i128::from(385));
        assert_eq!(pc.linf_norm(), u128::from(10u32));

        // let testdata2: [u64; 128]= [0, 1, 4, 9, 16, 25, 36, 49, 64, 81, 100, 121, 144, 169, 196, 225, 256, 289, 324, 361, 400, 441, 484, 529, 576, 625, 676, 729, 784, 841, 900, 961, 1024, 1089, 1156, 1225, 1296, 1369, 1444, 1521, 1600, 1681, 1764, 1849, 1936, 2025, 2116, 2209, 2304, 2401, 2500, 2601, 2704, 2809, 2916, 3025, 3136, 3249, 3364, 3481, 3600, 3721, 3844, 3969, 4096, 4225, 4356, 4489, 4624, 4761, 4900, 5041, 5184, 5329, 5476, 5625, 5776, 5929, 6084, 6241, 6400, 6561, 6724, 6889, 7056, 7225, 7396, 7569, 7744, 7921, 8100, 8281, 8464, 8649, 8836, 9025, 9216, 9409, 9604, 9801, 10000, 10201, 10404, 10609, 10816, 11025, 11236, 11449, 11664, 11881, 12100, 12321, 12544, 12769, 12996, 13225, 13456, 13689, 13924, 14161, 14400, 14641, 14884, 15129, 15376, 15625, 15876, 16129];
        // let pc = PolyCanon::new(&testdata2);
        // assert_eq!(pc.l1_norm(), 690880);
        // assert_eq!(pc.l2_norm(), 82087.93450928097);
        // assert_eq!(pc.linf_norm(), 16129);
    }


    #[test]
    fn test_innerproduct_sigma_reflect(){
        // let poly1: Poly = Poly::new(DATA2);
        for _ in 0..TEST_COUNT{
            let poly1 = Poly::random();
            let poly2 = Poly::random();
            assert_eq!(poly2.clone(),poly2.clone().sigma_reflect().sigma_reflect());
            let inner_product_const_poly = &poly1*&poly2.clone().sigma_reflect();
            // println!("{:?}",inner_product_const_poly.into_canonical_poly().coeff);
            assert_eq!(inner_product_const_poly.canonical_repr()[0] , poly1.into_canonical_poly().inner_product_modq(poly2.into_canonical_poly()));
        }
    }

    #[test]
    fn test_scaled_sum_lemma(){
        // This is ENS20 Lemma 2.1. We have 1/l * Sum over NTT(coeff) = Original_coeff[up to slot d/l]
        let poly = Poly::random();

        for j in 0..BASEMUL_DEGREE{
            let mut sum = Zq::zero();
            for i in 0..DEGREE/BASEMUL_DEGREE{
                sum = sum + (&poly.coeff[i*BASEMUL_DEGREE+j]);
            }

            let l_u128 = Zq::from(L);
            // (&MODULUS_U128).unwrap();
            let l_inv = Zq::one()/Zq::from(L);
            assert_eq!(l_inv * (&l_u128), Zq::one());
            println!("Index:{:?}",j);
            assert_eq!(sum * (&l_inv), poly.canonical_repr()[j]);
        }
    }

    #[test]
    fn test_bin_repr_of_ntt(){
        let p = Poly::random_integer();
        let p_bin = p.bin_repr();
        // println!("p_bin: {:?}",p_bin);

        // Test binary vectors in NTT domain
        // In the NTT domain x_ntt + (x_ntt-1) = 0
        let res = &p_bin * &(&p_bin + &Poly::one().neg());
        assert_eq!([Zq::zero(); DEGREE], (res.coeff));
        assert_eq!(Poly::zero(), res);

        // Test binary decomposition, note that we have NTT(int_a) = (int_a, int_a , int_a, ...)
        assert_eq!(Poly::binary_compose((p.bin_repr().coeff).to_vec()), p.coeff[0]);
        assert_eq!((Poly::binary_compose((p.bin_repr().coeff).to_vec())), p.canonical_repr()[0]);

        // Test close to property of (34) in LNPS21
        // first d/l coefficient of m_bin_repr * NTT^-1(Q^T phi) - m NTT^-1(phi) = 0
        let phi = Poly::random();
        // let phi = Poly::one();
        // println!("phi:={:?}",phi);
        // println!("QT phi:={:?}",phi.binary_compose_transpose_leftmultiply_self());
        let lhs = p_bin * phi.binary_compose_transpose_leftmultiply_self();
        let rhs =(p.clone() * phi.clone()).neg();
        // assert_eq!(Poly::zero(), rhs.clone() + (p.clone() * phi.clone()));
        let res = &lhs + &rhs;
        for i in 0..BASEMUL_DEGREE{
            assert_eq!(res.canonical_repr()[i], Zq::zero());
        }

    }

    // #[test]
    // fn test_test(){
    //     println!("{:?},{:?}", Poly::random_integer().coeff[0],Poly::random_integer().coeff[1] );
    //     assert!(false);
    // }

    #[test]
    fn test_ntt_each_slot(){
        let p = Poly::random_integer_at_slot(2);
        let q = Poly::random_integer_at_slot(3);
        println!("{}", p);
        println!("{}", q);
        // assert!(false);
    }
}
