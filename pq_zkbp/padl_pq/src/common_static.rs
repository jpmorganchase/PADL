

use crate::common::{BM_TWIDDLE_NON, CT_TWIDDLE_NON, GS_TWIDDLE_NON, MODULUS_I128 as mod_i128, NINV_NON, MODULUS_MINUS1_OVER2,MODULUS_SQRT, MODULUS_SQRT_INV};
use crate::common::L;
use crate::common::MODULUS;
use crate::common::DEGREE;
// use crate::common::ZqConfig;
use crate::matrix::Matrix;
use crate::polynomial::Poly;
use crate::polynomial::Poly_U128;
use crate::common_trait::SigmaReflect;
// use crypto_bigint::*;
use lazy_static::lazy_static;
// use num_traits::One;

use ark_ff::{Fp, Fp128, MontBackend};

#[cfg (feature="d256")]
#[path="common_custom_d256.rs"]
mod common_custom;

#[cfg (feature="d1024")]
#[path="common_custom_d1024.rs"]
mod common_custom;

pub use common_custom::lambda as lambda;
pub use common_custom::kappa as kappa;
pub use common_custom::SIGMA_VERYLARGE as SIGMA_VERYLARGE;
pub use common_custom::SIGMA_LARGE as SIGMA_LARGE;
pub use common_custom::SIGMA_LARGE_U128 as SIGMA_LARGE_U128;
pub use common_custom::SIGMA_VERYLARGE_u32 as SIGMA_VERYLARGE_u32;
pub use common_custom::SIGMA_SMALL as SIGMA_SMALL;
pub use common_custom::SIGMA_POB_S1 as SIGMA_POB_S1;
pub use common_custom::SIGMA_POC_S1 as SIGMA_POC_S1;
pub use common_custom::SIGMA_POC_S2 as SIGMA_POC_S2;
pub use common_custom::SIGMA_POC_S3 as SIGMA_POC_S3;
pub use common_custom::SIGMA_POE_S1 as SIGMA_POE_S1;
pub use common_custom::SIGMA_POE_S2 as SIGMA_POE_S2;
pub use common_custom::SIGMA_POE_S3 as SIGMA_POE_S3;
pub use common_custom::SIGMA_POA_S1 as SIGMA_POA_S1;
pub use common_custom::SIGMA_POA_COMPACT_S1 as SIGMA_POA_COMPACT_S1;
pub use common_custom::SIGMA_POA_COMPACT_S0 as SIGMA_POA_COMPACT_S0;
pub use common_custom::SIGMA_POA_COMPACT_S2 as SIGMA_POA_COMPACT_S2;
pub use common_custom::SIGMA_POA_COMPACT_S3 as SIGMA_POA_COMPACT_S3;
pub use common_custom::ZqConfig as ZqConfig;

pub type Zq = Fp128<MontBackend<ZqConfig, 2>>;
use num_traits::{One,Zero};
use rayon::ThreadPoolBuilder;

/// Maximum Byte needed to represent a Polynomial  
pub const POLY_SIZE: usize = 16*DEGREE;

pub const MAX_COEFF_BETA: usize = 64;

lazy_static!{
    // pub static ref DUMMY: u32 = {
    //     ThreadPoolBuilder::new()
    //     .num_threads(1)
    //     .build_global()
    //     .unwrap();

    //     1
    // };

    /// This is used for scaling when INTT operation is finished
    pub static ref NINV_NON_ZQ: Zq = {
        Zq::from(NINV_NON)
    };



    // pub static ref MODULUS_SQRT_I128: crypto_bigint::NonZero<crypto_bigint::Int<2>> = {
    //     crypto_bigint::NonZero::new(I128::from_i128(MODULUS_SQRT as i128)).unwrap()
    // };

    pub static ref LOOK_UP_VEC_ZQ : [[Zq; 2]; 2] = [[Zq::zero(),Zq::from(MODULUS-1)],[Zq::one(),Zq::zero()]];
    pub static ref LOOK_UP_VEC_ZQ_I128 : [[i128; 2]; 2] = [[i128::zero(), -i128::one()],[i128::one(),i128::zero()]];


    pub static ref MODULUS_SQRT_ZQ: Zq = {
        Zq::from(MODULUS_SQRT)
    };
    pub static ref MODULUS_SQRT_INV_ZQ: Zq = {
        Zq::from(MODULUS_SQRT_INV)
    };
    

    /// This is MODULUS-1 or -1 in q-1//2 interpretation
    pub static ref NEGATIVE_ONE_ZQ: Zq = {
        Zq::from(MODULUS-1)
        // Zq::zero().sub_mod(&Zq::one(), &MODULUS_U128)
    };
    pub static ref MODULUS_MINUS1_OVER2_ZQ: Zq = {
        Zq::from(MODULUS_MINUS1_OVER2)
    };

    // pub static ref MODULUS_I128_STATIC: crypto_bigint::NonZero<crypto_bigint::Int<2>> = {
    //     crypto_bigint::NonZero::new(I128::from_i128(mod_i128)).unwrap()
    // };

    pub static ref BM_TWIDDLE_NON_ZQ: [Zq; L as usize] = {
        BM_TWIDDLE_NON.into_iter().map(|item| Zq::from(item)).collect::<Vec<Zq>>().try_into().unwrap() 
    };
    pub static ref CT_TWIDDLE_NON_ZQ: [Zq; (L-1) as usize] = {
        CT_TWIDDLE_NON.into_iter().map(|item| Zq::from(item)).collect::<Vec<Zq>>().try_into().unwrap() 
    };
    pub static ref GS_TWIDDLE_NON_ZQ: [Zq; (L-1) as usize] = {
        GS_TWIDDLE_NON.into_iter().map(|item| Zq::from(item)).collect::<Vec<Zq>>().try_into().unwrap() 
    };

    pub static ref ej_vec_static: Vec<Matrix::<Poly>> = {
        let mut res_vec = vec![Matrix::<Poly>::empty(); DEGREE];
        for i in 0..DEGREE{
            let mut ez = [Poly_U128::zero();DEGREE];
            ez[i] = Poly_U128::one();
            let ez_poly = Poly::new(ez);
            res_vec[i] = Matrix::from_vec_transpose(vec![ez_poly.sigma_reflect()]); //Transpose because it is left multiplicaiton.
        }
        res_vec
    };

    pub static ref rj_ej_one_vec_static: Vec<Matrix::<Poly>> = {
        let mut res_vec = vec![Matrix::<Poly>::empty(); DEGREE];
        for i in 0..DEGREE{
            res_vec[i] = Matrix::from_vec_transpose(vec![Poly::one()]); //Transpose because it is left multiplicaiton.
        }
        res_vec
    };

    pub static ref SIGMA_MINUS_ONE_NEGATIVE_ONE : Poly = {
        let arr1 = [Zq::from(-1);DEGREE];
        let neg_one = Zq::from(-1);
        for item in arr1{
            assert_eq!(item, neg_one);
        }
        Poly::new(arr1.try_into().unwrap()).sigma_reflect()
    };

}