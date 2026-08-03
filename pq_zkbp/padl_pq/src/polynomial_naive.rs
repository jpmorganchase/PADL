
// use std::ops::Rem;
use std::mem::{self};
use std::ops::Mul;
use crate::common::*;
// use crate::common_static::{BM_TWIDDLE_NON_U128, CT_TWIDDLE_NON_U128, MODULUS_U128, GS_TWIDDLE_NON_U128, NINV_NON_U128};
// use crypto_bigint::{Zero, U128};
use crate::common_static::{Zq,CT_TWIDDLE_NON_ZQ,GS_TWIDDLE_NON_ZQ,NINV_NON_ZQ,BM_TWIDDLE_NON_ZQ};
use ark_ff::Zero;

// This struct does not derive Copy to avoid copy on function invokacation using Poly as parameter i.e. it is moved.  
#[derive(Clone, Debug)]
pub struct PolyNonMon{
    // Coefficient by default should be in NTT domain.
    coeff : [Zq; DEGREE] 
}

impl Mul for PolyNonMon{
    type Output = Self;
    
    fn mul(self, rhs: Self) -> Self::Output {
        let mut temp: [Zq; DEGREE] = [Zq::zero(); DEGREE];

        //NOTE: Currently only support BASEMUL_DEGREE==2
        for i in 0..(DEGREE/BASEMUL_DEGREE){
            // Perform base multiplication here. We do schoolbook.
            // Then we do polynomial modulo reduction
            let final_red_amount = self.coeff[i*BASEMUL_DEGREE + 1] * (&rhs.coeff[i*BASEMUL_DEGREE + 1]) * (&BM_TWIDDLE_NON_ZQ[i]); 
            let zero_place = self.coeff[i*BASEMUL_DEGREE] * (&rhs.coeff[i*BASEMUL_DEGREE]);
            temp[i*BASEMUL_DEGREE] = zero_place + (&final_red_amount);
            temp[i*BASEMUL_DEGREE + 1] = (
                self.coeff[i*BASEMUL_DEGREE + 1] * (&rhs.coeff[i*BASEMUL_DEGREE]) + (
                &self.coeff[i*BASEMUL_DEGREE] * (&rhs.coeff[i*BASEMUL_DEGREE + 1]))
            );
        }

        PolyNonMon { coeff: temp}
    }
}

impl PolyNonMon{
    pub fn new(arr: [Zq; DEGREE]) -> Self{
        Self {
            coeff: arr
        }.ntt_fwd()
    }
    pub fn canonical_repr(&self) -> [Zq; DEGREE]{
        self.ntt_inv()
    }

    //Cooley-Tukey Butterfly NTT (automatically tarnsform into brev) [Incomplete-NTT]
    fn ntt_fwd(mut self) -> Self{
        let mut twiddle_counter = 0;
        let logn = FULL_LAYERS;
        for i in 0..NUM_LAYERS{
            let distance = 2usize.pow(logn - 1u32 -i); 
            for j in 0..2usize.pow(i){
                let twiddle = CT_TWIDDLE_NON_ZQ[twiddle_counter];
                twiddle_counter+=1;
                for k in 0..distance{
                    let idx0 = 2*j*distance + k;
                    let idx1 = idx0 + distance;

                    let tmp = self.coeff[idx1] * (&twiddle);
                    self.coeff[idx1] = self.coeff[idx0] - (&tmp);
                    self.coeff[idx0] = self.coeff[idx0] + (&tmp);
                }
            }
        }

        self
    }

    // Perfomring ntt_inv should return a new copy rather than mutating coeff that is assumed to be in NTT domain.
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

                    // TODO: this need to be optimized.
                    let cur_temp = ret[idx0] + (&ret[idx1]);
                    let internal_tmp = ret[idx0] - (&ret[idx1]);
                    ret[idx1]  = internal_tmp * (&twiddle);
                    ret[idx0] = cur_temp;
                }
            }
        }

        // Scaling
        for i in 0..DEGREE{
            ret[i] = (ret[i]) * (*NINV_NON_ZQ);
        }

        ret
    }

    // pub fn mul(&self, other: Self) -> &Self {

    // }
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
}

#[cfg(test)]
mod tests{
    // use crate::common_old::MODULUS;

    use super::*;
    use num_traits::One;
    use rand::Rng;

    use lazy_static::lazy_static;
    lazy_static!{
        pub static ref DATA0: [Zq; DEGREE] = (0..DEGREE).map(|_| Zq::zero()).collect::<Vec<Zq>>().try_into().unwrap();
        pub static ref DATA1: [Zq; DEGREE] = (0..DEGREE).map(|_| Zq::one()).collect::<Vec<Zq>>().try_into().unwrap();
        pub static ref DATA2: [Zq; DEGREE] = (0..DEGREE).map(|i| Zq::from(i as u128)).collect::<Vec<Zq>>().try_into().unwrap();

        pub static ref DATA3: [Zq; DEGREE] = (0..DEGREE).map(|index| {
            if index!=0{
                Zq::zero()
            }
            else{
                Zq::one()
            }
        }
        ).collect::<Vec<Zq>>().try_into().unwrap();
    }
    
    #[test]
    fn test_config(){
        assert_eq!(BASEMUL_DEGREE,2);
    }

    #[test]
    fn test_mul_poly(){
        let p = PolyNonMon::new(*DATA2);
        let q = PolyNonMon::new(*DATA2);
        let res = p*q;
        let res_ref=  PolyNonMon::mul_naive(&DATA2, &DATA2);
        assert_eq!(res.canonical_repr(), res_ref);
        // println!("{:?}", res.canonical_repr());
        // println!("{:?}", res_ref);

        let mut rand= rand::rng();
        let arr1: Vec<Zq> = (0..DEGREE).map(|_index| (Zq::from(rand.random::<u128>()) )).collect();
        let arr2: Vec<Zq> = (0..DEGREE).map(|_index| (Zq::from(rand.random::<u128>()) )).collect();

        let p = PolyNonMon::new(arr1[..].try_into().unwrap());
        let q = PolyNonMon::new(arr2[..].try_into().unwrap());
        let res= p*q;
        // println!("{:?}", res.canonical_repr());
        assert_eq!(res.canonical_repr(),PolyNonMon::mul_naive(&arr1[..].try_into().unwrap(), &arr2[..].try_into().unwrap()));

    }

    #[test]
    fn test_ntt(){
        let p = PolyNonMon::new(*DATA0);
        assert_eq!(p.canonical_repr(), *DATA0);

        let p = PolyNonMon::new(*DATA3);
        assert_eq!(p.canonical_repr(), *DATA3);

        let p = PolyNonMon::new(*DATA1);
        assert_eq!(p.canonical_repr(), *DATA1);

        let p = PolyNonMon::new(*DATA2);
        assert_eq!(p.canonical_repr(), *DATA2);

        let mut rand= rand::rng();
        let arr: Vec<Zq> = (0..DEGREE).map(|_index| (Zq::from(rand.random::<u64>()))).collect();
        let p = PolyNonMon::new(arr[..].try_into().unwrap());
        assert_eq!(p.canonical_repr(), arr[..]);

        let mut rand= rand::rng();
        let arr: Vec<Zq> = (0..DEGREE).map(|_index| (Zq::from(rand.random::<u128>()) )).collect();
        let p = PolyNonMon::new(arr[..].try_into().unwrap());
        assert_eq!(p.canonical_repr(), arr[..]);
    }
}