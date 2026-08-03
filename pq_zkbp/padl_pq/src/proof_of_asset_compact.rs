use ark_ff::Field;
use ark_ff::One;
use num_traits::Float;
use num_traits::ToPrimitive;
use sha3::Shake256;
use sha3::digest::ExtendableOutput;
use crate::commitment::ABDLOP;
use crate::common_static::POLY_SIZE;
use crate::common_static::SIGMA_POA_COMPACT_S1;
use crate::common_static::rj_ej_one_vec_static;
use crate::common_static::{ej_vec_static,lambda,kappa};
use crate::common_trait::{Norm, SigmaReflect};
use crate::matrix::Matrix;
use crate::polynomial::Poly;
use crate::polynomial::Poly_U128;
use crate::common::DEGREE;
use crate::sampler::Sampler;
use crate::sampler_ddll::Sampler as Sampler_ddll;
use crate::common_static;
use sha3::digest::Update;

use num_traits::Zero;
use rayon::prelude::*;
use rayon::iter::IntoParallelIterator;
use rayon::iter::IndexedParallelIterator;
use std::ops::Deref;
use std::ops::Neg;
use crate::polynomial::PolyCanon;
use postcard::{to_extend,to_stdvec, to_vec, to_slice, to_io};
use std::io::Cursor;

use rug::Integer;

use crate::common_static::SIGMA_POA_COMPACT_S2;
use crate::common_static::SIGMA_MINUS_ONE_NEGATIVE_ONE;

use sha3::{Digest as Sha3_Digest, Sha3_256};
/// =========================================================
/// Proof of Asset Compact Version:

/// =========================================================
///
///
///

use lazy_static::lazy_static;
use crate::common_static::Zq;

// pub const MAX_VALUE_BOUND: u64 = u64::MAX-1;
// pub const MAX_COEFF_BETA: usize = 64;
use crate::common_static::MAX_COEFF_BETA;

// DEGREE * beta
pub const MAX_VALUE_BOUND: u64 = (DEGREE as u64) * (MAX_COEFF_BETA as u64); //This is the max value 

fn compute_custom_xcompose(challenge_row: &Vec<Poly>, beta_power: &Vec<Poly>, sigma_one_series: &Vec<Poly>, v_bin_vec: &Vec<Poly>, value_poly: &Poly) -> Poly{
    use crate::common::DEGREE;
    use std::ops::Neg;
    assert_eq!(challenge_row.len(), beta_power.len() * v_bin_vec.len());
    let acc = (challenge_row,sigma_one_series).into_par_iter().enumerate().map( |(index,(challenge_row_item, sigma_one_series_item))| {
        let beta_index = index % beta_power.len();
        let vbin_index = index * v_bin_vec.len() / DEGREE ;
        let matrix_mul_res = (&beta_power[beta_index].sigma_reflect() * &v_bin_vec[vbin_index]) + (sigma_one_series_item * value_poly).neg(); 
        let temp = challenge_row_item * &matrix_mul_res;
        temp
    }).reduce(|| Poly::zero(), |a,b| a+b);
    acc
}

lazy_static!{
    pub static ref Z2_MAX_BOUND: u128 = {
        ((DEGREE as f64).sqrt() * 1.64).to_u128().unwrap() * common_static::SIGMA_POA_COMPACT_S2 as u128
        // (512.0.sqrt().to_u128().unwrap() * common_static::SIGMA_POA_COMPACT_S2)
    };


    pub static ref POWER_OF_2_COEFF_POLY_VERIFIER_COMPACT : Vec<Poly> = {
        assert!(DEGREE >= 256);
        assert_eq!(MAX_COEFF_BETA,64);
        let power = Zq::from(2);
        let mut res_poly_vec = vec![Poly::zero();DEGREE/MAX_COEFF_BETA];
        for j in 0..DEGREE/MAX_COEFF_BETA{
            let mut arr1 = [Zq::zero();DEGREE];
            let mut power_of_two = Zq::from(1);
            for i in 0..MAX_COEFF_BETA{
                arr1[j*MAX_COEFF_BETA + i] = power_of_two;
                power_of_two = power_of_two * power;
            }
            res_poly_vec[j] = Poly::new(arr1.try_into().unwrap());
        }
        res_poly_vec
    };

    pub static ref SIGMA_ONE_COMPACT : Vec<Poly> = {
        assert!(DEGREE >= 256);
        assert_eq!(MAX_COEFF_BETA,64);
        let one = Zq::from(1);
        let mut res_poly_vec = vec![Poly::zero();DEGREE];
        for j in 0..DEGREE{
            let mut arr1 = [Zq::zero();DEGREE];
            arr1[j]= Zq::one();
            res_poly_vec[j] = Poly::new(arr1.try_into().unwrap()).sigma_reflect();
        }
        res_poly_vec
    };

    pub static ref EmptyProof: ProofOfAssetCompact = {
        ProofOfAssetCompact{
            u0: Matrix::empty(),
            u_y2: Matrix::empty(),
            u_masking_g: Matrix::empty(),
            u_g1: Poly::zero(),
            bin_challenge_mat_poly_sigma: Vec::new(), 
            dj_vec: Vec::new(),
            dj_vec_binary: Vec::new(),
            dj_vec_compose: Vec::new(),
            challenge: Poly::zero(),
            z2: Poly::zero(),
            z0: Matrix::empty(),
            z1: Matrix::empty(),
            z3: Matrix::empty(),
            w1: Matrix::empty(),
            w2: Matrix::empty(),
            v : Poly::zero(),
            h : Poly::zero()
        }
    };
}



#[derive(Clone, Debug)]
pub struct ProofOfAssetCompact {
    // ABDLOP ZKP initial commitment
    pub u0: Matrix<Poly>,
    pub u_y2: Matrix<Poly>,
    pub u_masking_g: Matrix<Poly>,
    pub u_g1: Poly,
    
    //Challenge
    pub bin_challenge_mat_poly_sigma: Vec<Matrix<Poly>>,
    pub dj_vec: Vec<Poly>,
    pub dj_vec_binary: Vec<Poly>,
    pub dj_vec_compose: Vec<Poly>,
    pub challenge: Poly,
    
    //Response
    pub z2: Poly,
    pub z0: Matrix<Poly>,
    pub z1: Matrix<Poly>,
    pub z3: Matrix<Poly>,
    
    pub w1: Matrix<Poly>,
    pub w2: Matrix<Poly>,
    pub v: Poly,
    pub h : Poly,
}

fn zq_vec_to_vec_str(print_vec :Vec<Zq>, is_space: bool)-> String{
    let mut str = "".to_owned();
    for item in print_vec{
        if item.to_string() == ""{
            str = str + &("0");
        }
        else{
            str = str + &item.to_string();
        }
        if is_space{
            str = str + ",";
        }
    }
    str
}


pub fn gen_proof_of_asset_compact (
    bdlop: &ABDLOP,     // original (qpadl) parameters used to produce cm1,r1
    abdlop: &ABDLOP,    // Proof Parameter
    ori_commit: &Matrix<Poly>, //public commitment
    ori_r: &Matrix<Poly>,  // witness randomness used in original commitment
    value: &Poly, //witness value
    is_rejection_sampling: bool
) -> ProofOfAssetCompact{
    let mut rejected_time =0;
    let value_coeff_form = value.bin_repr_coeff_compact(MAX_COEFF_BETA);
    let proof_ck_vec =abdlop.ck.slice_into_custom(abdlop.ck_binding_height_n);
    let  proof_ck_top = &proof_ck_vec[0];
    let  proof_ck_y2 = &proof_ck_vec[proof_ck_vec.len()-3];
    let  proof_ck_g = &proof_ck_vec[proof_ck_vec.len()-2];
    let  proof_ck_g1 = &proof_ck_vec[proof_ck_vec.len()-1];
    let proof_ck_vbin_compact = &proof_ck_vec[1..proof_ck_vec.len()-2];

    let (oricm1_com0,_oricm1_com1,_oricm1_com2, oricm1_com3) = ori_commit.slice_into_4(bdlop.ck_binding_height_n);
    let (oricm1_ck_top, _oricm1_ck_m1, _oricm1_ck_m2, oricm1_ck_m3 )= bdlop.ck.slice_into_4(bdlop.ck_binding_height_n);
    let value_flatten: Vec<Zq> = value_coeff_form.iter().map(|value_coeff| value_coeff.flatten_ref()).collect::<Vec<Vec<Zq>>>().into_iter().flatten().collect();

    '_outer: loop {    
        
        let masking_g = Poly::random_constant_unmasked(); 
        assert_eq!(masking_g.canonical_repr()[0],Poly_U128::ZERO);   
        let y2 = Poly::random_discrete_gaussian(SIGMA_POA_COMPACT_S2);

        let mut messages = vec![];
        // messages.append(&mut value_coeff_form.clone());
        messages.append(&mut vec![y2.clone(), masking_g.clone()]);
        let prepared_m = abdlop.prepare_message_custom(messages);
        let (proof_cm, proof_s) = abdlop.commit_full_partial(&prepared_m, &Matrix::from_vec(value_coeff_form.clone()));
 
        // let [proof_ck_top, proof_ck_y2, proof_ck_g, proof_ck_theta, proof_ck_theta_g1 ]= proof_ck_vec.as_slice() else {
            // panic!("Proof CK length not matched");
        // };
        let u_vec = proof_cm.slice_into_custom(bdlop.ck_binding_height_n);
        let u0 = &u_vec[0];
        let u_y2 = &u_vec[u_vec.len()-2];
        let u_masking_g = &u_vec[u_vec.len()-1];
        // let u_bin = &u_vec[1..u_vec.len()-2];
        assert_eq!(u_vec.len()+1, proof_ck_vec.len());

        // NO rejection sampliong d=1024, 10ms

        //  Sample random binary challenge matrix
        // A,B,B'a,B''a,com0,com3, u0,u_y2,u_masking_g

        // let mut combined = Vec::with_capacity(4249184);
        // A,A_a || b,b_y2,b_g, b_theta, b_g1 || u0,com0 || com3, u_y2,u_masking_g, u_theta, beta^2 [underestimation is supported by overestimation of kappa+lambda+2]
        const TOTAL_SIZE: usize = 2*kappa*(kappa+lambda+3)*POLY_SIZE + 5*POLY_SIZE + 2*kappa*POLY_SIZE + 5*POLY_SIZE ; //Corase estimation
        let mut combined : Box<[u8; TOTAL_SIZE]> = Box::new([0;TOTAL_SIZE]);
        let mut writer = Cursor::new(&mut combined[..]);

        to_io(&oricm1_ck_top, &mut writer).unwrap();
        to_io(&oricm1_ck_m3, &mut writer).unwrap();
        // to_io(proof_ck_top, &mut writer).unwrap();
        to_io(proof_ck_y2, &mut writer).unwrap();
        to_io(proof_ck_g, &mut writer).unwrap();
        to_io(proof_ck_g1, &mut writer).unwrap();
        to_io(&oricm1_com0, &mut writer).unwrap();
        to_io(&oricm1_com3, &mut writer).unwrap();
        to_io(u0, &mut writer).unwrap();
        to_io(u_y2, &mut writer).unwrap();
        to_io(u_masking_g, &mut writer).unwrap();
        to_io(&MAX_COEFF_BETA, &mut writer).unwrap();
        let total_len =writer.position() as usize;

        // let output: Vec<u8> = postcard::to_iter(&oricm1_ck_top).unwrap()
        let bin_challenge_mat;
        let bin_challenge_mat_poly_sigma;

        let mut hasher = Shake256::default();
        hasher.update(&combined[..total_len]); //Better to use serialzed byte instead. String for convenient.
        let mut hashed = hasher.clone().finalize_xof();


        // let (bin_challenge_mat, bin_challenge_mat_poly_sigma) = Poly::random_binary_vector(1); 
        // (bin_challenge_mat, bin_challenge_mat_poly_sigma) = Poly::random_binary_vector_fs(MAX_COEFF_BETA, &mut hashed); 
        
        let bin_challenge_mat_poly_sigma_temp;
        (bin_challenge_mat, bin_challenge_mat_poly_sigma_temp) = Poly::random_binary_vector_fs_split1(MAX_COEFF_BETA, &mut hashed); 

     
        const SEC_PARAM: usize = 256;
        let mut poly_coeff = vec![Poly_U128::ZERO;DEGREE];
        // assert_eq!(bin_challenge_mat.len(), DEGREE);
        assert!(bin_challenge_mat.len() >= 256);
        assert!(DEGREE >= 256); //Security level for 128

        // let mut value_flatten =  (value).flatten_ref();
        // value_flatten.append(&mut theta_poly.flatten_ref());

        (&mut poly_coeff[..SEC_PARAM]).into_par_iter().enumerate().for_each(|(i, poly_coeff_mut) | {
            // println!("{}??",bin_challenge_mat.len());
            assert_eq!(bin_challenge_mat[i].len(), MAX_COEFF_BETA*DEGREE);
            assert_eq!(value_flatten.len(), MAX_COEFF_BETA*DEGREE);
            *poly_coeff_mut = PolyCanon::inner_product(bin_challenge_mat[i].clone(), value_flatten.clone());
        });

        let riv_poly = Poly::new(poly_coeff.try_into().unwrap());
        let z2 = &y2 + &riv_poly;


        if Sampler::reject_0(&Matrix::from_vec(vec![z2.clone()]), &Matrix::from_vec(vec![riv_poly.clone()]), SIGMA_POA_COMPACT_S2 as f64) && is_rejection_sampling {
            rejected_time +=1;
            continue;
        }


        bin_challenge_mat_poly_sigma = Poly::random_binary_vector_fs_split2(MAX_COEFF_BETA,bin_challenge_mat_poly_sigma_temp); 

        //No rejection sampling number

        // NOTE: client challenge
        // Sample linear combination challenge dj, d'j
        let combined: Vec<_> = vec![];
        let combined = to_extend(&z2, combined).unwrap();
        hasher.update(&combined);
        let mut hashed = hasher.clone().finalize_xof();
        let dj_vec = Poly::random_zq_vec_fs(SEC_PARAM, &mut hashed);
        let dj_vec_prime_binaryvbin = Poly::random_zq_vec_fs(MAX_COEFF_BETA, &mut hashed);
        let dj_vec_prime_compose = Poly::random_zq_vec_fs(DEGREE, &mut hashed);

        let x_ez_term = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_static, &Matrix::from_vec(vec![z2.clone()]));
        let x_ey_term = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_static, &Matrix::from_vec(vec![y2.clone()]));
        let x_rl_term = ABDLOP::compute_product_sum(&dj_vec, &bin_challenge_mat_poly_sigma, &Matrix::from_vec(value_coeff_form.clone()));
        let x_vbin_binaryterm =ABDLOP::compute_product_sum_varquad_custom_vbinvbin(&dj_vec_prime_binaryvbin, &value_coeff_form);
        let x_compose =compute_custom_xcompose(&dj_vec_prime_compose, &POWER_OF_2_COEFF_POLY_VERIFIER_COMPACT, &SIGMA_ONE_COMPACT, &value_coeff_form, &value);

        let h_poly = x_rl_term.clone() +  x_ey_term.clone() + x_ez_term.neg() + x_compose +  x_vbin_binaryterm + masking_g.clone();
        // assert_eq!(h_poly.canonical_repr()[0],Zq::zero());
        // + x_bound_diff + x_theta_binaryterm + masking_g.clone();

        let mut outer_hasher = hasher;

 
        '_inner: loop{        
            // // ZKProof of opening for ABDLOP
            // w_1 = A_a y1, w2 = A_bdlop y3

            // Compute Responses
            let y1: Vec<Poly> = (0..proof_ck_top.val[0].len()).into_par_iter().map(|_| Poly::random_discrete_gaussian(common_static::SIGMA_POA_COMPACT_S1)).collect() ;
            let y1: Matrix<Poly> = Matrix::from_vec(y1);
            let y_bin_vec: Vec<Poly> = (0..MAX_COEFF_BETA).into_par_iter().map(|_| Poly::random_discrete_gaussian(common_static::SIGMA_POA_COMPACT_S0)).collect() ;
            let y0 = Matrix::from_vec(y_bin_vec.clone());
            let y3: Vec<Poly> = (0..oricm1_ck_top.val[0].len()).into_par_iter().map(|_| Poly::random_discrete_gaussian(common_static::SIGMA_POA_COMPACT_S3)).collect() ;
            let y3= Matrix::from_vec(y3);
            let w_1 =  proof_ck_top * &y1 + &abdlop.ck_atjai * &y0;
            let w_2 =  &oricm1_ck_top * &y3;

            //Start of Theta 2
            //y_masking_g = -Bg y1 because it is 1 of g1 and y is defined as -Bg y1
            //These y are defined specifically for g1_poly and g_0 only
            let y_masking_g = (proof_ck_g * &y1).neg().to_item_t();
            let y_value =  (&oricm1_ck_m3 * &y3).neg().to_item_t();
            let y_y2 =  (proof_ck_y2 * &y1).neg().to_item_t();

            let g1_poly = y_masking_g.clone(); //y_masking_g = -Bg y1 because it is 1 of g1 and y is defined as -Bg y1

            let ry_yv_ytheta = ABDLOP::compute_product_sum(&dj_vec, &bin_challenge_mat_poly_sigma, &Matrix::from_vec(y_bin_vec.clone()));
            let ey_y2_opening = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_static, &Matrix::from_vec(vec![y_y2.clone()]));
            //  ABDLOP::compute_product_sum_varquad_custom(&dj_vec_prime_binaryvbin, &value_coeff_form, &y_bin_vec);
            let g1_poly = g1_poly + ey_y2_opening + ry_yv_ytheta; //Add welformess of z2 where z2 = y2 + R(v||theta)

            //Add Binary of vbin
            let vbin_g1 = ABDLOP::compute_product_sum_varquad_custom(&dj_vec_prime_binaryvbin, &value_coeff_form, &y_bin_vec);
            let g1_poly = g1_poly + vbin_g1;

            //Add Compose
            let compose_g1 = compute_custom_xcompose(&dj_vec_prime_compose, &POWER_OF_2_COEFF_POLY_VERIFIER_COMPACT, &SIGMA_ONE_COMPACT, &y_bin_vec, &y_value);
            let g1_poly = g1_poly + compose_g1;

            let g_0 = ABDLOP::compute_product_sum_varquad_custom_vleftover(&dj_vec_prime_binaryvbin,  &y_bin_vec);
            drop(y_masking_g);
            drop(y_value);
            drop(y_y2);
            let left_over_v = g_0.clone() + (proof_ck_g1 * &y1).to_item_t();
            let u_g1 = (proof_ck_g1 * &proof_s).to_item_t() + g1_poly.clone();
            // proof_cm = Matrix::v_stack(&proof_cm, &Matrix::from_vec(vec![u_g1.clone()]));

            //end of theta2

            // Challenge from client
            //w1,w2 || h, v, u_g1 ;
            const TOTAL_SIZE: usize = 2*kappa*POLY_SIZE + 3*POLY_SIZE; //Corase estimation
            let mut combined : Box<[u8; TOTAL_SIZE]> = Box::new([0;TOTAL_SIZE]);
            let mut writer = Cursor::new(&mut combined[..]);
            to_io(&w_1, &mut writer).unwrap();
            to_io(&w_2, &mut writer).unwrap();
            to_io(&h_poly, &mut writer).unwrap();
            to_io(&left_over_v, &mut writer).unwrap();
            to_io(&u_g1, &mut writer).unwrap();
            let total_len =writer.position() as usize;
            let mut inner_hasher = outer_hasher.clone();
            inner_hasher.update(&combined[..total_len]); //Better to use serialzed byte instead. String for convenient.
            let mut hashed = inner_hasher.finalize_xof();
            let challenge = Poly::random_binomial_fs(&mut hashed);
            // let challenge = ABDLOP::get_challenge();

            let z1_v = &proof_s * &challenge;
            let z1 = &y1 + &z1_v;
            let z3_v =  ori_r * &challenge;
            let z3 = &y3 + &z3_v;


            // no rejection sampling nuber

            if (Sampler::reject_0(&z1, &z1_v, common_static::SIGMA_POA_COMPACT_S1 as f64) || Sampler::reject_0(&z3, &z3_v, common_static::SIGMA_POA_COMPACT_S3 as f64)) && is_rejection_sampling {
                rejected_time +=1;
                continue '_inner;
            }

            let z0_v = Matrix::from_vec(value_coeff_form.clone().into_par_iter().map(|item| item * challenge.clone()).collect());
            // let z0_v = Matrix::from_vec(value_coeff_form.clone()).map(|item| item * challenge.clone());
            let z0 = &y0 + &z0_v;

            if (Sampler::reject_0(&z0, &z0_v, common_static::SIGMA_POA_COMPACT_S0 as f64)) && is_rejection_sampling {
                rejected_time +=1;
                continue '_inner;
            }


    

            return ProofOfAssetCompact {
                u0: u0.clone(),
                u_y2: u_y2.clone(),
                u_masking_g: u_masking_g.clone(),
                u_g1: u_g1,
                bin_challenge_mat_poly_sigma: bin_challenge_mat_poly_sigma,
                dj_vec: dj_vec,
                dj_vec_binary: dj_vec_prime_binaryvbin,
                dj_vec_compose: dj_vec_prime_compose,
                challenge: challenge,
                z2: z2,
                z0: z0,
                z1: z1,
                z3: z3,
                w1: w_1,
                w2: w_2,
                v : left_over_v,
                h : h_poly
            };


        }
    }

}

pub fn gen_proof_of_asset_compact_parallel (
    bdlop: &ABDLOP,     // original (qpadl) parameters used to produce cm1,r1
    abdlop: &ABDLOP,    // Proof Parameter
    ori_commit: &Matrix<Poly>, //public commitment
    ori_r: &Matrix<Poly>,  // witness randomness used in original commitment
    value: &Poly, //witness value
    is_rejection_sampling: bool
) -> ProofOfAssetCompact{
    let mut rejected_time =0;
    let value_coeff_form = value.bin_repr_coeff_compact(MAX_COEFF_BETA);
    let proof_ck_vec =abdlop.ck.slice_into_custom(abdlop.ck_binding_height_n);
    let  proof_ck_top = &proof_ck_vec[0];
    let  proof_ck_y2 = &proof_ck_vec[proof_ck_vec.len()-3];
    let  proof_ck_g = &proof_ck_vec[proof_ck_vec.len()-2];
    let  proof_ck_g1 = &proof_ck_vec[proof_ck_vec.len()-1];
    let proof_ck_vbin_compact = &proof_ck_vec[1..proof_ck_vec.len()-2];

    let (oricm1_com0,_oricm1_com1,_oricm1_com2, oricm1_com3) = ori_commit.slice_into_4(bdlop.ck_binding_height_n);
    let (oricm1_ck_top, _oricm1_ck_m1, _oricm1_ck_m2, oricm1_ck_m3 )= bdlop.ck.slice_into_4(bdlop.ck_binding_height_n);
    let value_flatten: Vec<Zq> = value_coeff_form.iter().map(|value_coeff| value_coeff.flatten_ref()).collect::<Vec<Vec<Zq>>>().into_iter().flatten().collect();

    '_outer: loop {    
        
        let masking_g = Poly::random_constant_unmasked(); 
        assert_eq!(masking_g.canonical_repr()[0],Poly_U128::ZERO);   
        let y2 = Poly::random_discrete_gaussian(SIGMA_POA_COMPACT_S2);

        let mut messages = vec![];
        // messages.append(&mut value_coeff_form.clone());
        messages.append(&mut vec![y2.clone(), masking_g.clone()]);
        let prepared_m = abdlop.prepare_message_custom(messages);
        let (proof_cm, proof_s) = abdlop.commit_full_partial(&prepared_m, &Matrix::from_vec(value_coeff_form.clone()));
 
        // let [proof_ck_top, proof_ck_y2, proof_ck_g, proof_ck_theta, proof_ck_theta_g1 ]= proof_ck_vec.as_slice() else {
            // panic!("Proof CK length not matched");
        // };
        let u_vec = proof_cm.slice_into_custom(bdlop.ck_binding_height_n);
        let u0 = &u_vec[0];
        let u_y2 = &u_vec[u_vec.len()-2];
        let u_masking_g = &u_vec[u_vec.len()-1];
        // let u_bin = &u_vec[1..u_vec.len()-2];
        assert_eq!(u_vec.len()+1, proof_ck_vec.len());

        // NO rejection sampliong d=1024, 10ms

        //  Sample random binary challenge matrix
        // A,B,B'a,B''a,com0,com3, u0,u_y2,u_masking_g

        // let mut combined = Vec::with_capacity(4249184);
        // A,A_a || b,b_y2,b_g, b_theta, b_g1 || u0,com0 || com3, u_y2,u_masking_g, u_theta, beta^2 [underestimation is supported by overestimation of kappa+lambda+2]
        const TOTAL_SIZE: usize = 2*kappa*(kappa+lambda+3)*POLY_SIZE + 5*POLY_SIZE + 2*kappa*POLY_SIZE + 5*POLY_SIZE ; //Corase estimation
        let mut combined : Box<[u8; TOTAL_SIZE]> = Box::new([0;TOTAL_SIZE]);
        let mut writer = Cursor::new(&mut combined[..]);

        to_io(&oricm1_ck_top, &mut writer).unwrap();
        to_io(&oricm1_ck_m3, &mut writer).unwrap();
        // to_io(proof_ck_top, &mut writer).unwrap();
        to_io(proof_ck_y2, &mut writer).unwrap();
        to_io(proof_ck_g, &mut writer).unwrap();
        to_io(proof_ck_g1, &mut writer).unwrap();
        to_io(&oricm1_com0, &mut writer).unwrap();
        to_io(&oricm1_com3, &mut writer).unwrap();
        to_io(u0, &mut writer).unwrap();
        to_io(u_y2, &mut writer).unwrap();
        to_io(u_masking_g, &mut writer).unwrap();
        to_io(&MAX_COEFF_BETA, &mut writer).unwrap();
        let total_len =writer.position() as usize;

        // let output: Vec<u8> = postcard::to_iter(&oricm1_ck_top).unwrap()
        let bin_challenge_mat;
        let bin_challenge_mat_poly_sigma;

        let mut hasher = Shake256::default();
        hasher.update(&combined[..total_len]); //Better to use serialzed byte instead. String for convenient.
        let mut hashed = hasher.clone().finalize_xof();


        // let (bin_challenge_mat, bin_challenge_mat_poly_sigma) = Poly::random_binary_vector(1); 
        // (bin_challenge_mat, bin_challenge_mat_poly_sigma) = Poly::random_binary_vector_fs(MAX_COEFF_BETA, &mut hashed); 
        
        let bin_challenge_mat_poly_sigma_temp;
        (bin_challenge_mat, bin_challenge_mat_poly_sigma_temp) = Poly::random_binary_vector_fs_split1(MAX_COEFF_BETA, &mut hashed); 

     
        const SEC_PARAM: usize = 256;
        let mut poly_coeff = vec![Poly_U128::ZERO;DEGREE];
        // assert_eq!(bin_challenge_mat.len(), DEGREE);
        assert!(bin_challenge_mat.len() >= 256);
        assert!(DEGREE >= 256); //Security level for 128

        // let mut value_flatten =  (value).flatten_ref();
        // value_flatten.append(&mut theta_poly.flatten_ref());

        (&mut poly_coeff[..SEC_PARAM]).into_par_iter().enumerate().for_each(|(i, poly_coeff_mut) | {
            // println!("{}??",bin_challenge_mat.len());
            assert_eq!(bin_challenge_mat[i].len(), MAX_COEFF_BETA*DEGREE);
            assert_eq!(value_flatten.len(), MAX_COEFF_BETA*DEGREE);
            *poly_coeff_mut = PolyCanon::inner_product(bin_challenge_mat[i].clone(), value_flatten.clone());
        });

        let riv_poly = Poly::new(poly_coeff.try_into().unwrap());
        let z2 = &y2 + &riv_poly;


        if Sampler::reject_0(&Matrix::from_vec(vec![z2.clone()]), &Matrix::from_vec(vec![riv_poly.clone()]), SIGMA_POA_COMPACT_S2 as f64) && is_rejection_sampling {
            rejected_time +=1;
            continue;
        }


        bin_challenge_mat_poly_sigma = Poly::random_binary_vector_fs_split2(MAX_COEFF_BETA,bin_challenge_mat_poly_sigma_temp); 


        // NOTE: client challenge
        // Sample linear combination challenge dj, d'j
        let combined: Vec<_> = vec![];
        let combined = to_extend(&z2, combined).unwrap();
        hasher.update(&combined);
        let mut hashed = hasher.clone().finalize_xof();
        let dj_vec = Poly::random_zq_vec_fs(SEC_PARAM, &mut hashed);
        let dj_vec_prime_binaryvbin = Poly::random_zq_vec_fs(MAX_COEFF_BETA, &mut hashed);
        let dj_vec_prime_compose = Poly::random_zq_vec_fs(DEGREE, &mut hashed);

        let x_ez_term = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_static, &Matrix::from_vec(vec![z2.clone()]));
        let x_ey_term = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_static, &Matrix::from_vec(vec![y2.clone()]));
        let x_rl_term = ABDLOP::compute_product_sum(&dj_vec, &bin_challenge_mat_poly_sigma, &Matrix::from_vec(value_coeff_form.clone()));
        let x_vbin_binaryterm =ABDLOP::compute_product_sum_varquad_custom_vbinvbin(&dj_vec_prime_binaryvbin, &value_coeff_form);
        let x_compose =compute_custom_xcompose(&dj_vec_prime_compose, &POWER_OF_2_COEFF_POLY_VERIFIER_COMPACT, &SIGMA_ONE_COMPACT, &value_coeff_form, &value);

        let h_poly = x_rl_term.clone() +  x_ey_term.clone() + x_ez_term.neg() + x_compose +  x_vbin_binaryterm + masking_g.clone();
        // assert_eq!(h_poly.canonical_repr()[0],Zq::zero());
        // + x_bound_diff + x_theta_binaryterm + masking_g.clone();

        let mut outer_hasher = hasher;

        //No rejection sampling number

        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::sync::mpsc::sync_channel;

        let done = Arc::new(AtomicBool::new(false));
        let (tx, rx) = sync_channel::<ProofOfAssetCompact>(1);

        let proof_ck_vec =Arc::new(proof_ck_vec.clone());
        let u_vec = Arc::new(u_vec.clone());
        let abdlop = Arc::new((*abdlop).clone());
        let ori_r = Arc::new((*ori_r).clone());

        // rayon::current_num_threads()
        for tid in 0..4{
            let done = Arc::clone(&done);
            let tx = tx.clone();

            let proof_ck_vec = Arc::clone(&proof_ck_vec); //Increment ref count.
            let u_vec = Arc::clone(&u_vec);
            let abdlop = Arc::clone(&abdlop);
            let ori_r = Arc::clone(&ori_r);
            let oricm1_ck_top = oricm1_ck_top.clone();
            let oricm1_ck_m3 = oricm1_ck_m3.clone();
            let dj_vec =dj_vec.clone();
            let bin_challenge_mat_poly_sigma = bin_challenge_mat_poly_sigma.clone();
            let dj_vec_prime_binaryvbin = dj_vec_prime_binaryvbin.clone();
            let value_coeff_form = value_coeff_form.clone();
            let dj_vec_prime_compose = dj_vec_prime_compose.clone();
            let proof_s= proof_s.clone();
            let h_poly = h_poly.clone();
            let outer_hasher = outer_hasher.clone();
            let z2 = z2.clone();
            rayon::spawn(move || {
                while !done.load(Ordering::Relaxed){
                    let  proof_ck_top = &proof_ck_vec[0];
                    let  proof_ck_y2 = &proof_ck_vec[proof_ck_vec.len()-3];
                    let  proof_ck_g = &proof_ck_vec[proof_ck_vec.len()-2];
                    let  proof_ck_g1 = &proof_ck_vec[proof_ck_vec.len()-1];

                    let u0 = &u_vec[0];
                    let u_y2 = &u_vec[u_vec.len()-2];
                    let u_masking_g = &u_vec[u_vec.len()-1];

                    // Compute Responses
                    let y1: Vec<Poly> = (0..proof_ck_top.val[0].len()).into_par_iter().map(|_| Poly::random_discrete_gaussian(common_static::SIGMA_POA_COMPACT_S1)).collect() ;
                    let y1: Matrix<Poly> = Matrix::from_vec(y1);
                    let y_bin_vec: Vec<Poly> = (0..MAX_COEFF_BETA).into_par_iter().map(|_| Poly::random_discrete_gaussian(common_static::SIGMA_POA_COMPACT_S0)).collect() ;
                    let y0 = Matrix::from_vec(y_bin_vec.clone());
                    let y3: Vec<Poly> = (0..oricm1_ck_top.val[0].len()).into_par_iter().map(|_| Poly::random_discrete_gaussian(common_static::SIGMA_POA_COMPACT_S3)).collect() ;
                    let y3= Matrix::from_vec(y3);
                    let w_1 =  (proof_ck_top) * &y1 + &abdlop.ck_atjai * &y0;
                    let w_2 =  &oricm1_ck_top * &y3;

                    //Start of Theta 2
                    //y_masking_g = -Bg y1 because it is 1 of g1 and y is defined as -Bg y1
                    //These y are defined specifically for g1_poly and g_0 only
                    let y_masking_g = (proof_ck_g * &y1).neg().to_item_t();
                    let y_value =  (&oricm1_ck_m3 * &y3).neg().to_item_t(); 
                    let y_y2 =  (proof_ck_y2 * &y1).neg().to_item_t();

                    let g1_poly = y_masking_g.clone(); //y_masking_g = -Bg y1 because it is 1 of g1 and y is defined as -Bg y1

                    let ry_yv_ytheta = ABDLOP::compute_product_sum(&dj_vec, &bin_challenge_mat_poly_sigma, &Matrix::from_vec(y_bin_vec.clone()));
                    let ey_y2_opening = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_static, &Matrix::from_vec(vec![y_y2.clone()]));
                    //  ABDLOP::compute_product_sum_varquad_custom(&dj_vec_prime_binaryvbin, &value_coeff_form, &y_bin_vec);
                    let g1_poly = g1_poly + ey_y2_opening + ry_yv_ytheta; //Add welformess of z2 where z2 = y2 + R(v||theta)

                    //Add Binary of vbin
                    let vbin_g1 = ABDLOP::compute_product_sum_varquad_custom(&dj_vec_prime_binaryvbin, &value_coeff_form, &y_bin_vec);
                    let g1_poly = g1_poly + vbin_g1;

                    //Add Compose
                    let compose_g1 = compute_custom_xcompose(&dj_vec_prime_compose, &POWER_OF_2_COEFF_POLY_VERIFIER_COMPACT, &SIGMA_ONE_COMPACT, &y_bin_vec, &y_value);
                    let g1_poly = g1_poly + compose_g1;

                    let g_0 = ABDLOP::compute_product_sum_varquad_custom_vleftover(&dj_vec_prime_binaryvbin,  &y_bin_vec);
                    drop(y_masking_g);
                    drop(y_value);
                    drop(y_y2);
                    let left_over_v = g_0.clone() + (proof_ck_g1 * &y1).to_item_t();
                    let u_g1 = (proof_ck_g1 * &proof_s).to_item_t() + g1_poly.clone();
                    // proof_cm = Matrix::v_stack(&proof_cm, &Matrix::from_vec(vec![u_g1.clone()]));

                    //end of theta2

                    // Challenge from client
                    //w1,w2 || h, v, u_g1 ;
                    const TOTAL_SIZE: usize = 2*kappa*POLY_SIZE + 3*POLY_SIZE; //Corase estimation
                    let mut combined : Box<[u8; TOTAL_SIZE]> = Box::new([0;TOTAL_SIZE]);
                    let mut writer = Cursor::new(&mut combined[..]);
                    to_io(&w_1, &mut writer).unwrap();
                    to_io(&w_2, &mut writer).unwrap();
                    to_io(&h_poly, &mut writer).unwrap();
                    to_io(&left_over_v, &mut writer).unwrap();
                    to_io(&u_g1, &mut writer).unwrap();
                    let total_len =writer.position() as usize;
                    let mut inner_hasher = outer_hasher.clone();
                    inner_hasher.update(&combined[..total_len]); //Better to use serialzed byte instead. String for convenient.
                    let mut hashed = inner_hasher.finalize_xof();
                    let challenge = Poly::random_binomial_fs(&mut hashed);
                    // let challenge = ABDLOP::get_challenge();

                    let z1_v = &proof_s * &challenge;
                    let z1 = &y1 + &z1_v;
                    let z3_v =  &(*ori_r) * &challenge;
                    let z3 = &y3 + &z3_v;
                    let z0_v = Matrix::from_vec(value_coeff_form.clone().into_par_iter().map(|item| item * challenge.clone()).collect());
                    // let z0_v = Matrix::from_vec(value_coeff_form.clone()).map(|item| item * challenge.clone());
                    let z0 = &y0 + &z0_v;



                    // no rejection sampling nuber

                    if (Sampler::reject_0(&z1, &z1_v, common_static::SIGMA_POA_COMPACT_S1 as f64) || Sampler::reject_0(&z3, &z3_v, common_static::SIGMA_POA_COMPACT_S3 as f64) || Sampler::reject_0(&z0, &z0_v, common_static::SIGMA_POA_COMPACT_S0 as f64)) && is_rejection_sampling {
                        // Failed
                    }
                    else{
                        let ret = ProofOfAssetCompact {
                            u0: u0.clone(),
                            u_y2: u_y2.clone(),
                            u_masking_g: u_masking_g.clone(),
                            u_g1: u_g1.clone(),
                            bin_challenge_mat_poly_sigma: bin_challenge_mat_poly_sigma.clone(),
                            dj_vec: dj_vec.clone(),
                            dj_vec_binary: dj_vec_prime_binaryvbin.clone(),
                            dj_vec_compose: dj_vec_prime_compose.clone(),
                            challenge: challenge.clone(),
                            z2: z2.clone(),
                            z0: z0.clone(),
                            z1: z1.clone(),
                            z3: z3.clone(),
                            w1: w_1.clone(),
                            w2: w_2.clone(),
                            v : left_over_v.clone(),
                            h : h_poly.clone()
                        };

                        if !done.swap(true, Ordering::Relaxed){
                            let _ = tx.send(ret);
                        }
                    }
                }
            });
        }
        drop(tx);

        let result = rx.recv().expect("no attemp succeeded");
        return result;
    }

}

pub fn verify_proof_of_asset_compact(proof: ProofOfAssetCompact, bdlop: &ABDLOP, abdlop: &ABDLOP, ori_commit: &Matrix<Poly> ) -> bool{
    const SEC_PARAM: usize = 256;
    let proof_ck_vec =abdlop.ck.slice_into_custom(abdlop.ck_binding_height_n);
    let proof_ck_top = &proof_ck_vec[0];
    let proof_ck_y2 = &proof_ck_vec[proof_ck_vec.len()-3];
    let proof_ck_g = &proof_ck_vec[proof_ck_vec.len()-2];
    let proof_ck_g1 = &proof_ck_vec[proof_ck_vec.len()-1];
    let proof_ck_abdlop = &abdlop.ck_atjai;
    // let proof_ck_vbin_compact = &proof_ck_vec[1..proof_ck_vec.len()-2];
    
    let (oricm1_com0,oricm1_com1,oricm1_com2, oricm1_com3) = ori_commit.slice_into_4(bdlop.ck_binding_height_n);
    let (oricm1_ck_top, oricm1_ck_m1, oricm1_ck_m2, oricm1_ck_m3 )= bdlop.ck.slice_into_4(bdlop.ck_binding_height_n);

    let mut bit_sum = true;

    //Check FS
    let combined = vec![];
    let combined = to_extend(&oricm1_ck_top, combined).unwrap();
    let combined = to_extend(&oricm1_ck_m3, combined).unwrap();
    // let combined = to_extend(&proof_ck_top, combined).unwrap();
    let combined = to_extend(&proof_ck_y2, combined).unwrap();
    let combined = to_extend(&proof_ck_g, combined).unwrap();
    let combined = to_extend(&proof_ck_g1, combined).unwrap();
    let combined = to_extend(&oricm1_com0, combined).unwrap();
    let combined = to_extend(&oricm1_com3, combined).unwrap();
    let combined = to_extend(&proof.u0, combined).unwrap();
    let combined = to_extend(&proof.u_y2, combined).unwrap();
    let combined = to_extend(&proof.u_masking_g, combined).unwrap();
    let combined = to_extend(&MAX_COEFF_BETA, combined).unwrap();
    let mut hasher = Shake256::default();
    hasher.update(&combined); //Better to use serialzed byte instead. String for convenient.
    let mut hashed = hasher.clone().finalize_xof();
    let (_, bin_challenge_mat_poly_sigma) = Poly::random_binary_vector_fs(MAX_COEFF_BETA, &mut hashed);

    bit_sum = bit_sum && (bin_challenge_mat_poly_sigma == proof.bin_challenge_mat_poly_sigma);
    assert!(bit_sum, "FS failed");

    let combined: Vec<_> = vec![];
    let combined = to_extend(&proof.z2, combined).unwrap();
    hasher.update(&combined);
    let mut hashed = hasher.clone().finalize_xof();
    let dj_vec = Poly::random_zq_vec_fs(SEC_PARAM, &mut hashed);
    
    let dj_vec_prime_binarytheta = Poly::random_zq_vec_fs(MAX_COEFF_BETA, &mut hashed);
    let dj_vec_prime_bounddiff = Poly::random_zq_vec_fs(DEGREE, &mut hashed);
    bit_sum = bit_sum && (proof.dj_vec == dj_vec);
    bit_sum = bit_sum && (proof.dj_vec_binary == dj_vec_prime_binarytheta);
    bit_sum = bit_sum && (proof.dj_vec_compose == dj_vec_prime_bounddiff);
    assert!(bit_sum, "FS random linear challenge failed");

    let combined: Vec<_> = vec![];
    let combined = to_extend(&proof.w1, combined).unwrap();
    let combined = to_extend(&proof.w2, combined).unwrap();
    let combined = to_extend(&proof.h, combined).unwrap();
    let combined = to_extend(&proof.v, combined).unwrap();
    let combined = to_extend(&proof.u_g1, combined).unwrap();
    hasher.update(&combined);
    let mut hashed = hasher.finalize_xof();
    let challenge = Poly::random_binomial_fs( &mut hashed);
    bit_sum = bit_sum && (proof.challenge == challenge);
    assert!(bit_sum, "FS final challenge");

    //Verification
    // Equation (a)
    let z1_max_bound = (SIGMA_POA_COMPACT_S1 as f64 * ((2*(abdlop.randomness_vector_dimension_k)*DEGREE) as f64).sqrt() ).to_i128().unwrap();
    bit_sum = bit_sum && (proof.z1.norm_l2() <=  z1_max_bound);
    assert!(bit_sum, "Bound error challenge");


    let z0_max_bound = (SIGMA_POA_COMPACT_S1 as f64 * ((2*(MAX_COEFF_BETA)*DEGREE) as f64).sqrt() ).to_i128().unwrap();
    bit_sum = bit_sum && (proof.z0.norm_l2() <=  z0_max_bound);
    assert!(bit_sum, "Bound error challenge");


    let z3_max_bound = (common_static::SIGMA_POA_COMPACT_S3 as f64 * ((2*(bdlop.randomness_vector_dimension_k)*DEGREE) as f64).sqrt() ).to_i128().unwrap();
    bit_sum = bit_sum && (proof.z3.norm_l2() <=  z3_max_bound);
    assert!(bit_sum, "Bound error challenge");


    // Equation (b)

    // println!("canonincal_poly:{:?}", proof.z2.into_canonical_poly().coeff);
    // println!("z2_max_bound:{}, proof.z2.norm_linf:{}", *Z2_MAX_BOUND, proof.z2.norm_linf());
    bit_sum = bit_sum && (proof.z2.norm_l2_int_square().sqrt().to_u128().unwrap() <= *Z2_MAX_BOUND);

    // bit_sum = bit_sum && (proof.z2.norm_linf() <= *Z2_MAX_BOUND);
    //This trigger under random >64 bit message.

    // Equation (c)
    bit_sum = bit_sum && (proof.h.canonical_repr()[0] == Poly_U128::ZERO);

    // Equation (d)
    bit_sum = bit_sum && (proof.w2 + &oricm1_com0 * &proof.challenge == &oricm1_ck_top * &proof.z3);

    bit_sum = bit_sum && (proof.w1 + &proof.u0 * &proof.challenge == proof_ck_top * &proof.z1 + proof_ck_abdlop * &proof.z0);

    //(e)
    let f = &proof.u_g1 * &challenge + (proof_ck_g1 * &proof.z1).to_item_t().neg();

    let z_bin_vec = {
        let res_vec = proof.z0.to_vec();
        res_vec
    };
    let z_masking_g =(&proof.u_masking_g * &challenge + (proof_ck_g * &proof.z1).neg()).to_item_t();
    let z_y2 = (&proof.u_y2 * &challenge + (proof_ck_y2 * &proof.z1).neg()).to_item_t();
    let z_v = (&oricm1_com3 * &challenge + (&oricm1_ck_m3 * &proof.z3).neg()).to_item_t();
    let f = &proof.u_g1 * &challenge + (proof_ck_g1 * &proof.z1).to_item_t().neg();

    let z_vbin_wellformness = ABDLOP::compute_product_sum_varquad_custom_zopening_vbin(&challenge,&proof.dj_vec_binary, &z_bin_vec);

    let z_compose_wellformness = &challenge * &compute_custom_xcompose(&proof.dj_vec_compose, &POWER_OF_2_COEFF_POLY_VERIFIER_COMPACT, &SIGMA_ONE_COMPACT, &z_bin_vec, &z_v);

    let middle_r = ABDLOP::compute_product_sum(&dj_vec, &bin_challenge_mat_poly_sigma, &( Matrix::from_vec(z_bin_vec)));
    let middle_e = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_static, &Matrix::from_vec(vec![z_y2.clone()]) );
    let z2_wellformness_opening = &challenge * &(middle_r+middle_e);

    let ez = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_static, &Matrix::from_vec(vec![proof.z2.clone()]));
    let masking_g_constant = &z_masking_g * &challenge;
    // assert_eq!();
    bit_sum = bit_sum && ( z2_wellformness_opening + z_vbin_wellformness + z_compose_wellformness + masking_g_constant  + (&challenge * &challenge * (proof.h.clone()+ ez.clone())).neg() + proof.v.neg() + f.neg() == Poly::zero());

    return bit_sum;
}


#[cfg(test)]
mod tests {
    use ark_ff::One;
    use crate::common_trait::SigmaReflect;

    use crate::proof_of_asset_compact::{MAX_COEFF_BETA, MAX_VALUE_BOUND, gen_proof_of_asset_compact_parallel};
    use crate::{commitment::ABDLOP, polynomial::Poly, proof_of_asset_compact::verify_proof_of_asset_compact};

    use super::gen_proof_of_asset_compact;

    #[test]
    fn test_sigma_reflect_1(){
        let poly1 = Poly::one();
        assert_eq!(poly1.clone(),poly1.sigma_reflect());
    }

    // #[test]
    // fn test_poa_compact_random_exact() {
    //     let (bdlop, _, _, _, _) = ABDLOP::new_random_instance();
    //     let (abdlop, _, _, _, _) = ABDLOP::new_random_instance_custom(3 + MAX_COEFF_BETA); //2 for ABDLOP, y2,g, BETA, g1
    //     use num_traits::pow;

    //     {
    //         //Correct
    //         let values = [0, 5, 0];
    //         let _ = Poly::random_u64();
    //         let message: Poly = Poly::random_withmax(10 as u128);
    //         let m_vec = bdlop.prepare_qpadl_message(message.clone());
    //         let (ori_cm, ori_r) = bdlop.commit(&m_vec);
    //         let proof = gen_proof_of_asset_compact(&bdlop, &abdlop, &ori_cm, &ori_r, &message, false);
    //         assert!(verify_proof_of_asset_compact(proof, &bdlop, &abdlop, &ori_cm));
    //     }
    // }

    #[test]
    fn test_poa_compact_random_exact2(){
        let (bdlop, _, _, _ ,_)= ABDLOP::new_random_instance();
        let (abdlop, _,_,_,_)= ABDLOP::new_random_instance_custom_twomessage(3, MAX_COEFF_BETA); //2 for ABDLOP, y2,g, BETA, g1
        // use num_traits::pow;

        {
            //Correct
            let message: Poly = Poly::random_withmax((u64::MAX-1).try_into().unwrap());
            let m_vec = bdlop.prepare_qpadl_message(message.clone());
            let (ori_cm, ori_r) = bdlop.commit(&m_vec);
            let proof = gen_proof_of_asset_compact(&bdlop, &abdlop, &ori_cm, &ori_r, &message, false);
            assert!(verify_proof_of_asset_compact(proof, &bdlop, &abdlop, &ori_cm));
        }

        {
            //False
            let message = Poly::random_u128_guarantee(); 
            let m_vec = bdlop.prepare_qpadl_message(message.clone());
            let (ori_cm, ori_r) = bdlop.commit(&m_vec);
            let proof = gen_proof_of_asset_compact(&bdlop, &abdlop, &ori_cm, &ori_r, &message, false); //Rejection sampling wont work, disable it since the secret message value is too big.
            assert!(!verify_proof_of_asset_compact(proof, &bdlop, &abdlop, &ori_cm));
        }

        {
            let message: Poly = Poly::random_fixed_negative();
            println!("message_coeff: {:?}", message.into_canonical_poly().coeff);
            let m_vec = bdlop.prepare_qpadl_message(message.clone());
            let (ori_cm, ori_r) = bdlop.commit(&m_vec);
            let proof = gen_proof_of_asset_compact(&bdlop, &abdlop, &ori_cm, &ori_r, &message, false);
            assert!(!verify_proof_of_asset_compact(proof, &bdlop, &abdlop, &ori_cm));
        }
    }



}
