use std::hint::black_box;
use std::time::Duration;
use criterion::{criterion_group, criterion_main, Criterion};
use padl_pq::common_static;
use padl_pq::common_static::MAX_COEFF_BETA;
use padl_pq::proof_of_asset_compact::gen_proof_of_asset_compact_parallel;
// use crypto_bigint::CheckedMul;
// use crypto_bigint::Constants;
// use crypto_bigint::U128;

use std::str::FromStr;
use rug::{Integer};
// use ::padl_pq::sampler_ddll::SAMPLER as SAMPLER_DDLL;
use ::padl_pq::common::*;
use padl_pq::common_static::MODULUS_SQRT_ZQ;
use padl_pq::common_trait::SigmaReflect;
use std::ops::Neg;
use rand::Rng;
// use rand_old::rngs::ThreadRng;
// use rand_old::thread_rng as RngOld;
use num_traits::{One,Zero};
use rayon::prelude::*;
use ::padl_pq::common::MODULUS;
// use ::padl_pq::common_static::BM_TWIDDLE_NON_U128;
// use ::padl_pq::common_static::MODULUS_U128;
use ::padl_pq::common_static::BM_TWIDDLE_NON_ZQ;

use sha3::{Sha3_256, Digest as Sha3_Digest};

use::padl_pq::commitment::ABDLOP;
// use ::padl_pq::polynomial_naive::PolyNonMon;
use ::padl_pq::polynomial::Poly;
use ::padl_pq::polynomial::PolyCanon;
use ::padl_pq::polynomial::Poly_U128;
// use ::padl_pq::common::*;
use ::padl_pq::matrix::Matrix;
use ark_ff::Field;
use ark_ff::{Fp, Fp128, MontBackend, MontConfig};
use ::padl_pq::common_static::{Zq};

use padl_pq::sampler::Sampler;

// This discrete gaussian uses FACCT and DDLL13.
// See www.github.com/chancehudson/discrete-gaussian
use discrete_gaussian::k_from_theta;
use discrete_gaussian::sample_vartime_k;

fn matrix_l2_norm_sqr (mat: &Matrix<Poly>) -> i128{
    assert_eq!(mat.col_n, 1);
    let mut norm_sum = 0;
    for row_index in 0..mat.row_m{
        norm_sum += mat.val[row_index][0].into_canonical_poly().l2_norm_sqr();
    }
    norm_sum
}


// Polymul assumiing we are alreayd in the ntt domain.
fn test_fn_naive (n: &[u64;DEGREE], m: &[u64;DEGREE]) -> [u64;DEGREE]{
    let mut temp: [u64; DEGREE] = [0; DEGREE];
    //NOTE: Currently only support BASEMUL_DEGREE==2
    for i in 0..(DEGREE/BASEMUL_DEGREE){
        // Perform base multiplication here. We do schoolbook.
        // Then we do polynomial modulo reduction
        let final_red_amount = ((n[i*BASEMUL_DEGREE + 1] as u128)*(m[i*BASEMUL_DEGREE + 1] as u128) % MODULUS) * (BM_TWIDDLE_NON[i] as u128);
        let zero_place = (n[i*BASEMUL_DEGREE] as u128)*(m[i*BASEMUL_DEGREE] as u128);
        temp[i*BASEMUL_DEGREE] = ((zero_place  + final_red_amount) % MODULUS) as u64;
        temp[i*BASEMUL_DEGREE + 1] = (
            (
                (n[i*BASEMUL_DEGREE + 1] as u128)*(m[i*BASEMUL_DEGREE] as u128) + 
                (n[i*BASEMUL_DEGREE] as u128) * (m[i*BASEMUL_DEGREE + 1] as u128) 
            ) %(MODULUS)
        ) as u64    
    }
    temp
}

fn test_fn_naive_bigint_3arkwork(n: &[Zq;DEGREE], m: &[Zq;DEGREE]) -> [Zq;DEGREE]{
    // Start with bigintcrypto for mult then 
    let mut temp: [Zq; DEGREE] = [Zq::ZERO; DEGREE];
    //NOTE: Currently only support BASEMUL_DEGREE==2
    for i in 0..(DEGREE/BASEMUL_DEGREE){
        // Perform base multiplication here. We do schoolbook.
        // Then we do polynomial modulo reduction
        let final_red_amount = (n[i*BASEMUL_DEGREE + 1]) * (&m[i*BASEMUL_DEGREE + 1] ) * (BM_TWIDDLE_NON_ZQ[i]); 
        let zero_place = (n[i*BASEMUL_DEGREE]) * (&m[i*BASEMUL_DEGREE]);
        temp[i*BASEMUL_DEGREE] = (zero_place + (&final_red_amount));
        temp[i*BASEMUL_DEGREE + 1] = (
                (n[i*BASEMUL_DEGREE + 1]) * (&m[i*BASEMUL_DEGREE]) + (
                &(n[i*BASEMUL_DEGREE]) * (&m[i*BASEMUL_DEGREE + 1]))
        );
    }
    temp
}


fn test_balance(com_vec: &Vec<Matrix<Poly>>, r_sum: &Matrix<Poly>, bdlop: &ABDLOP, is_prove_only: bool){
    let mut com_sum = Matrix::from_vec(vec![Poly::zero(); com_vec[0].row_m]);
    for com in com_vec{
        com_sum  = &com_sum + com;
    }
    // let com_sum = com_vec.iter().reduce(|acc, item| &(acc+item)).unwrap();
    loop {
        let r = (0..bdlop.randomness_vector_dimension_k).map(|_| Poly::random_binomial()).collect();
        let pob_y  = Matrix::from_vec(r);
    
        let (ck_top, ck_m1, ck_m2, ck_m3) = bdlop.ck.slice_into_4(bdlop.ck_binding_height_n);

        let w = &ck_top * &pob_y;
        let u = &ck_m3 * &pob_y;
    
        // let mut c1_byte = Vec::new();
        let w_string = serde_json::to_string(&w).unwrap();
        let u_string = serde_json::to_string(&u).unwrap();
        let combined = w_string + &u_string;
    
        let mut hasher = Sha3_256::new();
        hasher.update(combined); //Better to use serialzed byte instead. String for convenient.
        let hashed = hasher.finalize().to_vec();
    
        let challenge = Poly::random_binomial();
    
        let cr = &(r_sum * &challenge);
        let z = &pob_y + &cr;
    
        if Sampler::reject_0(&z.clone(),&cr, 27000f64) {
            continue;
        }
    
        if is_prove_only{
            return;
        }
    
        // Az =? w+ ccom0
        let num = matrix_l2_norm_sqr(&z);
        assert!(num>1);
        let az = &ck_top * &z;
        let (ori_ar,ori_com1_m,ori_com2_sqrtm, ori_com3_m) = com_sum.slice_into_4(bdlop.ck_binding_height_n);
        let wccom0 = &w + &(&ori_ar * &challenge);
        assert_eq!(az, wccom0);
    
        let az2 = &ck_m3 * &z;
        let wccom02 = &u + &(&ori_com3_m * &challenge);
        assert_eq!(az2, wccom02);
    
        break;
    }
    
}

fn test_equivalence_2(com_1: &Matrix<Poly>, com_2: &Matrix<Poly>, r_1: &Matrix<Poly>, r_2: &Matrix<Poly>, bdlop: &ABDLOP, is_prove_only: bool){
    loop {
        let r = (0..bdlop.randomness_vector_dimension_k).map(|_| Poly::random_binomial()).collect();
        let poe2_y  = Matrix::from_vec(r);
    
        let r = (0..bdlop.randomness_vector_dimension_k).map(|_| Poly::random_binomial()).collect();
        let poe2_y2  = Matrix::from_vec(r);
    
        let (ck_top, ck_m1, ck_m2, ck_m3) = bdlop.ck.slice_into_4(bdlop.ck_binding_height_n);
    
        let w = &ck_top * &poe2_y;
        let w2 = &ck_top * &poe2_y2;
        let u = &ck_m1 * &poe2_y+ (&ck_m1 * &poe2_y2).neg();
    
        // let mut c1_byte = Vec::new();
        let w_string = serde_json::to_string(&w).unwrap();
        let w2_string = serde_json::to_string(&w2).unwrap();
        let u_string = serde_json::to_string(&w2).unwrap();
        let combined = w_string + &w2_string + &u_string;
    
        let mut hasher = Sha3_256::new();
        hasher.update(combined); //Better to use serialzed byte instead. String for convenient.
        let hashed = hasher.finalize().to_vec();
    
        let challenge = Poly::random_binomial();
    
        let cr = &(r_1 * &challenge);
        let z = &poe2_y + &cr;
        let cr2 = &(r_2 * &challenge);
        let z2 = &poe2_y2 + &cr2;
    
        if Sampler::reject_0(&z.clone(),&cr, 27000f64) && Sampler::reject_0(&z2.clone(),&cr2, 27000f64) {
            continue;
        }
    
        if is_prove_only{
            return;
        }
    
        // Az =? w+ ccom0
        let num = matrix_l2_norm_sqr(&z);
        assert!(num>1);
        let az = &ck_top * &z;
        let (ori_ar,ori_com1_m,ori_com2_sqrtm, ori_com3_m) = com_1.slice_into_4(bdlop.ck_binding_height_n);
        let wccom0 = &w + &(&ori_ar * &challenge);
        assert_eq!(az, wccom0);
    
        let num = matrix_l2_norm_sqr(&z2);
        assert!(num>1);
        let az2 = &ck_top * &z2;
        let (ori_ar2,ori_com1_m2,_, _) = com_2.slice_into_4(bdlop.ck_binding_height_n);
        let wccom02 = &w2 + &(&ori_ar2 * &challenge);
        assert_eq!(az2, wccom02);
    
        let b1z_m_b1z2 = (&ck_m1 * &z) + (&ck_m1 * &z2).neg();
        assert_eq!(b1z_m_b1z2, (&(ori_com1_m+ori_com1_m2.neg()) * &challenge) + u);
        break;
    }
    
}

fn test_commitment(message: Poly, second_message: Poly, bdlop :&ABDLOP) -> Poly{
    // let (bdlop,st1,st2, et1, et2) = ABDLOP::new_random_instance();
    let value =  Poly::random_integer();
    let m_vec = bdlop.prepare_qpadl_message(value.clone());
    let (cm1, r1) = bdlop.commit(&m_vec);

    cm1.val[0][0].clone()
}

fn test_proof_of_asset(is_rejection_sampling: bool, bdlop: &ABDLOP, is_prove_only: bool) -> i32 {
    let mut rejected_time =-1;
    while true{
        rejected_time +=1;
        // let (bdlop,st1,st2, et1, et2) = ABDLOP::new_random_instance();
        let (ck_top, ck_m1, ck_m2, ck_m3) = bdlop.ck.slice_into_4(bdlop.ck_binding_height_n);
        
        // let poa_y = Poly::random_discrete_gaussian(bdlop.std_dev_sigma as f64);
        let r = (0..bdlop.randomness_vector_dimension_k).map(|_| Poly::random_binomial()).collect();
        let poa_y  = Matrix::from_vec(r);
        let poa_w = &ck_top * &poa_y;
        let poa_u_mult =  &(&(&ck_m1 * &poa_y) * &(&ck_m1 * &poa_y)) +  &(&ck_m2 * &poa_y);
        let masking_g = Poly::random_constant_unmasked();
    
        let message =  Poly::random_integer();
        let m_vec = bdlop.prepare_qpadl_message(message.clone());
        let (original_commit, original_r) = bdlop.commit(&m_vec);
        let (ori_ar,ori_com1_m,ori_com2_sqrtm, ori_com3_m) = original_commit.slice_into_4(bdlop.ck_binding_height_n);
    
        let message_bin = message.bin_repr();
        let garbage_polynomial =  (&ck_m1 * &poa_y).to_item_t()  * (Poly::one() + (message_bin.clone()+message_bin.clone()).neg());
        // let (cm1, r1) = bdlop.commit(&m_vec);
        let mut padding_vec = {
            let mut res_vec: Vec<Poly> = vec![];
            for _ in 0..bdlop.ck_binding_height_n{
                res_vec.push(Poly::zero());
            }
            res_vec
        };
        let mut message_vec = vec![message.bin_repr(), garbage_polynomial, masking_g.clone()];
        padding_vec.append(&mut message_vec);
        let message_vec = 0;
        let perpare_message = &Matrix::from_vec(padding_vec);
        let (cm1) = bdlop.commit_with_r(&perpare_message, &original_r);
        let (new_cm_ar,new_cm_bin,new_cm_garbage, new_cm_maskingg) = cm1.slice_into_4(bdlop.ck_binding_height_n);
        
        let random_phi = Poly::random();
        let random_phi_qt = random_phi.binary_compose_transpose_leftmultiply_self();
        let function_f = (message.bin_repr() * random_phi_qt.clone()) + (message*random_phi.clone()).neg();
        let masked_h = function_f +masking_g;
    
        let u_lin = &(ck_m3.clone() + &ck_m1 *&random_phi_qt + (&ck_m1* &random_phi).neg()) * &poa_y;
        let challenge = Poly::random_binomial();
        let cr = &original_r * &challenge;
        let poa_z = poa_y + &original_r * &challenge;
        if Sampler::reject_0(&poa_z.clone(),&cr, 27000f64) && is_rejection_sampling {
            continue;
        }

        if is_prove_only{
            return rejected_time;
        }
    
        // Verification
        let num = matrix_l2_norm_sqr(&poa_z);
        assert!(num>1);

        let az = &ck_top* &poa_z;
        assert_eq!(az, poa_w+ &ori_ar * &challenge);
    
        let f_prime = &ck_m1 * &poa_z + (&new_cm_bin * &challenge).neg(); // abin z-cf1
        let f_prime_2 =  &ck_m2 * &poa_z + (&new_cm_garbage * &challenge).neg(); // a'bin^T z - cu
        assert_eq!(Poly::zero(), f_prime.to_item_t() * (f_prime.to_item_t()+challenge.clone()) + f_prime_2.to_item_t() + poa_u_mult.to_item_t().neg());
    
        let z_ulin = &(ck_m3 + &ck_m1 *&random_phi_qt + (&ck_m1* &random_phi).neg()) * &poa_z;
        let com_f = &new_cm_bin * &random_phi_qt + (&ori_com1_m * &random_phi).neg();
        assert_eq!(z_ulin, &( new_cm_maskingg + com_f +  Matrix::from_vec(vec![masked_h.neg()])) * &challenge + u_lin );

        let first_dl_coeff_arr = masked_h.canonical_repr();
        for i in 0..BASEMUL_DEGREE{
            assert_eq!(first_dl_coeff_arr[i],Poly_U128::ZERO);
        }

        break;
    }
    rejected_time
}


fn test_proof_of_consistency(is_rejection_sampling: bool, bdlop:&ABDLOP, abdlop:&ABDLOP, is_prove_only: bool) -> i32{
    let mut rejected_time =-1;
    '_outer: loop{
        rejected_time +=1;

        // let (bdlop,_,_, _, _) = ABDLOP::new_random_instance();

        let value =  Poly::random_integer();
        let m_vec = bdlop.prepare_qpadl_message(value.clone());
        let (cm1, r1) = bdlop.commit(&m_vec);
        let (ori_com0,ori_com1,ori_com2, ori_com3) = cm1.slice_into_4(bdlop.ck_binding_height_n);
        let (ori_ck_top, ori_ck_m1, ori_ck_m2, ori_ck_m3 )= bdlop.ck.slice_into_4(bdlop.ck_binding_height_n);
    
        // let (abdlop,_,_, _, _) = ABDLOP::new_random_instance();
        let (ck_top, ck_m1, ck_m2, ck_m3 )= abdlop.ck.slice_into_4(abdlop.ck_binding_height_n);
    
        // Sample g and y3
        let y3 = Poly::random_discrete_gaussian(bdlop.std_dev_sigma);
        let masking_g = Poly::random_constant_unmasked();
        assert_eq!(masking_g.canonical_repr()[0],Poly_U128::zero());
        let prepared_message = abdlop.prepare_simple_message(vec![value.clone(), y3.clone(), masking_g.clone()]);
        let (cm_proof, r_proof) = abdlop.commit_full(&prepared_message, &r1);
        let (cm_top, cm_m, cm_gp1, cm_gp2) = cm_proof.slice_into_4(abdlop.ck_binding_height_n);
        
        let (bin_challenge_mat, bin_challenge_mat_poly_sigma) = Poly::random_binary_vector(bdlop.randomness_vector_dimension_k);

        // Here Ri*vec<r_i> 
        let mut poly_coeff = vec![Poly_U128::zero();DEGREE];
        assert!(bin_challenge_mat.len() >= DEGREE);
        assert!(DEGREE >= 256); //for 128 security level, this need to be 256.
        let r1_coeffs_flatten = {
            let r1_vec = r1.to_vec();
            let total_coeff = DEGREE* r1.to_vec().len();
            let mut ret_vec = vec![Poly_U128::zero();total_coeff];
            let mut counter=0;
            for poly in r1_vec{
                let flatten_poly = poly.flatten();
                for i in 0..DEGREE{
                    ret_vec[counter+i] = flatten_poly[i];
                }
                counter+=DEGREE;
            }
            ret_vec
        };

        let r1_coeffs_flatten_ref = r1.to_vec().iter().fold(vec![],|acc, x| [acc,x.clone().flatten()].concat() );
        assert_eq!(r1_coeffs_flatten_ref, r1_coeffs_flatten);

        (&mut poly_coeff).into_par_iter().enumerate().for_each(|(i, poly_coeff_mut) | {
            // assert_eq!(bin_challenge_mat[i].len(), DEGREE*bdlop.randomness_vector_dimension_k);
            *poly_coeff_mut = PolyCanon::inner_product(bin_challenge_mat[i].clone(), r1_coeffs_flatten.clone());
        });
        


        // for i in 0..bin_challenge_mat.len(){
        //     // bin_challenge_mat[i]
        //     assert_eq!(bin_challenge_mat[i].len(), DEGREE*bdlop.randomness_vector_dimension_k);
        //     poly_coeff[i] = inner_product(bin_challenge_mat[i].clone(), r1_coeffs_flatten.clone());
        // }

        let rir1_poly = Poly::new(poly_coeff.try_into().unwrap());
        let z3 = &y3 + &rir1_poly;
        if Sampler::reject_0(&Matrix::from_vec(vec![z3.clone()]), &Matrix::from_vec(vec![rir1_poly.clone()]), 27000f64) && is_rejection_sampling {
            continue;
        }
        

        '_inner: loop{
            rejected_time +=1;
            // Sample linear combination challenge dj, d'j
            let dj_vec = Poly::random_zq_vec(DEGREE);
            // let dj_vec = Poly::random_zq_vec_scalar(DEGREE);
            let dj_vec_prime = Poly::random_zq_vec(128-1);
            // let dj_vec_prime = Poly::random_zq_vec_scalar(DEGREE-1);
        
            // Compute Responses
            // Sum over d1(sigma_rj . r_tai + sigma_ej . y_3 - sigma_ej . z3) 
            let mut ej_vec = vec![Matrix::<Poly>::empty(); DEGREE];
            let mut ej_vec_sigma = vec![Matrix::<Poly>::empty(); DEGREE];
            // let r1_sigma_mat = r1.map(|f| f.sigma_reflect());
            // for i in (0..DEGREE){
            //     let mut ez = [0;DEGREE];
            //     ez[i] = 1;
            //     let ez_poly = Poly::new(ez);
            //     ej_vec.push(Matrix::from_vec_transpose(vec![ez_poly.clone()])); //Transpose because it is left multiplicaiton.
            //     ej_vec_sigma.push(Matrix::from_vec_transpose(vec![ez_poly.sigma_reflect()])); //Transpose because it is left multiplicaiton.
            // }

            (&mut ej_vec, &mut ej_vec_sigma).into_par_iter().enumerate().for_each(|(i,(ej_vec_mut,ej_vec_sigma_mut))| {
                let mut ez = [Poly_U128::zero();DEGREE];
                ez[i] = Poly_U128::one();
                let ez_poly = Poly::new(ez);
                *ej_vec_mut = (Matrix::from_vec_transpose(vec![ez_poly.clone()])); //Transpose because it is left multiplicaiton.
                *ej_vec_sigma_mut = (Matrix::from_vec_transpose(vec![ez_poly.sigma_reflect()])); //Transpose because it is left multiplicaiton.
            });

            //Already reflected
            // let bin_challenge_mat_poly_sigma: Vec<Matrix<Poly>> = bin_challenge_mat_poly.clone().into_par_iter().map(|vec| vec.map(|poly| poly.sigma_reflect())).collect();
            
            // Compute dj(rr + ey - ez ), where r,y, z are fixed
            // for dj in dj_vec.clone(){

            // }
            let x_ez_term = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_sigma, &Matrix::from_vec(vec![z3.clone()]));
            let x_ey_term = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_sigma, &Matrix::from_vec(vec![y3.clone()]));
            // println!("Test area");
            let x_rr_term = ABDLOP::compute_product_sum(&dj_vec, &bin_challenge_mat_poly_sigma, &r1);
            // println!("\n bin_challenge_mat_poly_sigma :len:row:{}, col:{}", bin_challenge_mat_poly_sigma[0].row_m, bin_challenge_mat_poly_sigma[0].col_n);
            // println!("\n r1_vec_sigmaa:len:row:{}, col:{}", r1.row_m, r1.col_n);
            let x_v_term = ABDLOP::compute_product_sum(&dj_vec_prime, &ej_vec_sigma[1..128].to_vec(), &Matrix::from_vec(vec![value.clone()]));
        
            let h_poly = x_rr_term.clone() +  x_ey_term.clone() + x_ez_term.neg() + x_v_term.clone() + masking_g.clone();
            // Equation (d)
            assert_eq!(h_poly.canonical_repr()[0],Poly_U128::zero());
        
            // ZKProof of opening for ABDLOP
            let (w,y1,y2) = abdlop.zkp_abdlop_initial_commit();
            
            // All other y values
            // Ay1
            let leftover_y_0 = (&ori_ck_top * &y1);
            let negative_by2 = (&ck_m1 * &y2).neg();
            let leftover_y_1 = (&ori_ck_m1 * &y1) + negative_by2.clone();
            let mut neg_sqrtq_by2 = negative_by2.clone();
            neg_sqrtq_by2 *= *MODULUS_SQRT_ZQ;
            let leftover_y_2 = (&ori_ck_m2 * &y1) + neg_sqrtq_by2;
            let leftover_y_3 =(&ori_ck_m3 * &y1) + negative_by2.clone();
        
            let leftover_y_4_1 = ABDLOP::compute_product_sum(&dj_vec, &bin_challenge_mat_poly_sigma, &y1);
            let leftover_y_4_2 = ABDLOP::compute_product_sum(&dj_vec_prime, &ej_vec_sigma[1..128].to_vec(), &negative_by2);        
            let leftover_y_4_3 = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_sigma, &(&ck_m2 * &y2).neg());
            let leftover_y_4 =  leftover_y_4_1+ leftover_y_4_2 + leftover_y_4_3 + (&ck_m3 * &y2).neg().to_item_t();
        
            // Final challenge
            let challenge = ABDLOP::get_challenge();
            // Compute final responses
            let cr1 = &r1 * &challenge;
            let z1 = &y1 + &(cr1);
            let cr2  = &r_proof * &challenge;
            let z2 = &y2 + &cr2;
            if Sampler::reject_0(&z1.clone(),&cr1.clone(), 27000f64) && is_rejection_sampling {
                continue;
            }
            if Sampler::reject_0(&z2.clone(),&cr2.clone(), 27000f64) && is_rejection_sampling {
                continue;
            }

            if is_prove_only {
                return rejected_time;
            }
        
            // Equaton (e)
            let lhs = (&abdlop.ck_atjai * &z1) + (&ck_top * &z2);
            let rhs = &w + &(&cm_top * &challenge);
            assert_eq!(lhs,rhs);
        
            let masked_message_cf1_minus_bz2 = (&cm_m * &challenge) + (&ck_m1 * &z2).neg();
            assert_eq!(masked_message_cf1_minus_bz2, (&ck_m1 * &y2).neg()+Matrix::from_vec(vec![&challenge * &value]) );
            let mut sqrtq_masked_message_cf1_minus_bz2 = masked_message_cf1_minus_bz2.clone();
            sqrtq_masked_message_cf1_minus_bz2 *= *MODULUS_SQRT_ZQ;
        
            let masked_message_cu1_minus_bz2 = (&cm_gp1 * &challenge) + (&ck_m2 * &z2).neg();
            assert_eq!(masked_message_cu1_minus_bz2, (&ck_m2 * &y2).neg()+Matrix::from_vec(vec![&challenge * &y3]) );
            let masked_message_cu2_minus_bz2 = (&cm_gp2 * &challenge) + (&ck_m3 * &z2).neg();
            assert_eq!(masked_message_cu2_minus_bz2, (&ck_m3 * &y2).neg()+Matrix::from_vec(vec![&challenge * &masking_g]) );
        
            // Equation (f-0-4)
            let compute_leftover_0 = (&ori_ck_top * &z1) + (&ori_com0 * &challenge).neg();
            assert_eq!(compute_leftover_0, leftover_y_0);
            let compute_leftover_1 = (&ori_ck_m1 * &z1) + masked_message_cf1_minus_bz2.clone()  + ((&ori_com1 * &challenge).neg());
            assert_eq!(compute_leftover_1, leftover_y_1);
            let compute_leftover_2 = (&ori_ck_m2 * &z1) + sqrtq_masked_message_cf1_minus_bz2 + ((&ori_com2 * &challenge).neg());
            assert_eq!(compute_leftover_2, leftover_y_2);
            let compute_leftover_3 = (&ori_ck_m3 * &z1) + masked_message_cf1_minus_bz2.clone()  + ((&ori_com3 * &challenge).neg());
            assert_eq!(compute_leftover_3, leftover_y_3);
        
            let z_4_1 = ABDLOP::compute_product_sum(&dj_vec, &bin_challenge_mat_poly_sigma, &z1);
            let z_4_2 = ABDLOP::compute_product_sum(&dj_vec_prime, &ej_vec_sigma[1..128].to_vec(), &Matrix::from_vec(vec![masked_message_cf1_minus_bz2.to_item_t()]));
            let z_4_3 = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_sigma, &masked_message_cu1_minus_bz2);
            let ez_sigma = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_sigma, &Matrix::from_vec(vec![z3]));
            // let compute_leftover_4 = z_4_2 + (x_v_term *challenge).neg();
            let compute_leftover_4 = z_4_1+z_4_2+ z_4_3 + masked_message_cu2_minus_bz2.to_item_t() + ((h_poly + ez_sigma) * challenge).neg();
            assert_eq!(compute_leftover_4, leftover_y_4);
            // leftover_y_4
            break '_outer;
        }
    }
    rejected_time
    
}


fn test_proof_of_equivalence(is_rejection_sampling: bool, bdlop: &ABDLOP, st1: &Matrix<Poly>,st2: &Matrix<Poly>,et1: &Matrix<Poly>,et2:&Matrix<Poly>, abdlop:&ABDLOP, is_prove_only: bool) -> i32{    
    let mut rejected_time =0;
    '_outer: loop {

        // let (bdlop,st1,st2, et1, et2) = ABDLOP::new_random_instance();
        assert_eq!(st1.row_m,1);
        assert_eq!(st2.row_m,1);
        assert_eq!(et1.row_m,1);
        assert_eq!(et2.row_m,1);
        // let total_row = st1.row_m + st2.row_m + et1.row_m + et2.row_m;
        let concat_m = [st1.to_vec_onerow(), et1.to_vec_onerow(), st2.to_vec_onerow(), et2.to_vec_onerow()].concat();
        let concat_m_matrix = Matrix::from_vec(concat_m);
        assert_eq!(concat_m_matrix.col_n,1);
        assert_eq!(concat_m_matrix.row_m, 2*st1.col_n + 2* et1.col_n);
        
        let value =  Poly::random_integer();
        let m_vec = bdlop.prepare_qpadl_message(value.clone());
        let (cm1, r1) = bdlop.commit(&m_vec);
        let (cm1_com0,cm1_com1,cm1_com2, cm1_com3) = cm1.slice_into_4(bdlop.ck_binding_height_n);
        let (cm1_ck_top, cm1_ck_m1, cm1_ck_m2, cm1_ck_m3 )= bdlop.ck.slice_into_4(bdlop.ck_binding_height_n);

        // let value =  Poly::random_integer();
        // let m_vec = bdlop.prepare_qpadl_message(value.clone());
        let value =  Poly::random_integer();
        let m_vec2 = bdlop.prepare_qpadl_message(value.clone());
        let (cm2, r2) = bdlop.commit(&m_vec);
        let (cm2_com0,cm2_com1,cm2_com2, cm2_com3) = cm2.slice_into_4(bdlop.ck_binding_height_n);

        // let abdlop = ABDLOP::new_poe_abdlop();
        let (abdlop_ck_top, abdlop_ck_m1, abdlop_ck_m2)= abdlop.ck.slice_into_3(abdlop.ck_binding_height_n);
        let poe_com_diff_0 = cm1_com0+cm2_com0.neg();
        assert_eq!(poe_com_diff_0,&cm1_ck_top*&(&r1+&r2.neg()));
        let poe_u_pk1_pk2 = Matrix::from_vec([cm1_ck_m1.to_vec_onerow(), cm1_ck_m2.to_vec_onerow()].concat());
        let poe_ubar_comdiff1_2 = Matrix::from_vec([(cm1_com1+cm2_com1.neg()).to_vec_onerow(), (cm1_com2+cm2_com2.neg()).to_vec_onerow()].concat());

        let length_s = st1.col_n;
        let length_e = et1.col_n;
        assert_ne!(st1.col_n,1);
        assert_ne!(et1.col_n,1);
        assert_eq!(st1.col_n,st2.col_n);
        assert_eq!(et1.col_n,et2.col_n);

        // com_diff0 = A(r-r')
        // [[com_diff0.s1],[com_diff0.s2]]
        // println!("row:{:?}, col:{}", poe_com_diff_0.row_m, poe_com_diff_0.col_n);
        // println!("Poe_ubar_comdiff1_2--row:{}, col:{}", poe_ubar_comdiff1_2.row_m, poe_ubar_comdiff1_2.col_n);
        let com0diff_s1 = &poe_com_diff_0.transpose() *&st1.transpose();
        // println!("Poe_ubar_comdiff0_s1--row:{}, col:{}", com0diff_s1.row_m, com0diff_s1.col_n);
        // let com0diff_s1_t = com0diff_s1.transpose();
        let com0diff_s2 = &poe_com_diff_0.transpose() * &st2.transpose();
        // let com0diff_s2_t = com0diff_s2.transpose();

        let poe_norm_test_taget_without_u = Matrix::v_stack(&com0diff_s1, &com0diff_s2);
        let l_poe_u_comdiff1_comdiff2 =  &poe_norm_test_taget_without_u + &poe_ubar_comdiff1_2.neg();

        // assert!(false);

        // Sample g and y3
        let y3 = Poly::random_discrete_gaussian(common_static::SIGMA_POE_S3);
        let masking_g = Poly::random_constant_unmasked();
        assert_eq!(masking_g.canonical_repr()[0],Poly_U128::ZERO);
        let prepared_message = abdlop.prepare_simple_message(vec![y3.clone(), masking_g.clone()]);
        let (cm_proof, r_proof) = abdlop.commit_full(&prepared_message, &concat_m_matrix);
        let (cm_top, cm_y3, cm_g) = cm_proof.slice_into_3(abdlop.ck_binding_height_n);
    
        //  Sample random binary challenge matrix
        let (bin_challenge_mat, bin_challenge_mat_poly_sigma) = Poly::random_binary_vector(l_poe_u_comdiff1_comdiff2.to_vec().len());
        // Here Ri*vec<r_i> 
        let mut poly_coeff = vec![Poly_U128::ZERO;DEGREE];
        assert!(bin_challenge_mat.len() >= DEGREE);
        assert!(DEGREE >= 256); 

        let l_coeffs_flatten = {
            let l_vec = l_poe_u_comdiff1_comdiff2.to_vec();
            let total_coeff = DEGREE* l_poe_u_comdiff1_comdiff2.to_vec().len();
            let mut ret_vec = vec![Poly_U128::ZERO;total_coeff];
            let mut counter=0;
            for poly in l_vec{
                let flatten_poly = poly.flatten();
                for i in 0..DEGREE{
                    ret_vec[counter+i] = flatten_poly[i];
                }
                counter+=DEGREE;
            }
            ret_vec
        };

        let l_coeffs_flatten_ref = l_poe_u_comdiff1_comdiff2.to_vec().iter().fold(vec![],|acc, x| [acc,x.clone().flatten()].concat() );
        assert_eq!(l_coeffs_flatten_ref, l_coeffs_flatten);

        (&mut poly_coeff).into_par_iter().enumerate().for_each(|(i, poly_coeff_mut) | {
            // bin_challenge_mat[i]
            assert_eq!(bin_challenge_mat[i].len(), DEGREE*l_poe_u_comdiff1_comdiff2.to_vec().len());
            *poly_coeff_mut = PolyCanon::inner_product(bin_challenge_mat[i].clone(), l_coeffs_flatten.clone());
        });
        // for i in 0..bin_challenge_mat.len(){
        //     // bin_challenge_mat[i]
        //     assert_eq!(bin_challenge_mat[i].len(), DEGREE*bdlop.randomness_vector_dimension_k);
        //     poly_coeff[i] = inner_product(bin_challenge_mat[i].clone(), r1_coeffs_flatten.clone());
        // }

        let rir1_poly = Poly::new(poly_coeff.try_into().unwrap());
        let z3 = &y3 + &rir1_poly;
        // println!("\nHello:{:?}", bin_challenge_mat);
        // println!("\nHello:{:?}", rir1_poly.into_canonical_poly().coeff);
        // println!("\nHello:{:?}", y3.into_canonical_poly().coeff);
        // println!("\nHello:{:?}", z3.into_canonical_poly().coeff);
        // println!("Should be small (EQ):{}", z3.into_canonical_poly().linf_norm());
        // assert!(false);

        if Sampler::reject_0(&Matrix::from_vec(vec![z3.clone()]), &Matrix::from_vec(vec![rir1_poly.clone()]), 27000f64) && is_rejection_sampling {
            rejected_time +=1; 
            continue;
        }
        
        '_inner: loop{
            // NOTE: client challenge
            // Sample linear combination challenge dj, d'j
            let dj_vec = Poly::random_zq_vec(DEGREE);
            // let dj_vec_prime = Poly::random_zq_vec(DEGREE-1);
        
            // Compute Responses
            // Sum over d1(sigma_rj . r_tai + sigma_ej . y_3 - sigma_ej . z3) 
            let mut ej_vec = vec![Matrix::<Poly>::empty(); DEGREE];
            let mut ej_vec_sigma = vec![Matrix::<Poly>::empty(); DEGREE];
            // let r1_sigma_mat = r1.map(|f| f.sigma_reflect());
            // for i in (0..DEGREE){
            //     let mut ez = [0;DEGREE];
            //     ez[i] = 1;
            //     let ez_poly = Poly::new(ez);
            //     ej_vec.push(Matrix::from_vec_transpose(vec![ez_poly.clone()])); //Transpose because it is left multiplicaiton.
            //     ej_vec_sigma.push(Matrix::from_vec_transpose(vec![ez_poly.sigma_reflect()])); //Transpose because it is left multiplicaiton.
            // }
            (&mut ej_vec, &mut ej_vec_sigma).into_par_iter().enumerate().for_each(|(i,(ej_vec_mut,ej_vec_sigma_mut))| {
                let mut ez = [Poly_U128::ZERO;DEGREE];
                ez[i] = Poly_U128::ONE;
                let ez_poly = Poly::new(ez);
                *ej_vec_mut = Matrix::from_vec_transpose(vec![ez_poly.clone()]); //Transpose because it is left multiplicaiton.
                *ej_vec_sigma_mut = Matrix::from_vec_transpose(vec![ez_poly.sigma_reflect()]); //Transpose because it is left multiplicaiton.
            });
            
            // let bin_challenge_mat_poly_sigma: Vec<Matrix<Poly>> = bin_challenge_mat_poly.clone().into_par_iter().map(|vec| vec.map(|poly| poly.sigma_reflect())).collect();

            let x_ez_term = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_sigma, &Matrix::from_vec(vec![z3.clone()]));
            let x_ey_term = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_sigma, &Matrix::from_vec(vec![y3.clone()]));
            let x_rcm_term = ABDLOP::compute_product_sum(&dj_vec, &bin_challenge_mat_poly_sigma, &poe_norm_test_taget_without_u);
            let x_comdiff_ubar: Poly = ABDLOP::compute_product_sum(&dj_vec, &bin_challenge_mat_poly_sigma, &poe_ubar_comdiff1_2);

        
            let h_poly = x_rcm_term.clone() +  x_ey_term.clone() + x_ez_term.neg() + x_comdiff_ubar.neg() + masking_g.clone();
            // Equation (d)
            assert_eq!(h_poly.canonical_repr()[0],Poly_U128::ZERO);
        
            // ZKProof of opening for ABDLOP
            // w = A1y1+A2y2 (or A3y1+A4y2 in the diagram)
            let (w,y1,y2) = abdlop.zkp_abdlop_initial_commit_custom_sigma(common_static::SIGMA_POE_S1, common_static::SIGMA_POE_S2);
        
            // All other y values
            let (y1_s1, others) = y1.v_split(bdlop.ck_binding_height_n);
            let (y1_e1, others) = others.v_split(bdlop.randomness_vector_dimension_k);
            let (y1_s2, y2_e2) = others.v_split(bdlop.ck_binding_height_n);

            let leftover_y_0_s1e1 = (&cm1_ck_top.transpose() * &y1_s1) +y1_e1;
            let leftover_y_0_s2e2= (&cm1_ck_top.transpose() * &y1_s2) + y2_e2;
            let v0_leftover_y = Matrix::v_stack(&leftover_y_0_s1e1, &leftover_y_0_s2e2);

            let cbary_top = &poe_com_diff_0.transpose()*&y1_s1;
            let cbary_bot = &poe_com_diff_0.transpose()*&y1_s2;
            let cbary = Matrix::v_stack(&cbary_top, &cbary_bot);
            let leftover_y_1_drcy = ABDLOP::compute_product_sum(&dj_vec, &bin_challenge_mat_poly_sigma, &cbary);
            let minus_by2_b_for_y3 = (&abdlop_ck_m1 * &y2).neg();
            let leftover_y_1_deby2minus = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_sigma, &minus_by2_b_for_y3);
            let minus_by2_bg = (&abdlop_ck_m2 * &y2).neg();
            let v1_leftover_y = leftover_y_1_drcy + leftover_y_1_deby2minus + minus_by2_bg.to_item_t();
            
            // Challenge from client
            let challenge = ABDLOP::get_challenge();



            // Compute response z
            let cm_for_z1 = &concat_m_matrix * &challenge;
            let z1 =  y1 + cm_for_z1.clone();
            let cr_proof =  &r_proof * &challenge;
            let z2 = y2 + cr_proof.clone();
            // if  && is_rejection_sampling {
            //     continue;
            // }
            if (Sampler::reject_0(&z1, &cm_for_z1, 27000f64) || Sampler::reject_0(&z2, &cr_proof, 27000f64)) && is_rejection_sampling {
                rejected_time +=1;
                continue;
            }


            if is_prove_only{
                return rejected_time;
            }


            // Verification
            // (e) A3z1 + A4z2 =?  w + cf where f= cm_top
            assert_eq!(&abdlop.ck_atjai*&z1 + &abdlop_ck_top*&z2, w + &cm_top * &challenge);

            // (f)-> v0 =? T(row 1)z - cu
            let (z1_s1, others) = z1.v_split(bdlop.ck_binding_height_n);
            let (z1_e1, others) = others.v_split(bdlop.randomness_vector_dimension_k);
            let (z1_s2, z1_e2) = others.v_split(bdlop.ck_binding_height_n);
            let tz_s1e1 = (&cm1_ck_top.transpose() * &z1_s1) +z1_e1;
            let tz_s2e2= (&cm1_ck_top.transpose() * &z1_s2) + z1_e2;
            let tz_minus_cu = Matrix::v_stack(&tz_s1e1, &tz_s2e2) + &poe_u_pk1_pk2.neg()*&challenge;
            assert_eq!(tz_minus_cu,v0_leftover_y);

            //  (f)-> v1 =? T(row 2) [z, cu1-B'z1, cu2 - B''z2] - c[h+dez+drubar]
            let cbarz_top = &poe_com_diff_0.transpose()*&z1_s1;
            let cbarz_bot = &poe_com_diff_0.transpose()*&z1_s2;
            let cbarz = Matrix::v_stack(&cbarz_top, &cbarz_bot);
            let tz_com_z = ABDLOP::compute_product_sum(&dj_vec, &bin_challenge_mat_poly_sigma, &cbarz);

            let minus_bz2_b_for_y3 = (&abdlop_ck_m1 * &z2).neg();
            let tz_cu1_bz2 = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_sigma, &(&cm_y3 * &challenge + minus_bz2_b_for_y3));

            let cu2 = &cm_g * &challenge;
            let minus_by2_bg = (&abdlop_ck_m2 * &z2).neg(); 
            let tz_cu2_bz2  = cu2 + minus_by2_bg;

            let x_ez_term = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_sigma, &Matrix::from_vec(vec![z3.clone()]));
            let x_comdiff_ubar: Poly = ABDLOP::compute_product_sum(&dj_vec, &bin_challenge_mat_poly_sigma, &poe_ubar_comdiff1_2);
            let v1_rhs = (h_poly +  x_ez_term + x_comdiff_ubar) * challenge;

            assert_eq!(tz_com_z+ tz_cu1_bz2 + tz_cu2_bz2.to_item_t()+ v1_rhs.neg(), v1_leftover_y); 
            
            break '_outer; 
        } 
    }
    return rejected_time;
}

// fn test_sampling_ddll(i: usize){
//     let sampler = &SAMPLER_DDLL;
//     let  k= Integer::from_str("4387525644200305491968").unwrap();

//     let my_vec = vec![0;DEGREE];
//     my_vec.into_par_iter().for_each(|item| {
//         let mut thread_rng = rand::rng();
//         let res = sampler.discrete_gaussian_final(&mut thread_rng, k.clone());
//     }
//     );
// }

fn criterion_benchmark(c: &mut Criterion){
    let mut group = c.benchmark_group("My Group");
    group.sample_size(100);
    group.warm_up_time(Duration::from_millis(100));

    let mut rand= rand::rng();
    let arr1: Vec<u64> = (0..DEGREE).map(|_| (rand.random::<u64>())).collect();
    let arr2: Vec<u64> = (0..DEGREE).map(|_| (rand.random::<u64>())).collect();

    // let arr1_bigint: Vec<U128> = (0..DEGREE).map(|_| (U128::from_u128(rand.random::<u128>()))).collect();
    // let arr2_bigint: Vec<U128> = (0..DEGREE).map(|_| (U128::from_u128(rand.random::<u128>()))).collect();
    // let arr3_bigint: Vec<Zq> = (0..DEGREE).map(|_| (Zq::from(rand.random_range(0..MODULUS)))).collect();
    // let arr4_bigint: Vec<Zq> = (0..DEGREE).map(|_| (Zq::from(rand.random_range(0..MODULUS)))).collect();
    // // let p = PolyNonMon::new(arr1[..].try_into().unwrap());
    // // let q = PolyNonMon::new(arr2[..].try_into().unwrap());
    // let mod128= crypto_bigint::NonZero::new(U128::from_u128(MODULUS)).unwrap();
    // let c = U128::MAX - *mod128 + U128::one();
    // let c_limb = c.as_limbs();
    // println!("[0]:{}, [1]:{}", c_limb[0], c_limb[1]);

    // group.bench_function("polymul (Naive-Arkwork)", |b| b.iter(|| test_fn_naive_bigint_3arkwork(black_box(&arr3_bigint[..].try_into().unwrap()),black_box(&arr4_bigint[..].try_into().unwrap())) ));
    // group.bench_function("polymul (Naive-Bigint)", |b| b.iter(|| test_fn_naive_bigint_2(black_box(&arr1_bigint[..].try_into().unwrap()),black_box(&arr2_bigint[..].try_into().unwrap())) ));
    // group.bench_function("polymul (Naive)", |b| b.iter(|| test_fn_naive(black_box(&arr1[..].try_into().unwrap()),black_box(&arr2[..].try_into().unwrap())) ));
   

    // group.bench_function("polymul (Non)", |b| b.iter(|| test_fn_full_mul_non(black_box(&arr1[..].try_into().unwrap()),black_box(&arr2[..].try_into().unwrap())) ));

    // group.bench_function("polymul (Mon)", |b| b.iter(|| test_fn_full_mul_mont(black_box(&arr1[..].try_into().unwrap()),black_box(&arr2[..].try_into().unwrap())) ));

    // Commitment   
    // group.bench_function("Proof of commitment", |b| b.iter(|| test_commitment(black_box(Poly::random()), black_box(Poly::random_binomial())))); 

    // Proof of Consistency
    let (bdlop, st1,st2,et1,et2) = ABDLOP::new_random_instance();
    let (abdlop_consistency,_,_,_,_) =  ABDLOP::new_random_instance();
    let (abdlop_poe) =  ABDLOP::new_poe_abdlop();

    // group.bench_function("Proof of commitment", |b| b.iter(|| test_commitment(black_box (Poly::random()), black_box(Poly::random_binomial()), black_box(&bdlop))));


    let value =  Poly::random_integer();
    let m_vec = bdlop.prepare_qpadl_message(value.clone());
    let (cm1, r1) = bdlop.commit(&m_vec);
    let m_vec = bdlop.prepare_qpadl_message(value.clone());
    let (cm2, r2) = bdlop.commit(&m_vec);
    // group.bench_function("Proof of equivalence 2 (Prove only)", |b| b.iter(|| test_equivalence_2(black_box (&cm1), black_box(&cm2), black_box(&r1), black_box(&r2), black_box(&bdlop), true)));
    
    // group.bench_function("Proof of equivalence 2", |b| b.iter(|| test_equivalence_2(black_box (&cm1), black_box(&cm2), black_box(&r1), black_box(&r2), black_box(&bdlop), false)));

    let mut r1_sum = Matrix::from_vec(vec![Poly::zero(); bdlop.randomness_vector_dimension_k]);
    // ,Vec<Matrix<Poly>>
    let mut value_sum  = Poly::zero();
    let mut cm_vec: (Vec<Matrix<Poly>>) = (0..15).into_iter().map(|item| {
        let value =  Poly::random_integer();
        let m_vec = bdlop.prepare_qpadl_message(value.clone());
        let (cm1, r1) = bdlop.commit(&m_vec); 
        r1_sum = &r1_sum + &r1;
        value_sum = &value_sum + &value;
        (cm1)
    }
    ).collect();
    let value = value_sum.neg();
    let m_vec = bdlop.prepare_qpadl_message(value.clone());
    let (cm1, r1) = bdlop.commit(&m_vec); 
    r1_sum = &r1_sum + &r1;
    cm_vec.push(cm1);

    // group.bench_function("Proof of balance (Prove only)", |b| b.iter(|| test_balance(black_box (&cm_vec), black_box(&r1_sum), black_box(&bdlop), true)));
    
    // group.bench_function("Proof of balance", |b| b.iter(|| test_balance(black_box (&cm_vec), black_box(&r1_sum), black_box(&bdlop), false)));


    // group.bench_function("Proof of consistency (without RejSampling)", |b| b.iter(|| test_proof_of_consistency(black_box(false), black_box(&bdlop), black_box(&abdlop_consistency), true))); 

    // group.bench_function("Proof of consistency (without RejSampling) and with Verf", |b| b.iter(|| test_proof_of_consistency(black_box(false), black_box(&bdlop), black_box(&abdlop_consistency), false))); 
    // group.bench_function("Proof of consistency (with RejSampling)", |b| b.iter(|| test_proof_of_consistency(black_box(true), black_box(&bdlop), black_box(&abdlop_consistency), true))); 

    // group.bench_function("Proof of equivalence (without RejSampling)", |b| b.iter(|| test_proof_of_equivalence(black_box(false), black_box(&bdlop), black_box(&st1),black_box(&st2),black_box(&et1),black_box(&et2), black_box(&abdlop_poe), true)));   


    // group.bench_function("Proof of equivalence (without  RejSampling) and with Verf", |b| b.iter(|| test_proof_of_equivalence(black_box(false), black_box(&bdlop), black_box(&st1),black_box(&st2),black_box(&et1),black_box(&et2), black_box(&abdlop_poe), false)));   


    // // // With rejection sampling
    // group.bench_function("Proof of equivalence (with RejSampling)", |b| b.iter(|| test_proof_of_equivalence(black_box(true), black_box(&bdlop), black_box(&st1),black_box(&st2),black_box(&et1),black_box(&et2), black_box(&abdlop_poe), true)));   

    // // let total_samples = 20;
    // // let mut total_rejection_ctr = 0;
    // // for i in 0..total_samples{
    // //     total_rejection_ctr += test_proof_of_equivalence(black_box(true), black_box(&bdlop), black_box(&st1),black_box(&st2),black_box(&et1),black_box(&et2), black_box(&abdlop_poe));
    // // }
    // // println!("Rejection sampling (3 times) average{:?}", total_rejection_ctr/total_samples);

    // group.bench_function("Proof of asset (without RejSampling)", |b| b.iter(|| test_proof_of_asset(black_box(false), black_box(&bdlop), true))); 

    // group.bench_function("Proof of asset (without RejSampling) and with verf", |b| b.iter(|| test_proof_of_asset(black_box(false), black_box(&bdlop), false))); 

    // group.bench_function("Proof of asset (with RejSampling)", |b| b.iter(|| test_proof_of_asset(black_box(true), black_box(&bdlop), true))); 

    // group.bench_function("DDLL sample for PoA'", |b| b.iter(|| test_sampling_ddll(black_box(1))));   

    //Proof of Asset Compact
    {
        use padl_pq::proof_of_asset_compact::{gen_proof_of_asset_compact,verify_proof_of_asset_compact};

        let (bdlop, _, _, _ ,_)= ABDLOP::new_random_instance();
        let (abdlop, _,_,_,_)= ABDLOP::new_random_instance_custom_twomessage(3,MAX_COEFF_BETA); //2 for ABDLOP, y2,g, BETA, g1
    
        let message = Poly::random_u64();
        let m_vec = bdlop.prepare_qpadl_message(message.clone());
        let (ori_cm, ori_r) = bdlop.commit(&m_vec);
        let proof = gen_proof_of_asset_compact(&bdlop, &abdlop, &ori_cm, &ori_r, &message, true);
        // assert!(verify_proof_of_asset_compact(proof.clone(), &bdlop, &abdlop, &ori_cm));
        group.bench_function("PoA-Compact Proving (With Rejection Sampling)", |b| b.iter(|| gen_proof_of_asset_compact(&bdlop, &abdlop, &ori_cm, &ori_r, &message, true)));  
        // group.bench_function("Parallel Rej PoA-Compact Proving (With Rejection Sampling)", |b| b.iter(|| gen_proof_of_asset_compact_parallel(&bdlop, &abdlop, &ori_cm, &ori_r, &message, true)));  
        // group.bench_function("PoA-Compact Proving (Without Rejection Sampling)", |b| b.iter(|| gen_proof_of_asset_compact(&bdlop, &abdlop, &ori_cm, &ori_r, &message, false)));    
        // group.bench_function("PoA-Compact Verification", |b| b.iter(|| verify_proof_of_asset_compact(proof.clone(), &bdlop, &abdlop, &ori_cm)));   
    }

    // // Commitment bench
    // {
    //     let (bdlop, _, _, _ ,_)= ABDLOP::new_random_instance();
    
    //     let message = Poly::random_u64();
    //     let m_vec = bdlop.prepare_qpadl_message(message.clone());
    //     group.bench_function("Commitment", |b| b.iter(||  bdlop.commit(&m_vec)));   
     
    // }


    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);