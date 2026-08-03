
// use std::os::unix::thread;
// use std::ptr;
// use std::thread::Thread;

use rand::Rng;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;

use crate::common::MODULUS;
// use crate::common::MODULUS;
use crate::common::MODULUS_I128;
use crate::matrix::Matrix;
use crate::polynomial::Poly;
// use crate::polynomial::PolyCanon;
// use padl_pq_sampler::sampler::{CDT_BYTES_SMALL};

use crate::common_static::{SIGMA_SMALL};
use crate::common::DEGREE;
use crate::common::REJ_M;
use crate::polynomial::{Poly_I128, Poly_U128};
use num_traits::Zero;

use std::fs;
use std::io::Read;
use lazy_static::lazy_static;

lazy_static!{
    pub static ref SAMPLER: Sampler = {
       //let data = fs::read("cdt.bin").unwrap();
        // const CDT_BYTES1: &[u8] = include_bytes!("cdt_std1.bin");
        // const CDT_BYTES2: &[u8] = include_bytes!("cdt_std2.bin");
        // const CDT_BYTES3: &[u8] = include_bytes!("cdt_std3.bin");
        // const CDT_BYTES4: &[u8] = include_bytes!("cdt_std4.bin");

        const CDT_BYTES_SMALL: &[u8] = include_bytes!("cdt_small.bin");
        // let mut data: Vec<u8> = vec![];
        // CDT_BYTES1.chain(CDT_BYTES2).chain(CDT_BYTES3).chain(CDT_BYTES4).read_to_end(&mut data).unwrap();
        let mut res = vec![];
        let mut res_small = vec![];

        // Parse data into u64 and then store it...
        // for ptr in (0..data.len()).step_by(8){
        //     // This assume perfectly padded u64 bytes which is the case.
        //     let u64_data = u64::from_le_bytes(data[ptr..ptr+8].try_into().unwrap()); 
        //     res.push(u64_data);
        // }
        for ptr in (0..CDT_BYTES_SMALL.len()).step_by(8){
            // This assume perfectly padded u64 bytes which is the case.
            let u64_data = u64::from_le_bytes(CDT_BYTES_SMALL[ptr..ptr+8].try_into().unwrap()); 
            res_small.push(u64_data);
        }

        Sampler { max_theta: vec![SIGMA_SMALL], cdt_table: res, small_cdt_table: res_small }
    };
}

pub struct Sampler
{
    // thread_rng: &'a mut ThreadRng,
    max_theta: Vec<u32>,
    cdt_table :Vec<u64>,
    small_cdt_table: Vec<u64>
}

impl Sampler{
    // pub const fn new_const(sigma: u64) -> Sampler{
    //     // TODO: support dynamic table compilation instead
    //     // assert_eq!(sigma,27000); 

    //     // let data = fs::read("cdt_list");

    //     Sampler {target_theta: sigma}
    // }

    fn sample_discrete_gaussian_icdt(&self, sigma: u32) -> u128{
        if cfg!(debug_assertions){
            assert!(self.max_theta.contains(&sigma)); 
        }

        let mut thread_rng = rand::rng();
        let next_u64: u64 =thread_rng.random(); 
        let sign_u64 = thread_rng.random_bool(0.5); 
        let target_cdt_table: &Vec<u64> = match sigma{
            SIGMA_SMALL => &self.small_cdt_table,
            SIGMA_LARGE => &self.cdt_table,
            _ => {
                assert!(false);
                &self.cdt_table
            }
        };
        let mut sample = match target_cdt_table.binary_search(&next_u64){
            Ok(res)=>res as i64,
            Err(res)=> {
                res as i64
            }
        };
    
        let mut res = sample as u128;
        if sign_u64{
            res = (MODULUS-(sample as u128));
            // res = (-sample.rem_euclid(MODULUS_I64)) as u64;
        }

        res
    }

    pub fn sample_discrete_gaussian_icdt_poly(&self, sigma: u32) -> [Poly_U128;DEGREE]{
        if cfg!(debug_assertions){
            assert!(self.max_theta.contains(&sigma)); 
        }

        let mut res = [Poly_U128::zero();DEGREE];
        for i in 0..DEGREE{
            res[i] = Poly_U128::from(self.sample_discrete_gaussian_icdt(sigma));
        }

        res
    }

    // pub fn sample(&mut self) -> [u64; DEGREE]{
    //     let k = k_from_theta(self.target_theta);
    //     let mut return_sample = [0u64;DEGREE];
    //     let sample_count: usize = DEGREE;
    //     for i in 0..sample_count{
    //         return_sample[i] = sample_vartime_k(k, &mut self.thread_rng) as u64;
    //     }
    //     return_sample
    // }

    /// Rejection Sampling by Lyu. We assume z*v < i64 and z*v can fit into f64 (ie about 53 bits)
    /// This function fails when inner product is >64 bits.
    pub fn reject_0(z: &Matrix<Poly>, v: &Matrix<Poly>, sigma :f64) -> bool{
        if cfg!(debug_assertions){
            assert_eq!(z.row_m,v.row_m);
            assert_eq!(z.col_n,1);
            assert_eq!(v.col_n,1);
        }

        // f64 random is [0,1).
        let u: f64 = rand::rng().random_range(0.0..1.0);
        let mut collect_z: Vec<Poly_I128> = Vec::new();
        let mut collect_v: Vec<Poly_I128> = Vec::new();
        let mut v_l2norm_sqr_sum: f64 = 0.0;
        // if z.row_m < 64{
        for row_i in 0..z.row_m{
            collect_z.extend(&z.val[row_i][0].into_canonical_poly().coeff);
            let v_val = v.val[row_i][0].into_canonical_poly();
            collect_v.extend(&v_val.coeff);
            let cur_norm =v_val.l2_norm_sqr();
            // println!("cur_norm: {},", cur_norm);
            v_l2norm_sqr_sum += (u128::from_str_radix(&cur_norm.to_string(),10)).unwrap() as f64;

            // let cur_norm = v.val[row_i][0].into_canonical_poly().l2_norm();
            // v_l2norm_sqr_sum += cur_norm*cur_norm;
        }
        // }
        //TODO: parallelize it, not yet done
        // else{
        //     let (z_ret_vec, v_ret_vec, cur_norm_vec): (Vec<_>, Vec<_>, Vec<_>)  = (z.val,v.val).into_par_iter().map(|(a,b)| {
        //         let z_ret = a[0].into_canonical_poly().coeff;
        //         let v_temp = b[0].into_canonical_poly();
        //         let cur_norm = v_temp.l2_norm_sqr();
        //         let v_ret = &v_temp.coeff;
        //         // collect_z.extend(a[0].into_canonical_poly().coeff);
        //         // let v_val = b[0].into_canonical_poly();
        //         // collect_v.extend(&v_val.coeff);
        //         // let cur_norm =v_val.l2_norm_sqr();
        //         (Vec::from(z_ret),Vec::from(v_ret), cur_norm)
        //     }).collect_into_vec();
        //     // println!("cur_norm: {},", cur_norm);
        //     v_l2norm_sqr_sum += (u128::from_str_radix(&cur_norm.to_string(),10)).unwrap() as f64;
        // }

        // let v_l2norm = v_l2norm_sqr_sum.sqrt();

        let inner_product = collect_z.iter().zip(collect_v.iter()).map(|(x1,x2)| *x1 * *x2).reduce(|acc, e| acc+e).unwrap();
        // assert!(inner_product >= i64::MIN as i128);
        // assert!(inner_product <= i64::MAX as i128);

        //Directly using v_l2norm_sqr_sum to avoid precision loss.
        // println!("inner product: {}", inner_product);
        let inner_product_f64 =(i128::from_str_radix(&inner_product.to_string(),10)).unwrap() as f64;
        let sigma_sigma_2 = (2.0*sigma*sigma) as f64;
        let exp_exp: f64 = ((-2.0 * inner_product_f64 + v_l2norm_sqr_sum) / sigma_sigma_2).exp();

        if (exp_exp/REJ_M) == 0f64{
            // println!("inner_product_f64:{}, v_l2norm_sqr_sum:{}", inner_product_f64, v_l2norm_sqr_sum);
        }

        // println!("u:{}\t > ? :{}",u, (exp_exp/REJ_M));
        match u > (exp_exp/REJ_M) {
            true => true,
            _ => false
        }
    }
}


#[cfg(test)]
mod tests{
    use crate::common::{MODULUS, MODULUS_I128, MODULUS_MINUS1_OVER2, REJ_M};
    use crate::common_static::SIGMA_SMALL;
    use crate::polynomial::{PolyCanon, Poly_I128};

    use super::{Sampler, SAMPLER};
    use std::mem;
    use plotpy::{Histogram, Plot};
    // use rand::distr::uniform;
    use crate::sampler::Poly;
    use crate::matrix::Matrix;

    // use rand::thread_rng;
    // use discrete_gaussian::k_from_theta;
    // use discrete_gaussian::sample_vartime_k;
    // use rand_old::rngs::ThreadRng as RngNew;
    // use rand_old::thread_rng as RngOld;
    // use rand_old::Rng;
    // use rand_old::RngCore;

    #[test]
    fn test_rejection_sampling(){
        use std::collections::HashMap;
        use statrs::distribution::{ChiSquared, ContinuousCDF};

        //TODO: test for closeness of distribution 
        //Tested rejection rate

        // z = y+ cr
        let sigma = SIGMA_SMALL;
        // let sigma = 27000f64;
        let threshold_f = 0.04;

        let mut rejection_total = 0f64;
        let sample_total = 1000;
        let mut samples = vec![];
        let mut failed_z_arr = vec![];
        let mut uniform_sameples = vec![];
        for _index in 0..sample_total{
            let masking_y = Poly::random_discrete_gaussian(sigma as u32);
            let challenge = Poly::random_binomial();
    
            let secret = Poly::random_binomial();
            let v = &challenge * &secret;
            let z = &masking_y+&v;

            if Sampler::reject_0(&Matrix::from_vec(vec![z.clone()]), &Matrix::from_vec(vec![v]), sigma as f64) == true{
                rejection_total+=1.0;
                failed_z_arr.push(z);
            }
            else{
                samples.push(z.clone());
                failed_z_arr.push(z);
            }
            uniform_sameples.push(Poly::random());
        }   

        println!("Success Probability Rate:{:?}",(sample_total as f64-rejection_total)/(sample_total as f64));
        println!("Rejection Probability RAte:{:?}",(rejection_total)/(sample_total as f64));

        let good_prob = (sample_total as f64-rejection_total)/(sample_total as f64);
        assert!((good_prob  - (1.0/REJ_M)).abs()< threshold_f);

    }

    #[test]
    fn test_sample(){
        // Visual inspection is required. (Automatically test mean and std_dev is within certain bound)
        for sigma in SAMPLER.max_theta.clone(){
            // let sigma = sigma;
            let sigma_threshold = sigma/100;
            let mean_threshold = sigma/100;
    
            fn flatten_all(data_vec: Vec<Poly>) -> Vec<Poly_I128>{
                data_vec.iter().map(|poly| poly.into_canonical_poly().coeff.to_vec()).reduce(|mut acc, e| {
                    acc.append(&mut e.clone());
                    acc
                }).unwrap()
            }
    
            fn std_deviation(data: &[i128]) -> f32 {
                let mean: f32 = (data.iter().sum::<i128>()/(data.len() as i128)) as f32;
    
                let variance = data.iter().map(|value| {
                    let diff = mean - (*value as f32);
    
                    diff * diff
                }).sum::<f32>() / data.len() as f32;
    
                variance.sqrt()
            }
    
            const SAMPLE_N: usize  =1000000;
            let mut res = vec![0i128; SAMPLE_N];
            for i in 0..SAMPLE_N{
                let item_t = SAMPLER.sample_discrete_gaussian_icdt(sigma);
                    res[i] = match item_t > MODULUS_MINUS1_OVER2{
                        true => (item_t as i128)-MODULUS_I128,
                        _ => item_t as i128,
                    };
            }
    
            let sum: i128 = res.iter().sum();
            let mean = sum/(res.len() as i128);
            println!("Mean:{:?}", mean.abs());
            assert!(mean.abs() < (mean_threshold as i128));
            println!("Std_dev:{:?}, threashold: {}", std_deviation(&res),sigma_threshold);
            assert!( (std_deviation(&res)-(sigma as f32)) < (sigma_threshold) as f32);
    
            // Plot Histogram for visual inspection
            let mut histogram = Histogram::new();
            let num_bins = 300;
            let labels = ["Samples"];
            histogram.set_colors(&["#9de19a"]).set_line_width(2.0).set_stacked(true).set_style("step").set_number_bins(num_bins);
            histogram.draw(&vec![res], &labels);
    
            let mut plot = Plot::new();
            plot.add(&histogram).set_frame_border(true, false, true, false).grid_labels_legend("values", "count");
    
            let figure_path_name = format!("tmp/test_sample_distribution_icdt_{}.svg", sigma);
            let _ = plot.save(&figure_path_name);
        }
    }
}