// use num_bigint::{BigUint, BigInt};
use rand::Rng;
use rand::distr::Bernoulli;
use rand::rngs::ThreadRng;
// use rand_old::rngs::ThreadRng;
use rug::Complete;
// use rand_old::{Rng, thread_rng};
use rug::{Assign, Float, Integer, ops::Pow};
// use sha3::digest::consts::False;
use rug::rand::{ThreadRandGen, ThreadRandState};
use rug::rand::RandState;

use crate::polynomial::Poly;
use crate::common::DEGREE;
use crate::common_static::{SIGMA_LARGE, SIGMA_VERYLARGE};
use crate::common::MODULUS_I128;
use crate::common_static::Zq;
use rand::distr::Distribution;
use ark_ff::Field;


use crate::common::MODULUS;
use crate::matrix::Matrix;
use crate::common::REJ_M;
use crate::polynomial::{Poly_I128, Poly_U128};
use num_traits::Zero;

use lazy_static::lazy_static;

const MAX_BIT_X: usize = 150;

pub struct Sampler
{
    ci: [Float;MAX_BIT_X],
    target_sigma : u128
    // thread_rng: &'a mut ThreadRng,
}

const PRECISION: u32 = 128;

lazy_static!{
    pub static ref SAMPLER: Sampler = {
        // assert_eq!(888111417804452, SIGMA_VERYLARGE);
        let sigma: Float = Float::with_val(PRECISION, Float::parse(SIGMA_VERYLARGE.to_string()).unwrap()); //11.(sqrt337)*2**64-1
        let sigma_2_sqr = sigma.clone() * sigma * Float::with_val(PRECISION,Float::parse("2").unwrap());
        let f = sigma_2_sqr;


        let mut ci : Vec<Float>= vec![];
        // core::array::from_fn(|i| Float::with_val(53, Special::Zero)); 
        for i in 0..MAX_BIT_X{
            // ci[i] =  (Float::with_val(PRECISION, Float::parse(( - (Integer::from(2).pow(i as u32)) ).to_string_radix(10)).unwrap()) / f.clone()).exp().to_f64();
            ci.push((Float::with_val(PRECISION,  - (Integer::from(2).pow(i as u32)) )/f.clone()).exp());
            // ci[i] = (Float::with_val(PRECISION, ( - (Integer::from(2).pow(i as u32)) ))/f.clone()).exp();
            // ci[i] =  (Float::with_val(PRECISION, Float::from(PRECISION, ( - (Integer::from(2).pow(i as u32)) ).to_string_radix(10)).unwrap()) / f.clone()).exp().to_f64();
        }

        Sampler{
            ci: ci.try_into().unwrap(),
            target_sigma : SIGMA_VERYLARGE
        }
    };

    pub static ref SAMPLER_MEDIUM: Sampler = {
        let sigma: Float = Float::with_val(PRECISION, Float::parse(SIGMA_LARGE.to_string()).unwrap()); //11.(sqrt337)*2**64-1
        // assert_eq!(7237284, SIGMA_LARGE);
        // let sigma: Float = Float::with_val(PRECISION, Float::parse("7237284").unwrap()); //11.(sqrt337)*2**64-1
        let sigma_2_sqr = sigma.clone() * sigma * Float::with_val(PRECISION,Float::parse("2").unwrap());
        let f = sigma_2_sqr;
        let mut ci :Vec<Float> = vec![];
        for i in 0..MAX_BIT_X{
            ci.push((Float::with_val(PRECISION, ( - (Integer::from(2).pow(i as u32)) ))/f.clone()).exp());
        }

        Sampler{
            ci: ci.try_into().unwrap(),
            target_sigma : SIGMA_LARGE as u128
        }
    };
}

impl Sampler{
    // Algorithm 10
    pub fn discrete_sigma2(rng: &mut ThreadRng) -> u32{
        // let b =Self::sample_bernoulli_custom(rng, 0.5);
        let bernoulli_d = Bernoulli::new(0.5).unwrap();
        'outer_loop: loop{

            let b = bernoulli_d.sample(rng);
            if b==false{
                return 0;
            }
            let mut counter_i=1;
            loop{
                let k = (2*counter_i)-1;
                for _ in 1..=k-1{
                    let bit_l = bernoulli_d.sample(rng);
                    // let bit_l = rng.random_bool(0.5);                
                    if bit_l == true{
                        // counter_i+=1; //rejection sampling without increasing i
                        continue 'outer_loop;
                    }
                }
                // let bit_k = rng.random_bool(0.5);
                let bit_k = bernoulli_d.sample(rng);
                if bit_k == false{
                    return counter_i
                }
    
                counter_i+=1;
            }
        }
    }

    // Algorithm 11
    fn discrete_ksigma2(&self, rng: &mut ThreadRng, k : Integer) -> Integer{
        loop{
            let x= Integer::from(Self::discrete_sigma2(rng));
            let mut rand = RandState::new();
            // k.clone().random_below(&mut rand);
            let y = Integer::from(rng.random_range(0..(k.to_u128().unwrap())));
            let negative_y = -y.clone();
            // f is taken into account during precomputation where f = 2 sigma^2
            // let b = self.sample_bernoulli((y.clone())*( y+(2*k.clone()*x) ));
            let b = self.sample_bernoulli((negative_y)*( y.clone()+(2*k.clone()*x.clone()) ));
            let z = (k.clone()*x.clone()) + y.clone();
            // println!("sample:z-{}, = {}*{} + {}",k,x,y,z);
            if b == false{
                continue;
            }

            return z;
        }
    }

    // Algorithm 12
    // sigma = k * sigma2 = k * 0.849
    pub fn discrete_gaussian_final(&self, rng: &mut ThreadRng, k: Integer) -> Integer{
        loop{
            let z = self.discrete_ksigma2(rng, k.clone());
            let b = rng.random_bool(0.5);
            if z == 0 && b == false{
                continue;
            }
            let b2 = Self::sample_bernoulli_custom(rng, 0.5);
            if b2 == false{
                return z;
            }
            else{
                return -z;
            }
        }
    
    }

    pub fn sample_discrete_gaussian_icdt_poly(&self, sigma: u128) -> Poly{
        assert_eq!(self.target_sigma, sigma);
        // assert!(sigma == SIGMA_VERYLARGE || sigma as u32 == SIGMA_LARGE);

        let mut thread_rng = rand::rng();
        let mut val = vec![Zq::ZERO;DEGREE];
        for i in 0..DEGREE{
            // k  * 0.849 = sigma or  k = sigma/0.849 or k = sigma * 1.178
            let target_val = self.discrete_gaussian_final(&mut thread_rng, Integer::from(sigma * 1178 / 1000)).to_i128().unwrap();
            val[i] = Zq::from(match target_val <0{
                true => (MODULUS_I128 + target_val) as u128,
                _ => target_val as u128
            })
        }
        
        Poly::new(val.try_into().unwrap())
    }

    fn sample_bernoulli_custom(rng: &mut ThreadRng, pr: f64) -> bool{
        rng.random_bool(pr)
    }

    fn sample_bernoulli(&self, x: Integer) -> bool{
        let mut thread_rng = rand::rng();

        // sigma size
        // sigma = 3725009271926059171840
        // sigma (size of s3) => log2(11 * sqrt 337 * 2**64) => 8 + 64 => 72 bits
        // k.0.849 = sigma => k = 72.23 bits or 73 bits
        // k = 4387525644200305491968

        //6tails where x is 0.8 = .8*6 = 5
        // -y (y+2kx) where y = k size then for size purpose -k(k+2kx) = -k.k + 2.k.k.x
        // = -k.k + 10.k.k => around 11k**2 =>  log2(11)+ 73+73 => 150 bits

        //f have size 2sigma^2

        // if -B, then bin form == -1011
        let mut x = x;
        // if !x.is_negative(){
        // x = -x;
        // }
        let bin_x = x.to_string_radix(2);
        let bin_x_sign = bin_x.as_bytes()[0];
        assert!(x.is_negative() || x.is_zero()); // -x 
        let bin_x_without_sign = &bin_x.as_bytes()[1..];

        // println!("{}",x.to_string_radix(2));
        // println!("{}",String::from_utf8(vec![bin_x_sign]).unwrap());
        // println!("{:?}",(bin_x_without_sign.to_vec()));
        // println!("{}",String::from_utf8(bin_x_without_sign.to_vec()).unwrap());
        let mut bin_x_without_sign: Vec<u8> = bin_x_without_sign.iter().map(|item| item-48).collect();
        // let bin_x_without_sign = 
        // let mut temp =vec![0u8;(MAX_BIT_X-bin_x_without_sign.len())];
        let mut temp =vec![0u8;0];
        temp.append(&mut bin_x_without_sign);
        temp.reverse();
        let bin_x_without_sign = temp;
        // println!("{:?}",(bin_x_without_sign.to_vec()));
        
        let mut rand_state = RandState::new();
        for i in 0..bin_x_without_sign.len(){
            if bin_x_without_sign[i] == 1{
                // let mut f = Float::with_val(PRECISION, 0);
                // f.assign(Float::random_bits(&mut rand_state));
                // assert!(f<=1.0);
                // let a_i = f < self.ci[i];
                let a_i = Self::sample_bernoulli_custom(&mut thread_rng, self.ci[i].to_f64());
                if a_i == false{
                    return false;
                }
            }
        }
        true

    }

    pub fn reject_0_128prec(z: &Matrix<Poly>, v: &Matrix<Poly>, sigma :u128) -> bool{
        if cfg!(debug_assertions){
            assert_eq!(z.row_m,v.row_m);
            assert_eq!(z.col_n,1);
            assert_eq!(v.col_n,1);
        }
        let sigma = Float::with_val(PRECISION,sigma);

        // f64 random is [0,1).
        let u: f64 = rand::rng().random_range(0.0..1.0);
        let mut collect_z: Vec<Integer> = Vec::new();
        let mut collect_v: Vec<Integer> = Vec::new();
        let mut v_l2norm_sqr_sum: Float = Float::with_val(PRECISION, 0);
        for row_i in 0..z.row_m{
            let z_val = z.val[row_i][0].into_canonical_poly();
            collect_z.extend(z_val.coeff.into_iter().map(|val| Integer::from(val)).collect::<Vec<Integer>>());
            let v_val = v.val[row_i][0].into_canonical_poly();
            collect_v.extend(v_val.coeff.into_iter().map(|val| Integer::from(val)).collect::<Vec<Integer>>());
            let cur_norm = collect_v.clone().into_iter().reduce(|acc, item| (acc + (item.clone()*item))).unwrap().clone();
            // println!("cur_norm: {},", cur_norm);
            v_l2norm_sqr_sum += cur_norm;
        }
        // let v_l2norm = v_l2norm_sqr_sum.sqrt();

        let inner_product = collect_z.into_iter().zip(collect_v.into_iter()).map(|(x1,x2)| x1 * x2).reduce(|acc, e| acc+e).unwrap();
        // assert!(inner_product >= i64::MIN as i128);
        // assert!(inner_product <= i64::MAX as i128);

        //Directly using v_l2norm_sqr_sum to avoid precision loss.
        // println!("inner product: {}", inner_product);
        let sigma_sigma_2: Float = 2*sigma.clone()*sigma;
        let exp_exp = ((Float::with_val(PRECISION, -2.0) * Float::with_val(PRECISION,inner_product) + v_l2norm_sqr_sum) / sigma_sigma_2).exp().to_f64();

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
    use rand::Rng;
    use rayon::iter;
    use rug::Complete;
    use rug::{Integer,Float};
    use std::str::FromStr;

    use num_bigint::BigInt;


    use crate::common_static::SIGMA_LARGE;
    use crate::common_static::SIGMA_VERYLARGE;
    use crate::sampler_ddll::DEGREE;
    use crate::sampler_ddll::PRECISION;
    use crate::sampler_ddll::SAMPLER_MEDIUM;

    use super::{Sampler, SAMPLER};
    use plotpy::{Histogram, Plot};


    #[test]
    fn test_rejection_sampling_ddll(){
        use crate::polynomial::Poly;
        use crate::matrix::Matrix;
        use crate::sampler_ddll::REJ_M;


        // z = y+ cr
        let sigma = SIGMA_VERYLARGE;
        let threshold_f = 0.04;

        let mut rejection_total = 0f64;
        let sample_total = 1000;
        let mut samples = vec![];
        let mut failed_z_arr = vec![];
        let mut uniform_sameples = vec![];
        for _index in 0..sample_total{
            let masking_y = Poly::random_discrete_gaussian_u128(sigma);
            let challenge = Poly::random_binomial();
    
            use crate::proof_of_asset_compact::MAX_VALUE_BOUND;
            let secret = Poly::random_withmax(MAX_VALUE_BOUND as u128);
            let v = &challenge * &secret;
            let z = &masking_y+&v;

            if Sampler::reject_0_128prec(&Matrix::from_vec(vec![z.clone()]), &Matrix::from_vec(vec![v]), sigma) == true{
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

    fn std_deviation(data: &[i128], mean: &Float) -> Float {
        let variance = data.iter().map(|value| {
            let diff = mean.clone() - (Float::with_val(PRECISION,*value));

            diff.clone() * diff
        }).reduce(|acc, item| acc+item).unwrap() / Float::with_val(PRECISION, data.len());

        variance.sqrt()
    }

    #[test]
    fn test_ddll(){
        // let x = Integer::from_str("11").unwrap();
        // let f = Integer::from_str("10").unwrap();
        // let sigma = Integer::from_str("10").unwrap();
        // let mut thread_rng = rand::rng();
        // let  k= Integer::from_str("4387525644200305491968").unwrap();

        // let res = SAMPLER.discrete_gaussian_final(&mut thread_rng, k);
        // println!("res: {}", res);
        // assert!(false);
    }

    #[test]
    fn test_ddll_sigma2(){
        let sigma = 0.849;
        let sigma_threshold = sigma/50.0;
        let mean_threshold = 0.0 + 0.003;

        const SAMPLE_N: usize  = DEGREE * 2000;
        let mut res = vec![0i128; SAMPLE_N];
        let mut thread_rng = rand::rng();
        for i in 0..SAMPLE_N{
            let mut item_t = 0;
            loop {
                item_t = Sampler::discrete_sigma2(&mut thread_rng) as i128;
                let restart = thread_rng.random_bool(0.5);
                if item_t !=0 || !restart{
                    break;
                }
            }
            let flip = thread_rng.random_bool(0.5);
            if flip {
                item_t = -item_t;
            }
            res[i] = item_t;
        }

        let sum: Float = Float::with_val(PRECISION, res.iter().sum::<i128>());
        let mean = sum/(res.len());
        println!("Std_dev:{:?}", std_deviation(&res, &mean));
        println!("Mean:{:?}", mean.clone().abs());
        assert!( (std_deviation(&res, &mean)-sigma ) < (sigma_threshold) as f32);
        assert!((mean.abs()) < Float::with_val(PRECISION, mean_threshold));
    }

    #[test]
    fn test_ddll_medium(){
        // println!("ci_largesigma:{:?}",SAMPLER.ci);

        let sigma = SIGMA_LARGE;
        // Visual inspection is required. (Automatically test mean and std_dev is within certain bound)
        let sigma_threshold = sigma/100;
        let mean_threshold = sigma/100;

        fn std_deviation(data: &[i128]) -> Float {
            let mean: Float = Float::with_val(PRECISION, data.iter().sum::<i128>()/(data.len() as i128));

            let variance = data.iter().map(|value| {
                let diff = mean.clone() - (Float::with_val(PRECISION,*value));

                diff.clone() * diff
            }).reduce(|acc, item| acc+item).unwrap() / data.len();

            variance.sqrt()
        }

        let sampler = &SAMPLER_MEDIUM;
        let mut thread_rng = rand::rng();
        let  k= Integer::from(sigma as u128 * 1178u128 / 1000u128);

        // const SAMPLE_N: usize  = 1000000; Larger N for effect
        const SAMPLE_N: usize  = 1000;
        let mut res = vec![0i128; SAMPLE_N];
        for i in 0..SAMPLE_N{
            let item_t = sampler.discrete_gaussian_final(&mut thread_rng, k.clone());
            res[i] = item_t.to_i128().unwrap();
        }

        let sum: Float = Float::with_val(PRECISION, res.iter().sum::<i128>());
        let mean = sum/(res.len());
        println!("Std_dev:{:?}", std_deviation(&res));
        println!("Std_dev ratio:{:?}", std_deviation(&res)/sigma);
        println!("Mean:{:?}", mean.clone().abs());
        // assert!( (std_deviation(&res)-(sigma) ) < (sigma_threshold) as f32);
        // assert!((mean.abs()) < Float::with_val(PRECISION, mean_threshold));
        // assert!(false);

        // Plot Histogram for visual inspection
        let mut histogram = Histogram::new();
        let num_bins = 300;
        let labels = ["Samples"];
        histogram.set_colors(&["#9de19a"]).set_line_width(2.0).set_stacked(true).set_style("step").set_number_bins(num_bins);
        histogram.draw(&vec![res], &labels);

        let mut plot = Plot::new();
        plot.add(&histogram).set_frame_border(true, false, true, false).grid_labels_legend("values", "count");

        let _ = plot.save(&format!("tmp/test_sample_distribution_ddll_{}.svg", sigma));

    }

    #[test]
    fn test_ddll_graph_large(){
        let sigma = SIGMA_VERYLARGE;
        // Visual inspection is required. (Automatically test mean and std_dev is within certain bound)
        let sigma_threshold = sigma/100;
        let mean_threshold = sigma/100;

        fn std_deviation(data: &[i128]) -> Float {
            let mean: Float = Float::with_val(PRECISION, data.iter().sum::<i128>()/(data.len() as i128));

            let variance = data.iter().map(|value| {
                let diff = mean.clone() - (Float::with_val(PRECISION,*value));

                diff.clone() * diff
            }).reduce(|acc, item| acc+item).unwrap() / data.len();

            variance.sqrt()
        }

        let sampler = &SAMPLER;
        let mut thread_rng = rand::rng();
        let  k= Integer::from(sigma as u128 * 1178u128 / 1000u128);

        const SAMPLE_N: usize  = DEGREE * 1000;
        let mut res = vec![0i128; SAMPLE_N];
        for i in 0..SAMPLE_N{
            let item_t = sampler.discrete_gaussian_final(&mut thread_rng, k.clone());
            res[i] = item_t.to_i128().unwrap();
        }

        let sum: Float = Float::with_val(PRECISION, res.iter().sum::<i128>());
        let mean = sum/(res.len());
        println!("Std_dev:{:?}", std_deviation(&res));
        println!("Std_dev ratio:{:?}", std_deviation(&res)/sigma);
        println!("Mean:{:?}", mean.clone().abs());
        assert!( (std_deviation(&res)-(sigma) ) < (sigma_threshold) as f32);
        assert!((mean.abs()) < Float::with_val(PRECISION, mean_threshold));

        let max_val = res.iter().max().unwrap();
        let res = res.iter().map(|item| (Integer::parse(item.to_string()).unwrap().complete()* Integer::from(i64::MAX /2 ) / Integer::parse(max_val.to_string()).unwrap().complete()   ).to_i128().unwrap() ).collect();

        // Plot Histogram for visual inspection
        let mut histogram = Histogram::new();
        
        let num_bins = 300;
        let labels = ["Samples"];
        histogram.set_colors(&["#9de19a"]).set_line_width(2.0).set_stacked(true).set_style("step").set_number_bins(num_bins);
        histogram.draw(&vec![res], &labels);

        let mut plot = Plot::new();
        plot.add(&histogram).set_frame_border(true, false, true, false).grid_labels_legend("values", "count");

        let _ = plot.save(&format!("tmp/test_sample_distribution_ddll_{}_scaled.svg",sigma));

    }
}