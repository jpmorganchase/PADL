use num_traits::Zero;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

use crate::common_trait::SigmaReflect;
use crate::{matrix::Matrix, polynomial::Poly, polynomial::Poly_U128};
use crate::common::MODULUS_SQRT;
use crate::common_static::{MODULUS_SQRT_INV_ZQ, MODULUS_SQRT_ZQ, SIGMA_SMALL};
use crate::polynomial::{PolyCanon, Poly_I128};
use crate::common_static::{kappa,lambda};
// use crate::common_trait::SigmaReflect;
use crate::common_static::SIGMA_MINUS_ONE_NEGATIVE_ONE;

#[derive(Clone)]
pub struct ABDLOP{
    ///Message dimension l
    message_dimension_l: usize, 
    // A2 column
    second_message_dimension: usize,
    ///Height of A1 (without Message Dimension-L), Also height of A2 that is (A2(message)+A1(random))
    pub ck_binding_height_n: usize, 
    ///Width of A is the same as the height of the randomness vector
    pub randomness_vector_dimension_k: usize,
    ///Norm bound for hoenst prover randomness in l-inf norm
    beta_norm: u32, 
    /// A = n+l (row) . k (column) 
    pub ck: Matrix<Poly>, 
    // A2 = n row . ? column
    pub ck_atjai: Matrix<Poly>,
    ///Used for ZKP
    pub std_dev_sigma: u32, 
}

impl ABDLOP{
   pub fn new(message_dimension_l: usize, second_message_dimension:usize, ck_binding_height_n: usize, randomness_vector_dimension_k: usize, beta: u32, ck: Matrix<Poly>,ck_atjai: Matrix<Poly>, std_dev_sigma: u32) -> Self{
        assert_eq!(ck.row_m, ck_binding_height_n + message_dimension_l);
        assert_eq!(ck.col_n, randomness_vector_dimension_k);
        assert_eq!(ck_atjai.row_m, ck.row_m-message_dimension_l);
        assert_eq!(ck_atjai.col_n, second_message_dimension);

        ABDLOP { message_dimension_l: message_dimension_l, second_message_dimension:second_message_dimension, ck_binding_height_n: ck_binding_height_n, randomness_vector_dimension_k: randomness_vector_dimension_k, beta_norm: beta, ck: ck, ck_atjai:ck_atjai, std_dev_sigma: std_dev_sigma }
    }

    pub fn get_challenge() -> Poly{
        Poly::random_binomial()
    }

    ///NOTE: For testing only. It create a standard BDLOP ck with randomly selected parameter.
    pub fn new_random_test_instance(message_dimension_l: usize, second_message_dimension:usize) -> Self{
        // if cfg!(debug_assertions){
        // }
        let ck_binding_height_n = 2;
        // let message_dimension_l = 1;
        let randomness_vector_dimension_k = 2;

        let mut mat = Vec::new();
        for _i in 0..(ck_binding_height_n + message_dimension_l){
            let mut new_row = Vec::new();
            for _j in 0..randomness_vector_dimension_k{
                new_row.push(Poly::random());
            }
            mat.push(new_row);
        }

        let mut mat_ck2 = Vec::new();
        for _i in 0..(ck_binding_height_n){
            let mut new_row = Vec::new();
            for _j in 0..second_message_dimension{
                new_row.push(Poly::random());
            }
            mat_ck2.push(new_row);
        }

        let ck = Matrix::new(mat, ck_binding_height_n + message_dimension_l, randomness_vector_dimension_k);
        let ck2 = Matrix::new(mat_ck2, ck_binding_height_n, second_message_dimension);

        ABDLOP { message_dimension_l: message_dimension_l, second_message_dimension:second_message_dimension, ck_binding_height_n: ck_binding_height_n, randomness_vector_dimension_k: randomness_vector_dimension_k, beta_norm: 128, ck: ck, ck_atjai:ck2, std_dev_sigma: SIGMA_SMALL }
    }
    //// NOTE: This is a new random instance for QPADL
    pub fn new_random_instance() -> (Self, Matrix<Poly>, Matrix<Poly>,Matrix<Poly>,Matrix<Poly>){
        Self::new_random_instance_custom(3)
    }

    pub fn new_random_instance_custom(message_dimension_l: usize) -> (Self, Matrix<Poly>, Matrix<Poly>,Matrix<Poly>,Matrix<Poly>){
        // if cfg!(debug_assertions){
        // }
        assert!(message_dimension_l>=2);

        // let kappa = 16; //Height of the CK
        // let lambda = 16; //Additional randomness length

        let ck_binding_height_n = kappa;
        let message_dimension_l = message_dimension_l; //v, sqrt_v, v; for PoC v, y3,g
        let randomness_vector_dimension_k = kappa+lambda+message_dimension_l; //Row Width
        let second_message_dimension = randomness_vector_dimension_k; //length of r
        let mut mat = Vec::new();
        for _i in 0..(ck_binding_height_n){
            let mut new_row = Vec::new();
            for _j in 0..randomness_vector_dimension_k{
                new_row.push(Poly::random());
            }
            mat.push(new_row);
        }

        //Message's row in ck is trapdoor row
        let a0 = Matrix::new(mat.clone(), ck_binding_height_n, randomness_vector_dimension_k);
        let mut st1_vec = Vec::with_capacity(ck_binding_height_n);
        let mut st2_vec = Vec::with_capacity(ck_binding_height_n);
        let mut et1_vec = Vec::with_capacity(randomness_vector_dimension_k);
        let mut et2_vec = Vec::with_capacity(randomness_vector_dimension_k);
        for _ in 0..ck_binding_height_n{
            st1_vec.push(Poly::random_binomial());
            st2_vec.push(Poly::random_binomial());
        }        
        for _ in 0..randomness_vector_dimension_k{
            et1_vec.push(Poly::random_binomial());
            et2_vec.push(Poly::random_binomial());
        }
        let st1 = Matrix::from_vec_transpose(st1_vec);
        let st2 =  Matrix::from_vec_transpose(st2_vec);
        let et1 = Matrix::from_vec_transpose(et1_vec);
        let et2 =  Matrix::from_vec_transpose(et2_vec);

        let pk1 = &(&st1*&a0) + &et1;
        assert!(pk1.row_m == 1);
        assert!(pk1.col_n == randomness_vector_dimension_k);
        let pk2 =  &(&st2*&a0) + &et2;
        assert!(pk2.row_m == 1);
        assert!(pk2.col_n == randomness_vector_dimension_k);

        mat.push(pk1.val[0].clone());
        mat.push(pk2.val[0].clone());
        if message_dimension_l >= 3{
            for _ in 0..message_dimension_l-2{
                let mut new_row = Vec::new();
                for _j in 0..randomness_vector_dimension_k{
                    new_row.push(Poly::random());
                }
                mat.push(new_row);
            }
        }
        assert_eq!(mat.len(), message_dimension_l+ck_binding_height_n);
   
        let mut mat_ck2 = Vec::new();
        for _i in 0..(ck_binding_height_n){
            let mut new_row = Vec::new();
            for _j in 0..second_message_dimension{
                new_row.push(Poly::random());
            }
            mat_ck2.push(new_row);
        }

        let ck = Matrix::new(mat, ck_binding_height_n + message_dimension_l, randomness_vector_dimension_k);
        let ck2 = Matrix::new(mat_ck2, ck_binding_height_n, second_message_dimension);

        (ABDLOP { message_dimension_l: message_dimension_l, second_message_dimension: second_message_dimension, ck_binding_height_n: ck_binding_height_n, randomness_vector_dimension_k: randomness_vector_dimension_k, beta_norm: 128, ck: ck, ck_atjai:ck2, std_dev_sigma: SIGMA_SMALL }, st1, st2, et1, et2)
    }
    

    pub fn new_random_instance_custom_twomessage(message_dimension_l: usize, second_dimension_s1l: usize) -> (Self, Matrix<Poly>, Matrix<Poly>,Matrix<Poly>,Matrix<Poly>){
        // if cfg!(debug_assertions){
        // }
        assert!(message_dimension_l>=2);

        // let kappa = 16; //Height of the CK
        // let lambda = 16; //Additional randomness length

        let ck_binding_height_n = kappa;
        let message_dimension_l = message_dimension_l; //v, sqrt_v, v; for PoC v, y3,g
        let randomness_vector_dimension_k = kappa+lambda+message_dimension_l; //Row Width
        let second_message_dimension = second_dimension_s1l; //length of r
        let mut mat = Vec::new();
        for _i in 0..(ck_binding_height_n){
            let mut new_row = Vec::new();
            for _j in 0..randomness_vector_dimension_k{
                new_row.push(Poly::random());
            }
            mat.push(new_row);
        }

        //Message's row in ck is trapdoor row
        let a0 = Matrix::new(mat.clone(), ck_binding_height_n, randomness_vector_dimension_k);
        let mut st1_vec = Vec::with_capacity(ck_binding_height_n);
        let mut st2_vec = Vec::with_capacity(ck_binding_height_n);
        let mut et1_vec = Vec::with_capacity(randomness_vector_dimension_k);
        let mut et2_vec = Vec::with_capacity(randomness_vector_dimension_k);
        for _ in 0..ck_binding_height_n{
            st1_vec.push(Poly::random_binomial());
            st2_vec.push(Poly::random_binomial());
        }        
        for _ in 0..randomness_vector_dimension_k{
            et1_vec.push(Poly::random_binomial());
            et2_vec.push(Poly::random_binomial());
        }
        let st1 = Matrix::from_vec_transpose(st1_vec);
        let st2 =  Matrix::from_vec_transpose(st2_vec);
        let et1 = Matrix::from_vec_transpose(et1_vec);
        let et2 =  Matrix::from_vec_transpose(et2_vec);

        let pk1 = &(&st1*&a0) + &et1;
        assert!(pk1.row_m == 1);
        assert!(pk1.col_n == randomness_vector_dimension_k);
        let pk2 =  &(&st2*&a0) + &et2;
        assert!(pk2.row_m == 1);
        assert!(pk2.col_n == randomness_vector_dimension_k);

        mat.push(pk1.val[0].clone());
        mat.push(pk2.val[0].clone());
        if message_dimension_l >= 3{
            for _ in 0..message_dimension_l-2{
                let mut new_row = Vec::new();
                for _j in 0..randomness_vector_dimension_k{
                    new_row.push(Poly::random());
                }
                mat.push(new_row);
            }
        }
        assert_eq!(mat.len(), message_dimension_l+ck_binding_height_n);
   
        let mut mat_ck2 = Vec::new();
        for _i in 0..(ck_binding_height_n){
            let mut new_row = Vec::new();
            for _j in 0..second_message_dimension{
                new_row.push(Poly::random());
            }
            mat_ck2.push(new_row);
        }

        let ck = Matrix::new(mat, ck_binding_height_n + message_dimension_l, randomness_vector_dimension_k);
        let ck2 = Matrix::new(mat_ck2, ck_binding_height_n, second_message_dimension);

        (ABDLOP { message_dimension_l: message_dimension_l, second_message_dimension: second_message_dimension, ck_binding_height_n: ck_binding_height_n, randomness_vector_dimension_k: randomness_vector_dimension_k, beta_norm: 128, ck: ck, ck_atjai:ck2, std_dev_sigma: SIGMA_SMALL }, st1, st2, et1, et2)
    }

    //// NOTE: This is a new random instance for QPADL
    pub fn new_poe_abdlop() -> Self{
        // if cfg!(debug_assertions){
        // }
        // let kappa = 16; //Height of the CK
        // let lambda = 16; //Additional randomness length

        let ck_binding_height_n = kappa;
        let message_dimension_l = 2; // 2 == y,g
        let randomness_vector_dimension_k = kappa+lambda+message_dimension_l; //Row Width
        let second_message_dimension = 2*(kappa+kappa+lambda+3);  //m = (s,e,s2,e2), s have length kappa, e have length kappa+lambda+3 (of bdlop, the parameter is set [kappa] according to BDLOP, so we reuse kappa symbol here)
        let mut mat = Vec::new();
        for _i in 0..ck_binding_height_n{
            let mut new_row = Vec::new();
            for _j in 0..randomness_vector_dimension_k{
                new_row.push(Poly::random());
            }
            mat.push(new_row);
        }
        for _k in 0..message_dimension_l{
            let mut new_row = Vec::new();
            for _j in 0..randomness_vector_dimension_k{
                new_row.push(Poly::random());
            }
            mat.push(new_row);
        }

        let mut mat_ck2 = Vec::new();
        for _i in 0..(ck_binding_height_n){
            let mut new_row = Vec::new();
            for _j in 0..second_message_dimension{
                new_row.push(Poly::random());
            }
            mat_ck2.push(new_row);
        }

        let ck = Matrix::new(mat, ck_binding_height_n + message_dimension_l, randomness_vector_dimension_k);
        let ck2 = Matrix::new(mat_ck2, ck_binding_height_n, second_message_dimension);

        ABDLOP { message_dimension_l: message_dimension_l, second_message_dimension: second_message_dimension, ck_binding_height_n: ck_binding_height_n, randomness_vector_dimension_k: randomness_vector_dimension_k, beta_norm: 128, ck: ck, ck_atjai:ck2, std_dev_sigma: SIGMA_SMALL }
    }

    /// Let len(challenge_row) = N, this compute: Sum over for i in N { challenge_row[i] * (first_input[i] * second_input)[0][0] }
    pub fn compute_product_sum(challenge_row: &Vec<Poly>, first_input_vec: &Vec<Matrix<Poly>>, second_input_fixed: &Matrix<Poly>) -> Poly{ 
        // let mut acc = Poly::zero();
        // for i in 0..challenge_row.len()
        // {
        //     let matrix_mul_res = &first_input_vec[i] * second_input_fixed;
        //     let temp = &challenge_row[i] * &matrix_mul_res.to_item_t();
        //     acc = acc+temp;
        // }

        // println!("{},{}", challenge_row.len(), first_input_vec.len());
        // assert_eq!(challenge_row.len(), first_input_vec.len());
        let acc = (challenge_row,first_input_vec).into_par_iter().map( |(challenge_row_item, first_input_vec_item)| {
            let matrix_mul_res = first_input_vec_item * second_input_fixed;
            // let temp = matrix_mul_res.to_item_t();
            let temp = challenge_row_item * &matrix_mul_res.to_item_t();
            temp
        }).reduce(|| Poly::zero(), |a,b| a+b);

        acc
    }
    /// 1st vbin, 2nd ybin
    pub fn compute_product_sum_varquad_custom(challenge_row: &Vec<Poly>, first_input_vec: &Vec<Poly>, second_input_vec: &Vec<Poly>) -> Poly{ 
        // let mut acc = Poly::zero();
        // for i in 0..challenge_row.len()
        // {
        //     let matrix_mul_res = &first_input_vec[i] * second_input_fixed;
        //     let temp = &challenge_row[i] * &matrix_mul_res.to_item_t();
        //     acc = acc+temp;
        // }
        let acc = (challenge_row,first_input_vec, second_input_vec).into_par_iter().map( |(challenge_row_item, first_input_vec_item, second_input_vec_item)| {
            let matrix_mul_res = (&first_input_vec_item.sigma_reflect() * second_input_vec_item) + (first_input_vec_item * &second_input_vec_item.sigma_reflect() + (&*SIGMA_MINUS_ONE_NEGATIVE_ONE * second_input_vec_item)); //vbin_sigma * ybin + ybin_sigma * vbin + sigma(-1)ybin 
            //vbin = first, ybin = second
            // let temp = matrix_mul_res.to_item_t();
            let temp = challenge_row_item * &matrix_mul_res;
            temp
        }).reduce(|| Poly::zero(), |a,b| a+b);

        acc
    }
    pub fn compute_product_sum_varquad_custom_vbinvbin(challenge_row: &Vec<Poly>, first_input_vec: &Vec<Poly>) -> Poly{ 
        assert_eq!(challenge_row.len(), first_input_vec.len());
        let acc = (challenge_row,first_input_vec).into_par_iter().map( |(challenge_row_item, first_input_vec_item)| {
            let matrix_mul_res = (&first_input_vec_item.sigma_reflect() * first_input_vec_item) + (&*SIGMA_MINUS_ONE_NEGATIVE_ONE * first_input_vec_item); 
            // let temp = matrix_mul_res.to_item_t();
            let temp = challenge_row_item * &matrix_mul_res;
            temp
        }).reduce(|| Poly::zero(), |a,b| a+b);

        acc
    }
    pub fn compute_product_sum_varquad_custom_vleftover(challenge_row: &Vec<Poly>, first_input_vec: &Vec<Poly>) -> Poly{ 
        assert_eq!(challenge_row.len(), first_input_vec.len());
        let acc = (challenge_row,first_input_vec).into_par_iter().map( |(challenge_row_item, first_input_vec_item)| {
            let matrix_mul_res = &first_input_vec_item.sigma_reflect() * first_input_vec_item;
            // let temp = matrix_mul_res.to_item_t();
            let temp = challenge_row_item * &matrix_mul_res;
            temp
        }).reduce(|| Poly::zero(), |a,b| a+b);

        acc
    }
    pub fn compute_product_sum_varquad_custom_zopening_vbin(challenge:&Poly, challenge_row: &Vec<Poly>, first_input_vec: &Vec<Poly>) -> Poly{ 
        assert_eq!(challenge_row.len(), first_input_vec.len());
        let acc = (challenge_row,first_input_vec).into_par_iter().map( |(challenge_row_item, first_input_vec_item)| {
            let matrix_mul_res = (&first_input_vec_item.sigma_reflect() * first_input_vec_item) + (&(&*SIGMA_MINUS_ONE_NEGATIVE_ONE * first_input_vec_item )* &challenge);
            // let temp = matrix_mul_res.to_item_t();
            let temp = challenge_row_item * &matrix_mul_res;
            temp
        }).reduce(|| Poly::zero(), |a,b| a+b);

        acc
    }

    // pub fn compute_product_sum_scalar(challenge_row: &Vec<Poly_U128>, first_input_vec: &Vec<Matrix<Poly>>, second_input_fixed: &Matrix<Poly>) -> Poly{ 
    //     // let mut acc = Poly::zero();
    //     // for i in 0..challenge_row.len()
    //     // {
    //     //     let matrix_mul_res = &first_input_vec[i] * second_input_fixed;
    //     //     let temp = &challenge_row[i] * &matrix_mul_res.to_item_t();
    //     //     acc = acc+temp;
    //     // }

    //     let acc = (challenge_row,first_input_vec).into_par_iter().map( |(challenge_row_item, first_input_vec_item)| {
    //         let matrix_mul_res = first_input_vec_item * second_input_fixed;
    //         let temp = challenge_row_item * &matrix_mul_res.to_item_t();
    //         temp
    //     }).reduce(|| Poly::zero(), |a,b| a+b);

    //     acc
    // }

    pub fn prepare_simple_message(&self, message_m : Vec<Poly>) -> Matrix<Poly> {
        assert_eq!(self.message_dimension_l, message_m.len());
        let mut message_vec = Vec::new();
        for _ in 0..self.ck_binding_height_n{
            message_vec.push(vec![Poly::zero()]);
        }
        for message in message_m{
            message_vec.push(vec![message]);
        }
        Matrix::new(message_vec, self.ck_binding_height_n + self.message_dimension_l, 1)
    }

    /// prepare message to commit to TrapdoorPK.r+message_m, TrapdoorPK2.r+ sqrt_m, CK.r+message_m
    pub fn prepare_qpadl_message(&self, message_m: Poly) -> Matrix<Poly>{
        assert_eq!(self.message_dimension_l, 3);
        let mut message_vec: Vec<Vec<Poly>> = Vec::new();
        for _ in 0..self.ck_binding_height_n{
            message_vec.push(vec![Poly::zero()]);
        }
        message_vec.push(vec![message_m.clone()]);
        let mut sqrt_m = message_m.clone();
        sqrt_m *= *MODULUS_SQRT_ZQ;
        message_vec.push(vec![sqrt_m]);
        message_vec.push(vec![message_m]);
        Matrix::new(message_vec, self.ck_binding_height_n + self.message_dimension_l, 1)
    }

    pub fn prepare_message_custom(&self, source_message_vec: Vec<Poly>) -> Matrix<Poly>{
        let source_len =source_message_vec.len();
        assert!(self.message_dimension_l >= source_len);
        let mut message_vec: Vec<Vec<Poly>> = Vec::new();
        for _ in 0..self.ck_binding_height_n{
            message_vec.push(vec![Poly::zero()]);
        }
        for message in source_message_vec{
            message_vec.push(vec![message]);
        }
        Matrix::new(message_vec, self.ck_binding_height_n + source_len, 1)
    }

    /// (pk) v, (pk) sqrt v, (common matrix) v
    pub fn commit(&self, prepared_message_m: &Matrix<Poly>) -> (Matrix<Poly>, Matrix<Poly>) {
        if cfg!(debug_assertions){
            assert_eq!(prepared_message_m.col_n, 1);
            assert_eq!(prepared_message_m.row_m, self.message_dimension_l + self.ck_binding_height_n);
        }

        let r = (0..self.randomness_vector_dimension_k).map(|_| Poly::random_binomial()).collect();
        let r_mat  = Matrix::from_vec(r);

        ((&(&(self.ck) * &r_mat) + prepared_message_m), r_mat)
    }

    pub fn commit_partial(&self, prepared_message_m: &Matrix<Poly>) -> (Matrix<Poly>, Matrix<Poly>) {
        if cfg!(debug_assertions){
            assert_eq!(prepared_message_m.col_n, 1);
            assert!(prepared_message_m.row_m <= self.message_dimension_l + self.ck_binding_height_n);
        }

        let r = (0..self.randomness_vector_dimension_k).map(|_| Poly::random_binomial()).collect();
        let r_mat  = Matrix::from_vec(r);

        let (ck_split_1, _) = self.ck.v_split(prepared_message_m.val.len());
        // println!("ck_rowm: {}, ck_split_1_rowm: {}",self.ck.row_m, ck_split_1.row_m);
        ((&(&ck_split_1 * &r_mat) + prepared_message_m), r_mat)
    }

    pub fn commit_with_r(&self, prepared_message_m: &Matrix<Poly>, r: &Matrix<Poly>) -> Matrix<Poly> {
        if cfg!(debug_assertions){
            assert_eq!(prepared_message_m.col_n, 1);
            assert_eq!(prepared_message_m.row_m, self.message_dimension_l+self.ck_binding_height_n);
            assert_eq!(r.col_n, 1);
            assert_eq!(r.row_m, self.randomness_vector_dimension_k);
        }

        &(&(self.ck) * r) + prepared_message_m
    }

    pub fn commit_full_partial(&self, prepared_message_m: &Matrix<Poly>, second_message: &Matrix<Poly>) -> (Matrix<Poly>, Matrix<Poly>) {
        let diff = self.message_dimension_l + self.ck_binding_height_n-  prepared_message_m.row_m;
        if cfg!(debug_assertions){
            assert_eq!(prepared_message_m.col_n, 1);
            assert!(prepared_message_m.row_m <= self.message_dimension_l + self.ck_binding_height_n);
            assert_eq!(second_message.row_m, self.second_message_dimension);
            assert_eq!(second_message.col_n, 1);
        }

        let second_message_commit = &(self.ck_atjai) * second_message;
        let mut prepare_second_message_matrix_val = second_message_commit.to_vec();
        for _ in 0..(self.message_dimension_l + self.ck_binding_height_n - self.ck_atjai.row_m - diff){
            prepare_second_message_matrix_val.push(Poly::zero());
        }
        let second_message_commit_full = Matrix::from_vec(prepare_second_message_matrix_val);

        let r = (0..self.randomness_vector_dimension_k).map(|_| Poly::random_binomial()).collect();
        let r_mat  = Matrix::from_vec(r);


        let (ck_split_1, _) = self.ck.v_split(prepared_message_m.val.len());
        (&(&(&ck_split_1 * &r_mat) + prepared_message_m)  + &second_message_commit_full, r_mat)
    }

    pub fn commit_full(&self, prepared_message_m: &Matrix<Poly>, second_message: &Matrix<Poly>) -> (Matrix<Poly>, Matrix<Poly>) {
        if cfg!(debug_assertions){
            assert_eq!(prepared_message_m.col_n, 1);
            assert_eq!(prepared_message_m.row_m, self.message_dimension_l + self.ck_binding_height_n);
            assert_eq!(second_message.row_m, self.second_message_dimension);
            assert_eq!(second_message.col_n, 1);
        }

        let second_message_commit = &(self.ck_atjai) * second_message;
        let mut prepare_second_message_matrix_val = second_message_commit.to_vec();
        for _ in 0..(self.message_dimension_l + self.ck_binding_height_n - self.ck_atjai.row_m){
            prepare_second_message_matrix_val.push(Poly::zero());
        }
        let second_message_commit_full = Matrix::from_vec(prepare_second_message_matrix_val);

        let r = (0..self.randomness_vector_dimension_k).map(|_| Poly::random_binomial()).collect();
        let r_mat  = Matrix::from_vec(r);

        (&(&(&(self.ck) * &r_mat) + prepared_message_m) + &second_message_commit_full, r_mat)
    }

    //// First phase of commitment A1s1 + A2s2
    pub fn zkp_abdlop_initial_commit(&self) ->( Matrix<Poly>,Matrix<Poly>,Matrix<Poly>){
        // Sample y1
        let mut y1 = Vec::new();
        for _i in 0..(self.second_message_dimension){
            let mut new_row = Vec::new();
            for _j in 0..1{
                new_row.push(Poly::random_discrete_gaussian(self.std_dev_sigma));
            }
            y1.push(new_row);
        }
        let y1_mat = Matrix::new(y1, self.second_message_dimension, 1);

        // Sample y2
        let mut y2 = Vec::new();
        for _i in 0..(self.randomness_vector_dimension_k){
            let mut new_row = Vec::new();
            for _j in 0..1{
                new_row.push(Poly::random_discrete_gaussian(self.std_dev_sigma));
            }
            y2.push(new_row);
        }
        let y2_mat = Matrix::new(y2, self.randomness_vector_dimension_k, 1);

        let (ck_top,_) = self.ck.slice_into_2(self.ck_binding_height_n);

        (&(&self.ck_atjai * &y1_mat) + &(&ck_top * &y2_mat), y1_mat,y2_mat)

    }

    pub fn zkp_abdlop_initial_commit_custom_sigma(&self, sigma1: u32, sigma2 :u32) ->( Matrix<Poly>,Matrix<Poly>,Matrix<Poly>){
        // Sample y1
        let mut y1 = Vec::new();
        for _i in 0..(self.second_message_dimension){
            let mut new_row = Vec::new();
            for _j in 0..1{
                new_row.push(Poly::random_discrete_gaussian(sigma1));
            }
            y1.push(new_row);
        }
        let y1_mat = Matrix::new(y1, self.second_message_dimension, 1);

        // Sample y2
        let mut y2 = Vec::new();
        for _i in 0..(self.randomness_vector_dimension_k){
            let mut new_row = Vec::new();
            for _j in 0..1{
                new_row.push(Poly::random_discrete_gaussian(sigma2));
            }
            y2.push(new_row);
        }
        let y2_mat = Matrix::new(y2, self.randomness_vector_dimension_k, 1);

        let (ck_top,_) = self.ck.slice_into_2(self.ck_binding_height_n);

        (&(&self.ck_atjai * &y1_mat) + &(&ck_top * &y2_mat), y1_mat,y2_mat)

    }


    /// Extract plaintext message m from a QPADL commitment `cm` using trapdoors st1, st2.
    pub fn extract_without_r_message(
        bdlop: &ABDLOP,
        st1: &Matrix<Poly>,
        st2: &Matrix<Poly>,
        cm: &Matrix<Poly>,
    ) -> Poly {
        use std::{ops::Neg, vec};
        // split commitment into (t0, t1, t2, t3)
        let (t0, t1, t2, _t3) = cm.slice_into_4(bdlop.ck_binding_height_n);

        // eq1 = t1 - st1*t0 = epsilon1 + m
        let eq1 = &t1 + &((*&st1 * &t0).neg());

        // eq2 = t2 - st2*t0 = epsilon2 + sqrt(q)*m
        let eq2 = &t2 + &((*&st2 * &t0).neg());

        // temp = eq2 - sqrt(q)*eq1 = epsilon2 - sqrt(q)*epsilon1
        let mut sqrt_eq1 = eq1.clone();
        sqrt_eq1 *= *MODULUS_SQRT_ZQ;

        let temp = &eq2 + &(sqrt_eq1.neg());
        assert_eq!(temp.row_m, 1);
        assert_eq!(temp.col_n, 1);

        let temp_poly = temp.val[0][0].clone();

        // Recover epsilon2 by lifting coefficients mod sqrt(q)
        // signed_temp_poly is in "signed" representation ([-sqrtq/2, sqrtq/2] style)
        let signed_temp_poly = PolyCanon::mod_to_sign_custom(
            &temp_poly
                .into_canonical_poly()
                .coeff
                .map(|x| {
                    let rem: i128 = x.rem_euclid(MODULUS_SQRT as i128);
                    if rem < Poly_I128::zero() {
                        Poly_U128::from(rem + (MODULUS_SQRT as i128))
                    } else {
                        Poly_U128::from(rem)
                    }
                }),
            MODULUS_SQRT as i128,
        );

        // Put epsilon2 back into mod-q representation
        let epsilon2 = Poly::new(PolyCanon::sign_to_mod(&signed_temp_poly));

        // epsilon1:
        // temp = epsilon2 - sqrt(q)*epsilon1  (mod q)
        // => sqrt(q)*epsilon1 = epsilon2 - temp
        // => epsilon1 = (epsilon2 - temp) * inv_sqrt(q)
        let mut epsilon1 = (temp_poly + epsilon2.neg()).neg();
        epsilon1 *= *MODULUS_SQRT_INV_ZQ;

        // m = eq1 - epsilon1
        let plaintext = eq1.val[0][0].clone() + (epsilon1.neg());

        plaintext
    }


}

#[cfg(test)]
mod tests{
    use crate::{common_static::{MODULUS_SQRT_INV_ZQ, MODULUS_SQRT_ZQ}, polynomial::{Poly_I128, Poly_U128}, sampler::Sampler};
    // use crypto_bigint::U128;
    use rayon::iter::{IntoParallelIterator, ParallelIterator, IndexedParallelIterator};
    // use core::random;
    // use std::{ops::{Div, Mul, Neg}, vec};
    use std::{ops::Neg, vec};
    use crate::{common::{BASEMUL_DEGREE}, matrix::Matrix};
    use crate::common_trait::SigmaReflect;

    use num_traits::{One, Zero};


    use crate::{common::{DEGREE, MODULUS_SQRT, MODULUS_SQRT_INV}, polynomial::{Poly, PolyCanon}};

    use super::ABDLOP;

    #[test]
    fn test_bdlop(){
        // Check homomorphic commitment property + opening
        let bdlop = ABDLOP::new_random_test_instance(1,0);
        let m_vec = bdlop.prepare_simple_message(vec![Poly::random()]);
        let (cm1, r1) = bdlop.commit(&m_vec);

        let m_vec2 = bdlop.prepare_simple_message(vec![Poly::random()]);
        let (cm2, r2) = bdlop.commit(&m_vec2);

        let m_sum = &m_vec + &m_vec2;
        let r_sum = &r1 + &r2;
        
        let cm3 = bdlop.commit_with_r(&m_sum, &r_sum);

        // Homomorphic commit with opening
        assert_eq!(cm3, &cm1+&cm2);
        assert_eq!(cm3, bdlop.commit_with_r(&m_sum, &r_sum));
    }

    #[test]
    fn test_extractability_honest_prover(){
        let (bdlop,st1,st2, et1, et2) = ABDLOP::new_random_instance();
        // let message =  Poly::new([0;DEGREE]);
        let message =  Poly::random();
        let m_vec = bdlop.prepare_qpadl_message(message.clone());
        let (cm1, r1) = bdlop.commit(&m_vec);

        let (t0,t1,t2, _t3) = cm1.slice_into_4(bdlop.ck_binding_height_n);
    
        //eq1 = t1 - st1 * t0 = et1r + m = epsilon1 + m
        let eq1 = &t1 + &( (&st1*&t0).neg() );

        //t2 - st2 * t0 = et2r + /sqrt m = epsilon2 + sqrt m
        let eq2 =  &t2 + &((&st2 * &t0).neg());

        // eq2 - sqrt eq1 = epsilon_2 - sqrt epsilon1
        let mut sqrt_eq1 = eq1.clone();
        sqrt_eq1 *= *MODULUS_SQRT_ZQ;
        let temp = &eq2 + &(sqrt_eq1.neg());
        assert_eq!(temp.row_m,1);
        assert_eq!(temp.col_n,1);
        let temp_poly = temp.val[0][0].clone();
        // ( +- x mod sqrt q) => (  )
        // println!("{:?}",temp_poly.into_canonical_poly().coeff.map(|x| x.rem(&MODULUS_SQRT_I128_NONZERO)));
        let signed_temp_poly = PolyCanon::mod_to_sign_custom(&temp_poly.into_canonical_poly().coeff.map(|x| {
            let rem = x.rem_euclid(MODULUS_SQRT as i128);
            // let rem = x.rem(&MODULUS_SQRT_I128_NONZERO);
            if rem < Poly_I128::zero(){
                return Poly_U128::from(rem + (MODULUS_SQRT as i128))
            }
            else{
                return Poly_U128::from(rem)
            }
        }
        ), MODULUS_SQRT as i128);
        // let signed_temp_poly = PolyCanon::mod_to_sign(&temp_poly.into_canonical_poly().coeff.map(|x| x.rem_euclid(MODULUS_SQRT as i64) as u64), MODULUS_SQRT);
        // Putting back to the original mod for remaining calculation.
        let epsilon2 = Poly::new(PolyCanon::sign_to_mod(&signed_temp_poly));
        let ref_epsilon2_mat = &et2 * &r1;
        assert_eq!(ref_epsilon2_mat.row_m, 1);
        assert_eq!(ref_epsilon2_mat.col_n, 1);
        let ref_epsilon2 = ref_epsilon2_mat.val[0][0].clone();
        let mut message_sqrtq = message.clone();
        message_sqrtq *= *MODULUS_SQRT_ZQ;
        let ref_epsilon2_sqrtm = &ref_epsilon2 + &message_sqrtq;
        assert_eq!(eq2.val[0][0].into_canonical_poly().coeff, ref_epsilon2_sqrtm.into_canonical_poly().coeff, "Epsilon 2 + sqrtm calculation is wrong");
        assert_eq!(epsilon2.into_canonical_poly().coeff, ref_epsilon2.into_canonical_poly().coeff, "Epsilon 2 calculation is wrong");

        //Now compute epsilon1
        let mut epsilon1_sqrtq = (temp_poly + epsilon2.neg()).neg();
        epsilon1_sqrtq *= *MODULUS_SQRT_INV_ZQ;
        let epsilon1 = epsilon1_sqrtq;
        let ref_epsilon1_mat = &et1 * &r1;
        let ref_epsilon1 = ref_epsilon1_mat.val[0][0].clone();
        assert_eq!(ref_epsilon1, epsilon1, "Epsilon 1 Calculation is wrong");
        let plaintext = &(eq1.val[0][0].clone()) +  &(epsilon1.neg());

        assert_eq!(plaintext.canonical_repr(),message.canonical_repr());
    }
    #[test]
    fn test_extractability_honest_prover_refactored() {
        let (bdlop, st1, st2, _et1, _et2) = ABDLOP::new_random_instance();

        let message = Poly::random();
        let m_vec = bdlop.prepare_qpadl_message(message.clone());
        let (cm1, _r1) = bdlop.commit(&m_vec);

        let extracted = ABDLOP::extract_without_r_message(&bdlop, &st1, &st2, &cm1);

        assert_eq!(extracted.canonical_repr(), message.canonical_repr());
    }


    #[test]
    fn test_proof_of_asset(){
        let (bdlop,_st1,_st2, _et1, _et2) = ABDLOP::new_random_instance();
        let (ck_top, ck_m1, ck_m2, ck_m3) = bdlop.ck.slice_into_4(bdlop.ck_binding_height_n);
        
        // let poa_y = Poly::random_discrete_gaussian(bdlop.std_dev_sigma as f64);
        let r = (0..bdlop.randomness_vector_dimension_k).map(|_| Poly::random_binomial()).collect();
        let poa_y  = Matrix::from_vec(r);
        let poa_w = &ck_top * &poa_y;
        let poa_u_mult =  &(&(&ck_m1 * &poa_y) * &(&ck_m1 * &poa_y)) +  &(&ck_m2 * &poa_y);
        let masking_g = Poly::random_constant_unmasked();

        // let message =  Poly::random_integer().neg();
        let message =  Poly::random_integer();
        // let message =  Poly::random_negative_integer();
        let m_vec = bdlop.prepare_qpadl_message(message.clone());
        let (original_commit, original_r) = bdlop.commit(&m_vec);
        let (ori_ar,ori_com1_m,_ori_com2_sqrtm, _ori_com3_m) = original_commit.slice_into_4(bdlop.ck_binding_height_n);

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
        // let _message_vec = 0;
        let perpare_message = &Matrix::from_vec(padding_vec);
        let cm1 = bdlop.commit_with_r(&perpare_message, &original_r);
        let (_new_cm_ar,new_cm_bin,new_cm_garbage, new_cm_maskingg) = cm1.slice_into_4(bdlop.ck_binding_height_n);
        
        let random_phi = Poly::random();
        let random_phi_qt = random_phi.binary_compose_transpose_leftmultiply_self();
        let function_f = (message.bin_repr() * random_phi_qt.clone()) + (message*random_phi.clone()).neg();
        let masked_h = function_f +masking_g;

        let first_dl_coeff_arr = masked_h.canonical_repr();
        for i in 0..BASEMUL_DEGREE{
            assert_eq!(first_dl_coeff_arr[i],Poly_U128::zero());
        }

        let u_lin = &(ck_m3.clone() + &ck_m1 *&random_phi_qt + (&ck_m1* &random_phi).neg()) * &poa_y;
        let challenge = Poly::random();
        let poa_z = poa_y + &original_r * &challenge;

        // Verification
        let az = &ck_top* &poa_z;
        assert_eq!(az, poa_w+ &ori_ar * &challenge);

        let f_prime = &ck_m1 * &poa_z + (&new_cm_bin * &challenge).neg();
        let f_prime_2 =  &ck_m2 * &poa_z + (&new_cm_garbage * &challenge).neg();
        assert_eq!(Poly::zero(), f_prime.to_item_t() * (f_prime.to_item_t()+challenge.clone()) + f_prime_2.to_item_t() + poa_u_mult.to_item_t().neg());

        let z_ulin = &(ck_m3 + &ck_m1 *&random_phi_qt + (&ck_m1* &random_phi).neg()) * &poa_z;
        let com_f = &new_cm_bin * &random_phi_qt + (&ori_com1_m * &random_phi).neg();
        assert_eq!(z_ulin, &( new_cm_maskingg + com_f +  Matrix::from_vec(vec![masked_h.neg()])) * &challenge + u_lin );
    }

    #[test]
    fn test_abdlop_proof_of_opening(){
        let (bdlop, _st1,_st2, _et1, _et2) = ABDLOP::new_random_instance();
        let message =  Poly::random();
        let m_vec = bdlop.prepare_qpadl_message(message.clone());
        let (_cm1, r1) = bdlop.commit(&m_vec);
        // let (t0,t1,t2, t3) = cm1.slice_into_4(bdlop.ck_binding_height_n);

        let (abdlop,_,_, _, _) = ABDLOP::new_random_instance();
        let (ck_top, _ )= abdlop.ck.slice_into_2(abdlop.ck_binding_height_n);
        let (cm_proof, r_proof) = abdlop.commit_full(&m_vec, &r1);
        let (cm_top, _) = cm_proof.slice_into_2(abdlop.ck_binding_height_n);

        // ZKProof of opening for ABDLOP
        let (w,y1,y2) = abdlop.zkp_abdlop_initial_commit();
        let challenge = ABDLOP::get_challenge();

        let cr1 = &r1 * challenge.clone();
        let z1 = &y1 + &(cr1);
        let cr2  = &r_proof * challenge.clone();
        let z2 = &y2 + &cr2;

        let lhs = &(&abdlop.ck_atjai * &z1) + &(&ck_top * &z2);
        let rhs = &w + &(&cm_top * challenge);

        assert_eq!(lhs,rhs);

    }

    #[test]
    fn test_proof_of_consistency(){
        let (bdlop,_st1,_st2, _et1, _et2) = ABDLOP::new_random_instance();
        let value =  Poly::random_integer();
        let m_vec = bdlop.prepare_qpadl_message(value.clone());
        let (cm1, r1) = bdlop.commit(&m_vec);
        let (ori_com0,ori_com1,ori_com2, ori_com3) = cm1.slice_into_4(bdlop.ck_binding_height_n);
        let (ori_ck_top, ori_ck_m1, ori_ck_m2, ori_ck_m3 )= bdlop.ck.slice_into_4(bdlop.ck_binding_height_n);

        let (abdlop,_,_, _, _) = ABDLOP::new_random_instance();
        let (ck_top, ck_m1, ck_m2, ck_m3 )= abdlop.ck.slice_into_4(abdlop.ck_binding_height_n);

        // Sample g and y3
        let y3 = Poly::random_discrete_gaussian(bdlop.std_dev_sigma);
        let masking_g = Poly::random_constant_unmasked();
        assert_eq!(masking_g.canonical_repr()[0],Poly_U128::zero());
        let prepared_message = abdlop.prepare_simple_message(vec![value.clone(), y3.clone(), masking_g.clone()]);
        let (cm_proof, r_proof) = abdlop.commit_full(&prepared_message, &r1);
        let (cm_top, cm_m, cm_gp1, cm_gp2) = cm_proof.slice_into_4(abdlop.ck_binding_height_n);

        //  Sample random binary challenge matrix
        let (bin_challenge_mat, bin_challenge_mat_poly_sigma) = Poly::random_binary_vector(bdlop.randomness_vector_dimension_k);
        // Here Ri*vec<r_i> 
        let mut poly_coeff = vec![Poly_U128::zero();DEGREE];
        assert_eq!(bin_challenge_mat.len(), DEGREE);
        assert!(DEGREE >= 256); //For 128 security level, this need to be 256 though for theorem/lemma to go through.
        let r1_coeffs_flatten = r1.to_vec().iter().fold(vec![],|acc, x| [acc,x.clone().flatten()].concat() );
        for i in 0..bin_challenge_mat.len(){
            // bin_challenge_mat[i]
            assert_eq!(bin_challenge_mat[i].len(), DEGREE*bdlop.randomness_vector_dimension_k);
            poly_coeff[i] = PolyCanon::inner_product(bin_challenge_mat[i].clone(), r1_coeffs_flatten.clone());
        }
        let rir1_poly = Poly::new(poly_coeff.try_into().unwrap());
        let z3 = &y3 + &rir1_poly;

        // Sample linear combination challenge dj, d'j
        let dj_vec = Poly::random_zq_vec(DEGREE);
        let dj_vec_prime = Poly::random_zq_vec(DEGREE-1);

        // Compute Responses
        // Sum over d1(sigma_rj . r_tai + sigma_ej . y_3 - sigma_ej . z3) 
        let mut ej_vec = vec![];
        let mut ej_vec_sigma = vec![];
        // let r1_sigma_mat = r1.map(|f| f.sigma_reflect());
        for i in 0..DEGREE{
            let mut ez = [Poly_U128::zero();DEGREE];
            ez[i] = Poly_U128::one();
            let ez_poly = Poly::new(ez);
            ej_vec.push(Matrix::from_vec_transpose(vec![ez_poly.clone()])); //Transpose because it is left multiplicaiton.
            ej_vec_sigma.push(Matrix::from_vec_transpose(vec![ez_poly.sigma_reflect()])); //Transpose because it is left multiplicaiton.
        }


        // let bin_challenge_mat_poly_sigma: Vec<Matrix<Poly>> = bin_challenge_mat_poly.iter().map(|vec| vec.map(|poly| poly.sigma_reflect())).collect();
        let x_ez_term = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_sigma, &Matrix::from_vec(vec![z3.clone()]));
        let x_ey_term = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_sigma, &Matrix::from_vec(vec![y3.clone()]));
        let x_rr_term = ABDLOP::compute_product_sum(&dj_vec, &bin_challenge_mat_poly_sigma, &r1);
        let x_v_term = ABDLOP::compute_product_sum(&dj_vec_prime, &ej_vec_sigma[1..].to_vec(), &Matrix::from_vec(vec![value.clone()]));

        let h_poly = x_rr_term +  x_ey_term + x_ez_term.neg() + x_v_term + masking_g.clone();
        // Equation (d)
        assert_eq!(h_poly.canonical_repr()[0],Poly_U128::zero());

        // ZKProof of opening for ABDLOP
        let (w,y1,y2) = abdlop.zkp_abdlop_initial_commit();

        // All other y values
        // Ay1
        let leftover_y_0 = &ori_ck_top * &y1;
        let negative_by2 = (&ck_m1 * &y2).neg();
        let leftover_y_1 = (&ori_ck_m1 * &y1) + negative_by2.clone();
        let mut neg_sqrtq_by2 = negative_by2.clone();
        neg_sqrtq_by2 *= *MODULUS_SQRT_ZQ;
        let leftover_y_2 = (&ori_ck_m2 * &y1) + neg_sqrtq_by2;
        let leftover_y_3 =(&ori_ck_m3 * &y1) + negative_by2.clone();

        let leftover_y_4_1 = ABDLOP::compute_product_sum(&dj_vec, &bin_challenge_mat_poly_sigma, &y1);
        let leftover_y_4_2 = ABDLOP::compute_product_sum(&dj_vec_prime, &ej_vec_sigma[1..].to_vec(), &negative_by2);        
        let leftover_y_4_3 = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_sigma, &(&ck_m2 * &y2).neg());
        let leftover_y_4 =  leftover_y_4_1+ leftover_y_4_2 + leftover_y_4_3 + (&ck_m3 * &y2).neg().to_item_t();

        // Final challenge
        let challenge = ABDLOP::get_challenge();

        // Compute final responses
        let cr1 = &r1 * &challenge;
        let z1 = &y1 + &(cr1);
        let cr2  = &r_proof * &challenge;
        let z2 = &y2 + &cr2;

        let lhs = (&abdlop.ck_atjai * &z1) + (&ck_top * &z2);
        let rhs = &w + &(&cm_top * &challenge);
        // Equaton (e)
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
        let z_4_2 = ABDLOP::compute_product_sum(&dj_vec_prime, &ej_vec_sigma[1..].to_vec(), &Matrix::from_vec(vec![masked_message_cf1_minus_bz2.to_item_t()]));
        let z_4_3 = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_sigma, &masked_message_cu1_minus_bz2);
        let ez_sigma = ABDLOP::compute_product_sum(&dj_vec, &ej_vec_sigma, &Matrix::from_vec(vec![z3]));
        // let compute_leftover_4 = z_4_2 + (x_v_term *challenge).neg();
        let compute_leftover_4 = z_4_1+z_4_2+ z_4_3 + masked_message_cu2_minus_bz2.to_item_t() + ((h_poly + ez_sigma) * challenge).neg();
        assert_eq!(compute_leftover_4, leftover_y_4);
    }
}