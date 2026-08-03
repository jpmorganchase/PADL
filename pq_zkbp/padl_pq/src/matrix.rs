use std::ops::{MulAssign, Mul, Add, Neg};
use num_traits::{Zero,One};
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use rug::{Integer, Float};
use crate::{common_trait::{Norm, SigmaReflect}, polynomial::Poly_U128};
use serde::{Serialize, Deserialize};


// This is a row major implemetation. I.E Matrix = [Row<ColItem,ColItem>, Row<...>, Row<...>]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Matrix<T>{
    pub val : Vec<Vec<T>>,
    pub row_m: usize,
    pub col_n: usize
}

impl<'a, T> Neg for &'a Matrix<T> where &'a T:Neg, T:Zero, T:Clone, T:One, T:Send, T:Sync, T:Norm, T:SigmaReflect, &'a T: Neg<Output = T>{
    type Output = Matrix<T>;
    fn neg(self) -> Self::Output {
        let mut new_matrix: Vec<Vec<T>> = Vec::with_capacity(self.row_m);
        for row_index in 0..self.row_m{
            let mut new_row: Vec<T> = Vec::with_capacity(self.col_n);
            for col_index in 0..self.col_n{
                new_row.push(-&self.val[row_index][col_index]);
            }
            new_matrix.push(new_row);
        }
        Matrix::new(new_matrix, self.row_m, self.col_n)
    }
}

impl<'a, T> Mul for &'a Matrix<T> where T:Zero,T: Clone,T: One, T:Send, T:Sync, T:Norm, T:SigmaReflect, &'a T: Mul<Output = T>{
    type Output = Matrix<T>;

    fn mul(self, rhs: Self) -> Self::Output {
        if cfg!(debug_assertions){
            // println!("Matrix Size: mxk: {}x{}, kxn: {}x{}", self.row_m, self.col_n, rhs.row_m, rhs.col_n);
            // println!("PAss: m, k: {}x{}", self.val.len(), rhs.val.len());
            // println!("PAss: k, n: {:?}x{}", self.val.iter().map(|vec| vec.len()).collect::<Vec<usize>>(), rhs.val.len());
            assert_eq!(self.col_n, rhs.row_m);
        }
        // println!("Matrix Size: mxk: {}x{}, kxn: {}x{}", self.row_m, self.col_n, rhs.row_m, rhs.col_n);
        match self.row_m > 1{
            true => {self.clone().mul_par_row(rhs)},
            _ => {
                match self.col_n > 1{
                    true => {self.clone().mul_par_col(rhs)},
                    _ => {
                        let mut new_matrix: Vec<Vec<T>> = Vec::with_capacity(self.row_m);
                        for row_index in 0..self.row_m{
                            let mut new_row: Vec<T> = Vec::with_capacity(rhs.col_n);
                            for col_index2 in 0..rhs.col_n{
                                let mut sum: T = T::zero();
                                for col_index in 0..self.col_n{
                                    // println!("lhs: [{}][{}], rhs; [{}][{}]",row_index,col_index, col_index, col_index2);
                                    sum = sum + (&self.val[row_index][col_index])*(&rhs.val[col_index][col_index2]);
                                }
                                new_row.push(sum);
                            }
                            new_matrix.push(new_row);
                        }

                        Matrix::<T>{ val: new_matrix, row_m : self.row_m, col_n: rhs.col_n}
                    }
                }
            }
        }


    }
}
// impl<T> Mul for Matrix<T> where T:Zero, T: Mul<Output = T>{
//     type Output = Matrix<T>;
//     fn mul(self, rhs: Self) -> Self::Output {
//         &self * &rhs
//     }
// }

// , for<'b> &'a T: Mul<&'b T, Output = T>
impl<'a, T> Mul<T> for &'a Matrix<T> where T:Zero, T:Mul<Output = T>, T:Clone{
    type Output = Matrix<T>;

    fn mul(self, rhs: T) -> Self::Output {
        // println!("invoked");

        let mut new_matrix: Vec<Vec<T>> = Vec::with_capacity(self.row_m);
        for row_index in 0..self.row_m{
            let mut new_row: Vec<T> = Vec::with_capacity(self.col_n);
            for col_index in 0..self.col_n{
                let new_val = (self.val[row_index][col_index]).clone() * rhs.clone();
                new_row.push(new_val);
            }
            new_matrix.push(new_row);
        }

        Matrix::<T>{ val: new_matrix, row_m : self.row_m, col_n: self.col_n}
    }
}

impl<'a, T> Mul<&T> for &'a Matrix<T> where T:Zero, T:Mul<Output = T>, T:Clone, T:Send, T:Sync, T:One, T:Norm, T:SigmaReflect{
    type Output = Matrix<T>;

    fn mul(self, rhs: &T) -> Self::Output {
        match self.row_m > 1{
            true => {
                self.clone().mul_par_row_t(rhs)
            }
            _ => {
                let mut new_matrix: Vec<Vec<T>> = Vec::with_capacity(self.row_m);
                for row_index in 0..self.row_m{
                    let mut new_row: Vec<T> = Vec::with_capacity(self.col_n);
                    for col_index in 0..self.col_n{
                        let new_val = (self.val[row_index][col_index]).clone() * rhs.clone();
                        new_row.push(new_val);
                    }
                    new_matrix.push(new_row);
                }
                Matrix::<T>{ val: new_matrix, row_m : self.row_m, col_n: self.col_n}
            }
        }


        // for row_index in 0..self.row_m{
        //     let mut new_row: Vec<T> = Vec::with_capacity(self.col_n);
        //     for col_index in 0..self.col_n{
        //         let new_val = (self.val[row_index][col_index]).clone() * rhs.clone();
        //         new_row.push(new_val);
        //     }
        //     new_matrix.push(new_row);
        // }

        // Matrix::<T>{ val: new_matrix, row_m : self.row_m, col_n: self.col_n}
    }
}

// impl<'a, T> Mul<&T> for &'a Matrix<T> where T:Zero, &'a T: Mul<&'a T, Output = T>, T:Clone{
//     type Output = Matrix<T>;

//     fn mul(self, rhs: &T) -> Self::Output {
//         let mut new_matrix: Vec<Vec<T>> = Vec::with_capacity(self.row_m);
//         for row_index in 0..self.row_m{
//             let mut new_row: Vec<T> = Vec::with_capacity(self.col_n);
//             for col_index in 0..self.col_n{
//                 let new_val = &(self.val[row_index][col_index]) * rhs;
//                 new_row.push(new_val);
//             }
//             new_matrix.push(new_row);
//         }

//         Matrix::<T>{ val: new_matrix, row_m : self.row_m, col_n: self.col_n}
//     }
// }

impl<T> MulAssign<Poly_U128> for Matrix<T> where T: MulAssign<Poly_U128> {
    fn mul_assign(&mut self, rhs: Poly_U128) {
        for row in 0..self.row_m{
            for col in 0..self.col_n{
                self.val[row][col] *= rhs;
            }
        }
    }
}

impl<'a, T> Add for &'a Matrix<T> where T:Zero,  &'a T: Add<Output = T>{
    type Output = Matrix<T>;

    fn add(self, rhs: Self) -> Self::Output {
        if cfg!(debug_assertions){
            assert_eq!(self.col_n, rhs.col_n);
            assert_eq!(self.row_m, rhs.row_m);
        }

        let mut mat: Vec<Vec<T>> = Vec::with_capacity(self.row_m);
        for row_i in 0..self.row_m{
            let mut row_vec: Vec<T> = Vec::with_capacity(self.col_n);
            for col_j in 0..self.col_n{
                row_vec.push((&self.val[row_i][col_j] + &rhs.val[row_i][col_j]).try_into().unwrap())
            }
            mat.push(row_vec);
        }
        Matrix::<T>{ val: mat, row_m : self.row_m, col_n: self.col_n}
    }
}

impl<T> Add for Matrix<T> where for<'a> &'a T: Add<&'a T, Output = T>
{
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        if cfg!(debug_assertions){
            assert_eq!(self.col_n, rhs.col_n);
            assert_eq!(self.row_m, rhs.row_m);
        }

        let mut mat: Vec<Vec<T>> = Vec::with_capacity(self.row_m);
        for row_i in 0..self.row_m{
            let mut row_vec: Vec<T> = Vec::with_capacity(self.col_n);
            for col_j in 0..self.col_n{
                row_vec.push((&self.val[row_i][col_j] + &rhs.val[row_i][col_j]).try_into().unwrap())
            }
            mat.push(row_vec);
        }
        Matrix::<T>{ val: mat, row_m : self.row_m, col_n: self.col_n}
    }
}


impl<'a, T> Matrix<T> where T:Zero, T:One, T:Clone, T:Sync, T:Send, T:Norm, T:SigmaReflect {
    pub fn empty()-> Self{
        Matrix::<T>{val: vec![], row_m:0, col_n:0}
    }

    pub fn mul_par_row (self, rhs: &Self) -> Self{
        let new_matrix: Vec<Vec<T>> = (0..self.row_m).into_par_iter().map( |row_index| {
            let mut new_row: Vec<T> = Vec::with_capacity(rhs.col_n);
            for col_index2 in 0..rhs.col_n{
                let mut sum: T = T::zero();
                for col_index in 0..self.col_n{
                    // println!("lhs: [{}][{}], rhs; [{}][{}]",row_index,col_index, col_index, col_index2);
                    sum = sum + (self.val[row_index][col_index].clone())*(rhs.val[col_index][col_index2].clone());
                }
                new_row.push(sum);
            }
            new_row
        }).collect();

        Matrix::<T>{ val: new_matrix, row_m : self.row_m, col_n: rhs.col_n}
    }
    pub fn mul_par_row_t(self, rhs: &T) -> Self{
        let new_matrix: Vec<Vec<T>> = (0..self.row_m).into_par_iter().map( |row_index| {
            let mut new_row: Vec<T> = Vec::with_capacity(self.col_n);
            for col_index in 0..self.col_n{
                // println!("lhs: [{}][{}], rhs; [{}][{}]",row_index,col_index, col_index, col_index2);
                let new_val = (self.val[row_index][col_index].clone())*(rhs.clone());
                new_row.push(new_val);
            }
            new_row
        }).collect();

        //     let mut new_row: Vec<T> = Vec::with_capacity(self.col_n);
        //     for col_index in 0..self.col_n{
        //         let new_val = (self.val[row_index][col_index]).clone() * rhs.clone();
        //         new_row.push(new_val);
        //     }
        //     new_matrix.push(new_row);
        // }

        Matrix::<T>{ val: new_matrix, row_m : self.row_m, col_n: self.col_n}
    }
    pub fn mul_par_col (self, rhs: &Self) -> Self{
        let mut new_matrix: Vec<Vec<T>> = Vec::with_capacity(self.row_m);
        for row_index in 0..self.row_m{
            let new_row: Vec<T> = (0..rhs.col_n).into_par_iter().map(|col_index2|{
                let mut sum: T = T::zero();
                for col_index in 0..self.col_n{
                    // println!("lhs: [{}][{}], rhs; [{}][{}]",row_index,col_index, col_index, col_index2);
                    sum = sum + (self.val[row_index][col_index].clone())*(rhs.val[col_index][col_index2].clone());
                }
                sum
            }).collect();
            new_matrix.push(new_row);
        }

        Matrix::<T>{ val: new_matrix, row_m : self.row_m, col_n: rhs.col_n}

    }

    pub fn new(val: Vec<Vec<T>>, row_m:usize , col_n: usize) -> Self{
        if cfg!(debug_assertions){
            assert_eq!(row_m, val.len());
            for each_row in &val{
                assert_eq!(col_n, each_row.len());
            }
        }
        Matrix::<T>{ val: val, row_m: row_m, col_n: col_n }
    }


    pub fn slice_into_custom(&self, binding_row_num: usize) -> Vec<Matrix<T>>{
        let mut res : Vec<Matrix<T>> = vec![];
        res.push(Matrix::new(self.val[0..binding_row_num].to_vec(),binding_row_num,self.col_n));
        let number_of_item = self.row_m - binding_row_num;
        for index in 0..number_of_item{
            res.push(Matrix::new(self.val[binding_row_num+index..binding_row_num+index+1].to_vec(),1,self.col_n));
        }
        res
    }

    ///This is QPADL scheme specific. TODO: slice semantic with reference is better.
    /// We slice into 3 sectino. A (random matrix), B1 (trapdoor) for m, B2 (trapdoor) for sqrt_m, B3
    pub fn slice_into_4(&self, binding_row_num: usize) -> (Matrix<T>,Matrix<T>,Matrix<T>, Matrix<T>){
        (Matrix::new(self.val[0..binding_row_num].to_vec(),binding_row_num,self.col_n), Matrix::new(self.val[binding_row_num..binding_row_num+1].to_vec(),1,self.col_n),Matrix::new(self.val[binding_row_num+1..binding_row_num+2].to_vec(),1,self.col_n),Matrix::new(self.val[binding_row_num+2..binding_row_num+3].to_vec(),1,self.col_n))
    }


    pub fn slice_into_3(&self, binding_row_num: usize) -> (Matrix<T>,Matrix<T>,Matrix<T>){
        (Matrix::new(self.val[0..binding_row_num].to_vec(),binding_row_num,self.col_n), Matrix::new(self.val[binding_row_num..binding_row_num+1].to_vec(),1,self.col_n),Matrix::new(self.val[binding_row_num+1..binding_row_num+2].to_vec(),1,self.col_n))
    }

    pub fn slice_into_2(&self, binding_row_num: usize) -> (Matrix<T>,Matrix<T>){
        (Matrix::new(self.val[0..binding_row_num].to_vec(),binding_row_num,self.col_n), Matrix::new(self.val[binding_row_num..].to_vec(),self.row_m-binding_row_num,self.col_n) )
    }

    /// Matrix object from matrix Vec<Vec<T>>, check for col length equality assertion across all rows.
    pub fn from_mat_vec(vec: Vec<Vec<T>>) -> Self{
        assert_eq!(vec.len()>0,true);
        let row_length = vec.len();
        let col_length = vec[0].len();
        assert!(col_length>0);
        for all_row in &vec{
            assert_eq!(all_row.len(),col_length);
        }

        Matrix::<T>{ val: vec, row_m: row_length, col_n: col_length }
    }

    pub fn from_vec_transpose(vec: Vec<T>) -> Self{
        let col_length = vec.len();
        let mut mat = Vec::with_capacity(1);
        mat.push(vec);

        Matrix::<T>{ val: mat, row_m: 1, col_n: col_length }
    }

    pub fn from_vec(vec: Vec<T>) -> Self{
        let row_length = vec.len();
        let mut mat: Vec<Vec<T>> = Vec::with_capacity(row_length);
        let mut _counter=0;
        for item in vec{
            mat.push(vec![item]);
            // mat[counter] = vec![item];
            // counter+=1;
        }

        Matrix::<T>{ val: mat, row_m: row_length, col_n: 1 }
    }
    

    pub fn to_vec(&self) -> Vec<T>{
        assert_eq!(self.col_n,1);
        let row_length = self.row_m;
        let mut res: Vec<T> = Vec::with_capacity(row_length);
        let mut _counter=0;
        for item in self.val.clone(){
            res.push(item[0].clone()); //Take the first column from each row
            // mat[counter] = vec![item];
            // counter+=1;
        }
        res
    }
    pub fn to_vec_onerow(&self) -> Vec<T>{
        assert_eq!(self.row_m,1);
        self.val[0].clone() //return the first row
    }

    pub fn to_item_t(&self) -> T{
        assert_eq!(self.col_n,1);
        assert_eq!(self.row_m,1);
        self.val[0][0].clone()
    }

    pub fn map<F>(&self, f: F) -> Self
    where F: Fn(T) -> T{
        let res = self.val.iter().map(
            |t_collect|
                t_collect.iter().map(|t_item| f(t_item.clone())).collect()
        ).collect();
        Self::from_mat_vec(res)
    }

    pub fn identity(n : usize) -> Self{
        let mut mat_val: Vec<Vec<T>> = vec![];
        for row_index in 0..n{
            let mut new_row: Vec<T> = vec![T::zero();n];
            new_row[row_index]= T::one();
            mat_val.push(new_row);
        }
        Matrix::<T>::from_mat_vec(mat_val)
    }

    pub fn transpose(&self) -> Self{
        let new_row_length = self.col_n;
        let new_col_length = self.row_m;
        let mut new_val = vec![];
        for new_row_index in 0..new_row_length{
            let mut new_row = vec![];
            for new_col_index in 0..new_col_length{
                new_row.push(self.val[new_col_index][new_row_index].clone());
            }
            new_val.push(new_row);
        }
        Matrix::from_mat_vec(new_val)
    }

    pub fn v_stack(a: &Self , b: &Self) -> Self{
        assert_eq!(a.col_n, b.col_n);
        let mut new_val = a.val.clone();
        // let new_row_length = a.row_m+b.row_m;
        // let new_col_length = a.col_n;
        for b_row in b.val.clone(){
            new_val.push(b_row);
        }
        Matrix::from_mat_vec(new_val)
    }

    /// Split_at(2, [1,2,3]) => left [1,2], right [3]
    pub fn v_split(&self, split_at: usize) -> (Self,Self){
        assert_eq!(self.row_m >= split_at, true, "self.rowm:{},split_at:{}", self.row_m, split_at);
        let(new_val_left, new_val_right) = self.val.split_at(split_at);
        (Matrix::from_mat_vec(new_val_left.into()),Matrix::from_mat_vec(new_val_right.into()))
    }

    /// L2 Norm
    pub fn norm_l2 (&self) -> i128{
        Float::with_val(256 ,self.norm_l2_sqr().abs() as u128).sqrt().to_integer().unwrap().to_i128().unwrap()
    }
    /// Square of L2 Norm
    pub fn norm_l2_sqr (&self) -> i128{
        assert_eq!(self.col_n, 1);
        let mut norm_sum = 0;
        for row_index in 0..self.row_m{
            norm_sum += self.val[row_index][0].norm_l2_square();
        }
        norm_sum
    }
    pub fn norm_l2_sqr_int (&self) -> Integer{
        assert_eq!(self.col_n, 1);
        let mut norm_sum = Integer::from(0);
        for row_index in 0..self.row_m{
            norm_sum += self.val[row_index][0].norm_l2_int_square();
        }
        norm_sum
    }
    pub fn norm_l2_int (&self) -> Integer{
        assert_eq!(self.col_n, 1);
        let mut norm_sum = Integer::from(0);
        for row_index in 0..self.row_m{
            norm_sum += self.val[row_index][0].norm_l2_int_square();
        }
        norm_sum.sqrt()
    }

    pub fn sigma_reflect(&self) -> Self{
        self.map(|t| t.sigma_reflect())
    }
    
    // /// This will prepends a specified nubmer of row of zero at the top row(s).
    // pub fn pad_row_zero(&self, num_row: usize) -> Self{
    //     if cfg!(debug_assertions){
    //         //Currently this does not affect the funcitonality, but we expect this function is only used to prepad message
    //         assert_eq!(self.col_n, 1);
    //     };

    //     let mut newmat = Vec::with_capacity(self.row_m+num_row);
    //     for _ in 0..num_row{
    //         newmat.push(vec![T::zero()]);
    //     }
    //     // for i in 0..self.row_m{
    //     //     newmat.push(self.val[i].clone());
    //     // }
    //     newmat.extend(self.val.clone());

    //     Matrix::new(newmat, self.row_m+num_row,1)
    // }
}


#[cfg(test)]
mod tests{
    use rand::Rng;
    use crate::polynomial::Poly;
    use crate::polynomial::Poly_U128;
    use crate::common_trait::SigmaReflect;
    use super::Matrix;
    // use core::num;

    fn random_matrix(row:usize,col: usize)-> Matrix<Poly>{
        let mut testmat1 = Vec::new();
        for _row_i in 0..row{
            let mut new_row= Vec::new();
            for _col_j in 0..col{
                let poly1 = Poly::random();
                new_row.push(poly1);
            }
            testmat1.push(new_row);
        }
        Matrix::from_mat_vec(testmat1)
    }

    #[test]
    fn test_matrix_identity(){
        let mut rand= rand::rng();
        let row: usize = rand.random_range(1..8);
        let col = row.clone();

        let mat1 = random_matrix(row, col);
        let identity = Matrix::<Poly>::identity(row);
        assert_eq!(&mat1*&identity, mat1);
        assert_eq!(&identity*&mat1, mat1);
        assert_eq!(&identity*&identity, identity);

        let mat2 = random_matrix(col+1, col);
        let identity = Matrix::<Poly>::identity(col);
        assert_eq!(&mat2*&identity, mat2);
    }

    #[test]
    fn test_transpose(){
        let mut rand= rand::rng();
        let row: usize = rand.random_range(1..8);
        let col = row.clone();

        let mat1 = random_matrix(row, col);
        assert_eq!(mat1.transpose().transpose(), mat1);

        let multiplicant = random_matrix(col, row);
        assert_eq!((&mat1*&multiplicant).transpose(), &multiplicant.transpose()*&mat1.transpose());
    }

    // #[test]
    // fn test_matrix_mul(){
    //     // VectorT * Vector
    //     let testarr1 = vec![1,2,3,4,5,6,7,8,9];
    //     let testarr2 = vec![9,8,7,6,5,4,3,2,1];
    //     let v1 = Matrix::from_vec_transpose(testarr1);
    //     let v2 = Matrix::from_vec(testarr2);
    //     assert_eq!((&v1*&v2).val[0][0], 165);

    //     //Matrix * Vector
    //     let testarr1 = vec![vec![1,2,3,4,5,6,7,8,9],vec![8,8,8,8,8,8,8,8,8]];
    //     let testarr2 = vec![9,8,7,6,5,4,3,2,1];
    //     let v1 = Matrix::new(testarr1, 2, 9);
    //     let v2 = Matrix::from_vec(testarr2);
    //     assert_eq!((&v1*&v2).val, vec![vec![165],vec![360]]);

    //     // Matrix * Matrix
    //     let testarr1 = vec![vec![1,2,3,4,5,6,7,8,9],vec![8,8,8,8,8,8,8,8,8],vec![5,5,5,5,5,5,5,5,5]];
    //     let testarr2 = vec![vec![9,1],vec![8,2],vec![7,3],vec![6,4],vec![5,5],vec![4,4],vec![3,3],vec![2,2],vec![1,1]];
    //     let v1 = Matrix::new(testarr1, 3, 9);
    //     let v2 = Matrix::new(testarr2, 9, 2);
    //     assert_eq!((&v1*&v2).val, vec![vec![165,125],vec![360,200],vec![225,125]]);
    // }

    #[test]
    fn test_matrix_add(){
        let row = 5;
        let col = 8;

        let mut testmat1 = Vec::new();
        let mut testmat2 = Vec::new();
        let mut summat = Vec::new();

        for _row_i in 0..row{
            let mut new_row= Vec::new();
            let mut new_row2 = Vec::new();
            let mut sum_row = Vec::new();
            for _col_j in 0..col{
                let poly1 = Poly::random();
                let poly2 = Poly::random();
                let sumpoly = &poly1 + &poly2;
                new_row.push(poly1);
                new_row2.push(poly2);
                sum_row.push(sumpoly);
            }
            testmat1.push(new_row);
            testmat2.push(new_row2);
            summat.push(sum_row);
        }

        let m1 = Matrix::new(testmat1, row, col);
        let m2 = Matrix::new(testmat2, row, col);
        let reference_m = Matrix::new(summat, row, col);

        assert_eq!(&m1+&m2, reference_m)
    }

    #[test]
    fn test_mulassign(){
        let row = 5;
        let col = 8;

        let mut testmat1 = Vec::new();
        let mut scaled_mat = Vec::new();
        let mut rand= rand::rng();
        let scale_factor: Poly_U128 = Poly_U128::from(rand.random::<u128>());

        for _row_i in 0..row{
            let mut new_row= Vec::new();
            let mut scaled_row = Vec::new();
            for _col_j in 0..col{
                let mut poly1 = Poly::random();
                new_row.push(poly1.clone());
                poly1 *= scale_factor;
                scaled_row.push(poly1);
            }
            testmat1.push(new_row);
            scaled_mat.push(scaled_row);
        }

        let mut m1 = Matrix::new(testmat1, row, col);
        m1 *= scale_factor;
        let reference_m = Matrix::new(scaled_mat, row, col);

        assert_eq!(m1, reference_m)
    }

    #[test]
    fn test_matrix_neg(){
        let row = 5;
        let col = 8;

        let mut testmat1 = Vec::new();
        let mut negmat = Vec::new();

        for _row_i in 0..row{
            let mut new_row= Vec::new();
            let mut neg_row = Vec::new();
            for _col_j in 0..col{
                let poly1 = Poly::random();
                let negpoly = -&poly1;
                new_row.push(poly1);
                neg_row.push(negpoly);
            }
            testmat1.push(new_row);
            negmat.push(neg_row);
        }

        let mat1 = Matrix::new(testmat1, row, col);
        let reference_m = Matrix::new(negmat, row, col);

        assert_eq!(reference_m, -&mat1);
        assert_eq!(-&reference_m, mat1);
        assert_eq!(mat1, -&(-&mat1));

    }

    #[test]
    fn test_matrix_map(){
        let row = 5;
        let col = 8;

        let mut testmat1 = Vec::new();
        let mut negmat = Vec::new();

        for _row_i in 0..row{
            let mut new_row= Vec::new();
            let mut neg_row = Vec::new();
            for _col_j in 0..col{
                let poly1 = Poly::random();
                let negpoly = poly1.clone().sigma_reflect();
                new_row.push(poly1);
                neg_row.push(negpoly);
            }
            testmat1.push(new_row);
            negmat.push(neg_row);
        }

        let mat1 = Matrix::new(testmat1, row, col);
        let reference_m = Matrix::new(negmat, row, col);
        assert_eq!(reference_m, mat1.map(|t| t.sigma_reflect()));
        assert_eq!(reference_m.map(|t| t.sigma_reflect()), mat1);
    }

}