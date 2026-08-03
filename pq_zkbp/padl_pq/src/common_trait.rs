use rug::Integer;

pub trait Norm{
    fn norm_l2_square(&self) -> i128;
    fn norm_l2_int_square(&self) -> Integer;
    fn norm_linf(&self) -> u128;
}

pub trait SigmaReflect{
    fn sigma_reflect(&self) -> Self;
}