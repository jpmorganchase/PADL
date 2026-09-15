use crate::field::*;
use crate::ntt::intt;

pub fn sigma_alpha_coeffs(alpha: ArkField, n: usize, omega: ArkField) -> Vec<ArkField> {
    let mut vals = Vec::with_capacity(n);
    let mut a = from_u128(1);
    for _ in 0..n {
        vals.push(a);
        a = fmul(a, alpha);
    }
    intt(&vals, omega)
}

pub fn lambda_alpha_coeffs(
    alpha: ArkField,
    n: usize,
    omega: ArkField,
    psi: ArkField,
) -> Vec<ArkField> {
    let n_big = n as u128;
    let alpha_n = fpow(alpha, n_big);
    let alpha_n_plus1 = fadd(alpha_n, from_u128(1));
    let mut vals = Vec::with_capacity(n);
    let mut hi = psi;
    for _ in 0..n {
        let num = fmul(fsub(from_u128(0), hi), alpha_n_plus1);
        let den = fmul(from_u128(n_big), fsub(alpha, hi));
        vals.push(fmul(num, finv(den)));
        hi = fmul(hi, omega);
    }
    intt(&vals, omega)
}
