use crate::field::GF;
use crate::params::N_POLY;
use crate::params::{B_KS, B_PBS, LOG_B_KS, LOG_B_PBS, L_KS, L_PBS, Q};
use crate::poly::Poly;

/// Balanced base-B digit decomposition of a single field element.
/// Returns l digits, each in range [-(B/2), B/2 - 1] (represented as GF).
/// Recomposition: sum_{j=0}^{l-1} d_j * B^j ≡ val (mod Q)
///
/// To avoid carry overflow for large field elements (near Q ≈ 2^64),
/// we first convert to signed representation: values > Q/2 are treated as
/// negative (val - Q). This ensures |remaining| ≤ Q/2 ≈ 2^63 which fits
/// in 8 balanced base-256 digits.
pub fn decompose_element(val: GF, base_log: u32, levels: usize) -> Vec<i64> {
    let base = 1u64 << base_log;
    let half_base = (base / 2) as i64;
    let mask = base - 1;

    // Convert to signed representation to avoid carry overflow
    // Values > Q/2 represent negative numbers (val - Q)
    let mut remaining: i64 = if val.0 > Q / 2 {
        // val.0 - Q interpreted as negative (two's complement)
        (val.0 as i128 - Q as i128) as i64
    } else {
        val.0 as i64
    };

    let mut digits = Vec::with_capacity(levels);

    for _ in 0..levels {
        // Extract lowest base_log bits (treating as unsigned for masking)
        let digit = ((remaining as u64) & mask) as i64;
        let balanced_digit = if digit >= half_base {
            remaining = remaining.wrapping_add(base as i64);
            digit - base as i64
        } else {
            digit
        };
        digits.push(balanced_digit);
        // Arithmetic right shift preserves sign for negative values
        remaining >>= base_log;
    }

    digits
}

/// Decompose a polynomial coefficient-wise using PBS parameters.
/// Returns l polynomials, each with small coefficients.
pub fn decompose_poly_pbs(poly: &Poly) -> Vec<Poly> {
    let mut result: Vec<Vec<GF>> = vec![vec![GF::ZERO; N_POLY]; L_PBS];

    for i in 0..N_POLY {
        let digits = decompose_element(poly.coeffs[i], LOG_B_PBS, L_PBS);
        for j in 0..L_PBS {
            result[j][i] = GF::from_signed(digits[j]);
        }
    }

    result.into_iter().map(Poly::from_coeffs).collect()
}

/// Decompose a polynomial coefficient-wise using KS parameters.
pub fn decompose_poly_ks(poly: &Poly) -> Vec<Poly> {
    let mut result: Vec<Vec<GF>> = vec![vec![GF::ZERO; N_POLY]; L_KS];

    for i in 0..N_POLY {
        let digits = decompose_element(poly.coeffs[i], LOG_B_KS, L_KS);
        for j in 0..L_KS {
            result[j][i] = GF::from_signed(digits[j]);
        }
    }

    result.into_iter().map(Poly::from_coeffs).collect()
}

/// Decompose a single u64 value using KS parameters, returning signed digits
pub fn decompose_scalar_ks(val: u64) -> Vec<i64> {
    decompose_element(GF(val), LOG_B_KS, L_KS)
}

/// Unsigned base-B digit decomposition of a single field element.
/// Returns l digits, each in range [0, B-1].
/// Recomposition: sum_{j=0}^{l-1} d_j * B^j ≡ val (mod Q)
///
/// Since B^L = 256^8 = 2^64 > Q, every val ∈ [0, Q-1] has a unique
/// unsigned representation. The digits are simply the base-B digits
/// of val.0 (the canonical u64 representative).
pub fn decompose_element_unsigned(val: GF, base_log: u32, levels: usize) -> Vec<u64> {
    let mask = (1u64 << base_log) - 1;
    let mut remaining = val.0;
    let mut digits = Vec::with_capacity(levels);
    for _ in 0..levels {
        digits.push(remaining & mask);
        remaining >>= base_log;
    }
    digits
}

/// Decompose a single u64 value using KS parameters, returning unsigned digits
pub fn decompose_scalar_ks_unsigned(val: u64) -> Vec<u64> {
    decompose_element_unsigned(GF(val), LOG_B_KS, L_KS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompose_recompose() {
        let val = GF::new(123456789012345);
        let digits = decompose_element(val, LOG_B_PBS, L_PBS);

        // Verify recomposition
        let mut recomposed = 0i128;
        let base = B_PBS as i128;
        for j in (0..L_PBS).rev() {
            recomposed = recomposed * base + digits[j] as i128;
        }
        // recomposed mod Q should equal val
        let q = Q as i128;
        let recomposed_mod = ((recomposed % q) + q) % q;
        assert_eq!(recomposed_mod as u64, val.0);
    }

    #[test]
    fn test_digits_bounded() {
        let val = GF::new(0xDEADBEEFCAFEBABE % Q);
        let digits = decompose_element(val, LOG_B_PBS, L_PBS);
        let half_base = (B_PBS / 2) as i64;
        for &d in &digits {
            assert!(d >= -half_base && d < half_base, "digit {} out of range", d);
        }
    }
}
