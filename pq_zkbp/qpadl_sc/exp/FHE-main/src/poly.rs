use crate::field::GF;
use crate::ntt::NttContext;
use crate::params::N_POLY;
use std::ops::{Add, Sub};

/// Polynomial in R_Q = Z_Q[X]/(X^N+1)
#[derive(Clone, Debug)]
pub struct Poly {
    pub coeffs: Vec<GF>,
}

impl Poly {
    pub fn zero() -> Self {
        Poly {
            coeffs: vec![GF::ZERO; N_POLY],
        }
    }

    pub fn from_coeffs(coeffs: Vec<GF>) -> Self {
        assert_eq!(coeffs.len(), N_POLY);
        Poly { coeffs }
    }

    /// Scalar multiplication: c * poly
    pub fn scalar_mul(&self, c: GF) -> Self {
        Poly {
            coeffs: self.coeffs.iter().map(|&a| a * c).collect(),
        }
    }

    /// Negacyclic monomial rotation: X^k * self mod (X^N + 1)
    /// For rotation by k positions with negacyclic wraparound.
    pub fn monomial_rotate(&self, k: usize) -> Self {
        let n = N_POLY;
        let k = k % (2 * n); // k mod 2N
        let mut result = vec![GF::ZERO; n];

        for i in 0..n {
            let new_idx = i + k;
            if new_idx < n {
                result[new_idx] = self.coeffs[i];
            } else if new_idx < 2 * n {
                // Wraps around: X^N = -1, so coefficient gets negated
                result[new_idx - n] = -self.coeffs[i];
            } else {
                // new_idx >= 2N: X^(2N) = 1, so wraps back without negation
                result[new_idx - 2 * n] = self.coeffs[i];
            }
        }

        Poly { coeffs: result }
    }

    /// Polynomial multiplication via NTT (negacyclic)
    pub fn mul_ntt(&self, other: &Self, ctx: &NttContext) -> Self {
        let mut a_ntt = self.coeffs.clone();
        let mut b_ntt = other.coeffs.clone();

        ctx.forward(&mut a_ntt);
        ctx.forward(&mut b_ntt);

        let mut c_ntt: Vec<GF> = a_ntt
            .iter()
            .zip(b_ntt.iter())
            .map(|(&x, &y)| x * y)
            .collect();

        ctx.inverse(&mut c_ntt);

        Poly { coeffs: c_ntt }
    }
}

impl Add for &Poly {
    type Output = Poly;
    fn add(self, rhs: &Poly) -> Poly {
        Poly {
            coeffs: self
                .coeffs
                .iter()
                .zip(rhs.coeffs.iter())
                .map(|(&a, &b)| a + b)
                .collect(),
        }
    }
}

impl Sub for &Poly {
    type Output = Poly;
    fn sub(self, rhs: &Poly) -> Poly {
        Poly {
            coeffs: self
                .coeffs
                .iter()
                .zip(rhs.coeffs.iter())
                .map(|(&a, &b)| a - b)
                .collect(),
        }
    }
}

impl Poly {
    pub fn neg(&self) -> Self {
        Poly {
            coeffs: self.coeffs.iter().map(|&a| -a).collect(),
        }
    }
}
