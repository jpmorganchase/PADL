use crate::params::Q;
use std::fmt;
use std::ops::{Add, Mul, Neg, Sub};

/// Element of the Goldilocks field F_Q where Q = 2^64 - 2^32 + 1
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct GF(pub u64);

impl GF {
    pub const ZERO: GF = GF(0);
    pub const ONE: GF = GF(1);

    #[inline]
    pub fn new(val: u64) -> Self {
        GF(val % Q)
    }

    /// Reduce a u128 modulo Q using Goldilocks structure.
    /// Q = 2^64 - 2^32 + 1
    /// For x = x_hi * 2^64 + x_lo:
    /// x mod Q = x_lo + x_hi * (2^32 - 1) mod Q  (since 2^64 ≡ 2^32 - 1 mod Q)
    #[inline]
    pub fn reduce128(x: u128) -> Self {
        let x_lo = x as u64;
        let x_hi = (x >> 64) as u64;
        // 2^64 ≡ 2^32 - 1 (mod Q), let epsilon = 2^32 - 1
        let epsilon: u64 = (1u64 << 32) - 1;
        // x ≡ x_lo + x_hi * epsilon (mod Q)
        let hi_shifted = (x_hi as u128) * (epsilon as u128);
        let sum = (x_lo as u128) + hi_shifted;
        // sum < 2^96, reduce again: sum = s_hi * 2^64 + s_lo ≡ s_lo + s_hi * epsilon
        let s_lo = sum as u64;
        let s_hi = (sum >> 64) as u64; // < 2^32
                                       // s_hi * epsilon fits in u64 (both < 2^32), but s_lo + s_hi*epsilon may overflow u64
        let (result, carry) = s_lo.overflowing_add(s_hi.wrapping_mul(epsilon));
        if carry {
            // result + 2^64 ≡ result + epsilon (mod Q); this sum fits in u64
            GF(Self::reduce_once(result.wrapping_add(epsilon)))
        } else {
            GF(Self::reduce_once(result))
        }
    }

    #[inline]
    fn reduce_once(x: u64) -> u64 {
        if x >= Q {
            x - Q
        } else {
            x
        }
    }

    /// Modular inverse using Fermat's little theorem: a^(-1) = a^(Q-2) mod Q
    pub fn inv(self) -> Self {
        self.pow(Q - 2)
    }

    /// Fast exponentiation
    pub fn pow(self, mut exp: u64) -> Self {
        let mut base = self;
        let mut result = GF::ONE;
        while exp > 0 {
            if exp & 1 == 1 {
                result = result * base;
            }
            base = base * base;
            exp >>= 1;
        }
        result
    }

    /// Convert a signed value (i64) to field element
    pub fn from_signed(val: i64) -> Self {
        if val >= 0 {
            GF::new(val as u64)
        } else {
            // Q + val (since val is negative)
            GF(Q - ((-val) as u64 % Q))
        }
    }

    /// Interpret as signed: if val > Q/2, return val - Q
    pub fn to_signed(self) -> i64 {
        if self.0 > Q / 2 {
            self.0 as i64 - Q as i64
        } else {
            self.0 as i64
        }
    }
}

impl Add for GF {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        let (sum, carry) = self.0.overflowing_add(rhs.0);
        if carry {
            // sum + 2^64 mod Q = sum + (2^32 - 1) mod Q
            GF(Self::reduce_once(sum.wrapping_add((1u64 << 32) - 1)))
        } else {
            GF(Self::reduce_once(sum))
        }
    }
}

impl Sub for GF {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        if self.0 >= rhs.0 {
            GF(self.0 - rhs.0)
        } else {
            GF(Q - (rhs.0 - self.0))
        }
    }
}

impl Mul for GF {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        let prod = (self.0 as u128) * (rhs.0 as u128);
        Self::reduce128(prod)
    }
}

impl Neg for GF {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        if self.0 == 0 {
            GF::ZERO
        } else {
            GF(Q - self.0)
        }
    }
}

impl fmt::Debug for GF {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GF({})", self.0)
    }
}

impl fmt::Display for GF {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_arithmetic() {
        let a = GF::new(100);
        let b = GF::new(200);
        assert_eq!((a + b).0, 300);
        assert_eq!((b - a).0, 100);
        assert_eq!((a * b).0, 20000);
    }

    #[test]
    fn test_wraparound() {
        let a = GF(Q - 1);
        let b = GF(2);
        assert_eq!((a + b).0, 1);
    }

    #[test]
    fn test_inverse() {
        let a = GF::new(12345);
        let a_inv = a.inv();
        assert_eq!((a * a_inv).0, 1);
    }

    #[test]
    fn test_negation() {
        let a = GF::new(42);
        let neg_a = -a;
        assert_eq!((a + neg_a).0, 0);
    }

    #[test]
    fn test_from_signed() {
        let a = GF::from_signed(-5);
        let b = GF::new(5);
        assert_eq!((a + b).0, 0);
    }
}
