use crate::field::GF;
use crate::params::{N_POLY, Q};

#[cfg(target_arch = "x86_64")]
use crate::simd;

/// Bit-reversal permutation for array of size n (n must be a power of 2)
fn bit_reverse_permutation(a: &mut [GF]) {
    let n = a.len();
    let log_n = n.trailing_zeros() as usize;
    for i in 0..n {
        let j = i.reverse_bits() >> (usize::BITS as usize - log_n);
        if i < j {
            a.swap(i, j);
        }
    }
}

/// Find a primitive 2N-th root of unity in GF(Q).
/// Since Q - 1 = 2^32 * (2^32 - 1), and 2N = 2048 = 2^11,
/// we need a 2^11-th root of unity. Since 2^11 | 2^32 | (Q-1), it exists.
pub fn find_primitive_2n_root() -> GF {
    // g = primitive root of F_Q (generator of the multiplicative group)
    // We need ψ such that ψ^(2N) = 1 and ψ^N = -1 (i.e., ψ is a primitive 2N-th root)
    // ψ = g^((Q-1)/(2N))
    let two_n = (2 * N_POLY) as u64;
    let exp = (Q - 1) / two_n;

    // Find a generator of F_Q*. We'll use 7 which is a known generator for Goldilocks.
    let g = GF::new(7);
    let psi = g.pow(exp);

    // Verify: psi^(2N) = 1 and psi^N != 1
    debug_assert_eq!(psi.pow(two_n), GF::ONE);
    debug_assert_ne!(psi.pow(N_POLY as u64), GF::ONE);

    psi
}

/// Precomputed NTT twiddle factors for negacyclic NTT of size N.
/// Uses the "twisted NTT" approach:
/// 1. Multiply coefficients by ψ^i (twist)
/// 2. Standard NTT of size N with ω = ψ^2 (N-th root of unity)
pub struct NttContext {
    /// ψ^i for i = 0..N-1 (twist factors)
    pub psi_powers: Vec<GF>,
    /// ψ^(-i) for i = 0..N-1 (inverse twist factors)
    pub psi_inv_powers: Vec<GF>,
    /// Twiddle factors for forward NTT (bit-reversed order)
    pub forward_twiddles: Vec<GF>,
    /// Twiddle factors for inverse NTT (bit-reversed order)
    pub inverse_twiddles: Vec<GF>,
    /// 1/N mod Q
    pub n_inv: GF,
}

impl NttContext {
    pub fn new() -> Self {
        let n = N_POLY;
        let psi = find_primitive_2n_root(); // primitive 2N-th root
        let psi_inv = psi.inv();
        let omega = psi * psi; // ω = ψ^2, primitive N-th root of unity

        // Precompute ψ^i
        let mut psi_powers = vec![GF::ONE; n];
        for i in 1..n {
            psi_powers[i] = psi_powers[i - 1] * psi;
        }

        // Precompute ψ^(-i)
        let mut psi_inv_powers = vec![GF::ONE; n];
        for i in 1..n {
            psi_inv_powers[i] = psi_inv_powers[i - 1] * psi_inv;
        }

        // Precompute forward twiddle factors in bit-reversed order
        // For Cooley-Tukey: at each stage, twiddle = ω^(bit_rev(j) * N / (2*half_size))
        let forward_twiddles = Self::compute_twiddles(omega, n);
        let omega_inv = omega.inv();
        let inverse_twiddles = Self::compute_twiddles(omega_inv, n);

        let n_inv = GF::new(n as u64).inv();

        NttContext {
            psi_powers,
            psi_inv_powers,
            forward_twiddles,
            inverse_twiddles,
            n_inv,
        }
    }

    /// Compute twiddle factors in the order needed by iterative Cooley-Tukey NTT
    fn compute_twiddles(omega: GF, n: usize) -> Vec<GF> {
        // We store twiddles layer by layer.
        // Total n/2 twiddles needed (one per butterfly).
        // Layer structure: for half_size = 1, 2, 4, ..., n/2
        let mut twiddles = vec![GF::ZERO; n];
        let mut pos = 0;
        let mut half_size = 1;
        while half_size < n {
            let step = n / (2 * half_size);
            // ω_layer = omega^step
            let omega_layer = omega.pow(step as u64);
            let mut w = GF::ONE;
            for _j in 0..half_size {
                twiddles[pos] = w;
                w = w * omega_layer;
                pos += 1;
            }
            half_size <<= 1;
        }
        twiddles
    }

    /// Forward negacyclic NTT: polynomial → NTT domain
    /// Input: coefficients a[0..N-1] in coefficient form
    /// Output: NTT evaluations (in-place)
    pub fn forward(&self, a: &mut [GF]) {
        let n = a.len();
        debug_assert_eq!(n, N_POLY);

        // Step 1: Twist by ψ^i
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx512f") {
                unsafe {
                    simd::pointwise_mul_inplace(a, &self.psi_powers);
                }
            } else {
                for i in 0..n {
                    a[i] = a[i] * self.psi_powers[i];
                }
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            for i in 0..n {
                a[i] = a[i] * self.psi_powers[i];
            }
        }

        // Step 2: Bit-reverse the input for CT DIT
        bit_reverse_permutation(a);

        // Step 3: NTT butterflies
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx512f") {
                unsafe {
                    simd::ntt_forward_avx512(a, &self.forward_twiddles);
                }
                return;
            }
        }
        // Scalar fallback
        let mut twiddle_pos = 0;
        let mut half_size = 1;
        while half_size < n {
            let full_size = half_size << 1;
            for block in (0..n).step_by(full_size) {
                for j in 0..half_size {
                    let w = self.forward_twiddles[twiddle_pos + j];
                    let u = a[block + j];
                    let v = a[block + j + half_size] * w;
                    a[block + j] = u + v;
                    a[block + j + half_size] = u - v;
                }
            }
            twiddle_pos += half_size;
            half_size <<= 1;
        }
    }

    /// Inverse negacyclic NTT: NTT domain → polynomial coefficients
    /// Uses Gentleman-Sande (DIF) butterfly: layers from large to small
    pub fn inverse(&self, a: &mut [GF]) {
        let n = a.len();
        debug_assert_eq!(n, N_POLY);

        // Step 1: Inverse NTT butterflies
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx512f") {
                unsafe {
                    simd::ntt_inverse_avx512(a, &self.inverse_twiddles);
                }
            } else {
                self.inverse_scalar_butterflies(a);
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            self.inverse_scalar_butterflies(a);
        }

        // Step 2: Bit-reverse the output (GS DIF produces bit-reversed output)
        bit_reverse_permutation(a);

        // Step 3: Multiply by 1/N and untwist by ψ^(-i)
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx512f") {
                unsafe {
                    simd::scalar_mul_inplace(a, self.n_inv);
                    simd::pointwise_mul_inplace(a, &self.psi_inv_powers);
                }
                return;
            }
        }
        for i in 0..n {
            a[i] = a[i] * self.n_inv;
        }
        for i in 0..n {
            a[i] = a[i] * self.psi_inv_powers[i];
        }
    }

    /// Scalar fallback for inverse NTT butterflies
    fn inverse_scalar_butterflies(&self, a: &mut [GF]) {
        let n = a.len();
        let mut half_size = n / 2;
        while half_size >= 1 {
            let twiddle_pos = half_size - 1;
            let full_size = half_size << 1;
            for block in (0..n).step_by(full_size) {
                for j in 0..half_size {
                    let w = self.inverse_twiddles[twiddle_pos + j];
                    let u = a[block + j];
                    let v = a[block + j + half_size];
                    a[block + j] = u + v;
                    a[block + j + half_size] = (u - v) * w;
                }
            }
            half_size >>= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_of_unity() {
        let psi = find_primitive_2n_root();
        let two_n = (2 * N_POLY) as u64;
        assert_eq!(psi.pow(two_n), GF::ONE);
        assert_ne!(psi.pow(N_POLY as u64), GF::ONE);
    }

    #[test]
    fn test_ntt_roundtrip() {
        let ctx = NttContext::new();
        let mut a: Vec<GF> = (0..N_POLY as u64).map(|i| GF::new(i + 1)).collect();
        let original = a.clone();

        ctx.forward(&mut a);
        ctx.inverse(&mut a);

        for i in 0..N_POLY {
            assert_eq!(a[i], original[i], "Mismatch at index {}", i);
        }
    }

    #[test]
    fn test_negacyclic_mul_via_ntt() {
        let ctx = NttContext::new();

        // a(X) = 1 + 2X, b(X) = 3 + 4X
        // a*b mod (X^N+1):
        // For small degree, only coefficients 0 and 1 matter:
        // c_0 = 1*3 + 2*4*(−1 from X^N+1 wraparound for N=1024? No, no wraparound for deg < N)
        // Actually for N=1024, a*b = 3 + 4X + 6X + 8X^2 = 3 + 10X + 8X^2 (no wraparound)
        let mut a = vec![GF::ZERO; N_POLY];
        let mut b = vec![GF::ZERO; N_POLY];
        a[0] = GF::new(1);
        a[1] = GF::new(2);
        b[0] = GF::new(3);
        b[1] = GF::new(4);

        let mut a_ntt = a.clone();
        let mut b_ntt = b.clone();
        ctx.forward(&mut a_ntt);
        ctx.forward(&mut b_ntt);

        // Pointwise multiply
        let mut c_ntt: Vec<GF> = a_ntt
            .iter()
            .zip(b_ntt.iter())
            .map(|(&x, &y)| x * y)
            .collect();

        ctx.inverse(&mut c_ntt);

        // Expected: 3 + 10X + 8X^2
        assert_eq!(c_ntt[0], GF::new(3));
        assert_eq!(c_ntt[1], GF::new(10));
        assert_eq!(c_ntt[2], GF::new(8));
        for i in 3..N_POLY {
            assert_eq!(c_ntt[i], GF::ZERO);
        }
    }
}
