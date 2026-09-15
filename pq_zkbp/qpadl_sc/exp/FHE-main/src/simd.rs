//! AVX-512 SIMD acceleration for Goldilocks field arithmetic.
//! Processes 8 field elements (u64) in parallel using __m512i vectors.
//!
//! Based on the approach from Plonky3 for the Goldilocks field:
//! Q = 2^64 - 2^32 + 1, EPSILON = 2^32 - 1 (since 2^64 ≡ EPSILON mod Q)

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use crate::field::GF;
use crate::params::{N_POLY, Q};

/// Number of u64 lanes in an AVX-512 vector
pub const LANES: usize = 8;

// ─── Constants ────────────────────────────────────────────────────────────────

const EPSILON_U64: u64 = (1u64 << 32) - 1; // = Q.wrapping_neg() = 2^32 - 1

#[inline(always)]
unsafe fn field_order_vec() -> __m512i {
    _mm512_set1_epi64(Q as i64)
}

#[inline(always)]
unsafe fn epsilon_vec() -> __m512i {
    _mm512_set1_epi64(EPSILON_U64 as i64)
}

// ─── Core Arithmetic ──────────────────────────────────────────────────────────

/// Canonicalize: if x >= Q, subtract Q.
#[inline(always)]
pub unsafe fn canonicalize(x: __m512i) -> __m512i {
    let q = field_order_vec();
    let mask = _mm512_cmpge_epu64_mask(x, q);
    _mm512_mask_sub_epi64(x, mask, x, q)
}

/// Modular addition: (x + y) mod Q.
/// Requires: inputs can be up to 2^64-1 but x+y < 2^64 + Q.
#[inline(always)]
pub unsafe fn simd_add(x: __m512i, y: __m512i) -> __m512i {
    let y_canon = canonicalize(y);
    let res = _mm512_add_epi64(x, y_canon);
    // If the addition wrapped around (res < y_canon), we overflowed 2^64.
    // In that case, res + 2^64 mod Q = res - Q (since 2^64 = Q + EPSILON, but
    // we actually have res = (x+y) - 2^64 and need (x+y) - Q, so add EPSILON+1-Q...
    // Simpler: if overflow, subtract Q.
    let mask = _mm512_cmplt_epu64_mask(res, y_canon);
    let q = field_order_vec();
    _mm512_mask_sub_epi64(res, mask, res, q)
}

/// Modular subtraction: (x - y) mod Q.
#[inline(always)]
pub unsafe fn simd_sub(x: __m512i, y: __m512i) -> __m512i {
    let y_canon = canonicalize(y);
    let mask = _mm512_cmplt_epu64_mask(x, y_canon);
    let res = _mm512_sub_epi64(x, y_canon);
    let q = field_order_vec();
    _mm512_mask_add_epi64(res, mask, res, q)
}

/// Full 64×64 → 128-bit multiplication, returning (hi, lo) pair.
/// Uses 4× _mm512_mul_epu32 (32×32→64) and schoolbook combination.
#[inline(always)]
pub unsafe fn mul64_64(x: __m512i, y: __m512i) -> (__m512i, __m512i) {
    // Extract high 32 bits by moving them to low position via float shuffle
    let x_hi = _mm512_srli_epi64::<32>(x);
    let y_hi = _mm512_srli_epi64::<32>(y);

    // Four 32×32→64 products
    let mul_ll = _mm512_mul_epu32(x, y); // x_lo * y_lo
    let mul_lh = _mm512_mul_epu32(x, y_hi); // x_lo * y_hi
    let mul_hl = _mm512_mul_epu32(x_hi, y); // x_hi * y_lo
    let mul_hh = _mm512_mul_epu32(x_hi, y_hi); // x_hi * y_hi

    // Combine: result = mul_hh*2^64 + (mul_hl + mul_lh)*2^32 + mul_ll
    // First, add mul_ll_hi to mul_hl (cannot overflow since both fit in 64 bits)
    let mul_ll_hi = _mm512_srli_epi64::<32>(mul_ll);
    let t0 = _mm512_add_epi64(mul_hl, mul_ll_hi);

    // Split t0 into high and low 32-bit halves
    let t0_lo = _mm512_and_si512(t0, epsilon_vec()); // mask with 0xFFFFFFFF
    let t0_hi = _mm512_srli_epi64::<32>(t0);

    // Add t0_lo to mul_lh
    let t1 = _mm512_add_epi64(mul_lh, t0_lo);
    // High part of result: mul_hh + t0_hi + t1_hi
    let t1_hi = _mm512_srli_epi64::<32>(t1);
    let res_hi = _mm512_add_epi64(_mm512_add_epi64(mul_hh, t0_hi), t1_hi);

    // Low part: (t1_lo << 32) | mul_ll_lo
    let t1_lo_shifted = _mm512_slli_epi64::<32>(t1);
    let mul_ll_lo_mask = _mm512_set1_epi64(0xFFFFFFFF_i64);
    let mul_ll_lo = _mm512_and_si512(mul_ll, mul_ll_lo_mask);
    let res_lo = _mm512_or_si512(t1_lo_shifted, mul_ll_lo);

    (res_hi, res_lo)
}

/// Reduce 128-bit value (hi, lo) modulo Goldilocks Q.
/// Uses: x mod Q = lo + hi_lo * EPSILON - hi_hi (mod Q)
/// where hi = hi_hi*2^32 + hi_lo.
#[inline(always)]
pub unsafe fn reduce128_simd(hi: __m512i, lo: __m512i) -> __m512i {
    let eps = epsilon_vec();
    let q = field_order_vec();

    // hi_hi = hi >> 32
    let hi_hi = _mm512_srli_epi64::<32>(hi);

    // lo1 = lo - hi_hi (mod Q). Since 2^96 ≡ -1 mod Q.
    let mask1 = _mm512_cmplt_epu64_mask(lo, hi_hi);
    let lo1 = _mm512_sub_epi64(lo, hi_hi);
    let lo1 = _mm512_mask_add_epi64(lo1, mask1, lo1, q);

    // t1 = hi_lo * EPSILON (hi_lo < 2^32, EPSILON < 2^32, so product < 2^64)
    let t1 = _mm512_mul_epu32(hi, eps);

    // result = lo1 + t1 (mod Q). t1 < (2^32-1)^2 < Q, so safe.
    let res = _mm512_add_epi64(lo1, t1);
    let mask2 = _mm512_cmplt_epu64_mask(res, t1); // overflow check
    let res = _mm512_mask_sub_epi64(res, mask2, res, q);

    // Final canonicalization
    let mask3 = _mm512_cmpge_epu64_mask(res, q);
    _mm512_mask_sub_epi64(res, mask3, res, q)
}

/// Modular multiplication: (x * y) mod Q, 8 elements at once.
#[inline(always)]
pub unsafe fn simd_mul(x: __m512i, y: __m512i) -> __m512i {
    let (hi, lo) = mul64_64(x, y);
    reduce128_simd(hi, lo)
}

// ─── NTT Operations ───────────────────────────────────────────────────────────

/// Load 8 consecutive GF elements from a slice into an AVX-512 register.
#[inline(always)]
pub unsafe fn load_gf(ptr: *const GF) -> __m512i {
    _mm512_loadu_si512(ptr as *const __m512i)
}

/// Store an AVX-512 register into 8 consecutive GF elements.
#[inline(always)]
pub unsafe fn store_gf(ptr: *mut GF, v: __m512i) {
    _mm512_storeu_si512(ptr as *mut __m512i, v)
}

/// Broadcast a single GF element into all 8 lanes.
#[inline(always)]
pub unsafe fn broadcast_gf(val: GF) -> __m512i {
    _mm512_set1_epi64(val.0 as i64)
}

/// SIMD NTT butterfly: given u, v (8-wide) and twiddle w (8-wide),
/// computes: out_top = u + v*w, out_bot = u - v*w (all mod Q)
#[inline(always)]
pub unsafe fn butterfly_ct(u: __m512i, v: __m512i, w: __m512i) -> (__m512i, __m512i) {
    let vw = simd_mul(v, w);
    let top = simd_add(u, vw);
    let bot = simd_sub(u, vw);
    (top, bot)
}

/// SIMD GS (Gentleman-Sande) inverse butterfly:
/// out_top = u + v, out_bot = (u - v) * w  (all mod Q)
#[inline(always)]
pub unsafe fn butterfly_gs(u: __m512i, v: __m512i, w: __m512i) -> (__m512i, __m512i) {
    let top = simd_add(u, v);
    let diff = simd_sub(u, v);
    let bot = simd_mul(diff, w);
    (top, bot)
}

/// Perform forward NTT (Cooley-Tukey DIT) with AVX-512 acceleration.
/// Input: twisted, bit-reversed coefficients. Output: NTT evaluations.
/// This replaces the scalar butterfly loop in NttContext::forward.
#[target_feature(enable = "avx512f")]
pub unsafe fn ntt_forward_avx512(a: &mut [GF], twiddles: &[GF]) {
    let n = a.len();
    let ptr = a.as_mut_ptr();
    let mut twiddle_pos = 0;
    let mut half_size = 1;

    while half_size < n {
        let full_size = half_size << 1;

        if half_size >= LANES {
            // SIMD path: process 8 butterflies at a time within each block
            for block in (0..n).step_by(full_size) {
                let mut j = 0;
                while j + LANES <= half_size {
                    // Load twiddles (consecutive within this block segment)
                    let w = load_gf(twiddles.as_ptr().add(twiddle_pos + j) as *const GF);
                    let u = load_gf(ptr.add(block + j));
                    let v = load_gf(ptr.add(block + j + half_size));
                    let (top, bot) = butterfly_ct(u, v, w);
                    store_gf(ptr.add(block + j), top);
                    store_gf(ptr.add(block + j + half_size), bot);
                    j += LANES;
                }
            }
        } else {
            // Scalar path for small layers (half_size < 8)
            for block in (0..n).step_by(full_size) {
                for j in 0..half_size {
                    let w = twiddles[twiddle_pos + j];
                    let u = *ptr.add(block + j);
                    let v = *ptr.add(block + j + half_size) * w;
                    *ptr.add(block + j) = u + v;
                    *ptr.add(block + j + half_size) = u - v;
                }
            }
        }
        twiddle_pos += half_size;
        half_size <<= 1;
    }
}

/// Perform inverse NTT (Gentleman-Sande DIF) with AVX-512 acceleration.
#[target_feature(enable = "avx512f")]
pub unsafe fn ntt_inverse_avx512(a: &mut [GF], twiddles: &[GF]) {
    let n = a.len();
    let ptr = a.as_mut_ptr();
    let mut half_size = n / 2;

    while half_size >= 1 {
        let twiddle_pos = half_size - 1;
        let full_size = half_size << 1;

        if half_size >= LANES {
            for block in (0..n).step_by(full_size) {
                let mut j = 0;
                while j + LANES <= half_size {
                    let w = load_gf(twiddles.as_ptr().add(twiddle_pos + j) as *const GF);
                    let u = load_gf(ptr.add(block + j));
                    let v = load_gf(ptr.add(block + j + half_size));
                    let (top, bot) = butterfly_gs(u, v, w);
                    store_gf(ptr.add(block + j), top);
                    store_gf(ptr.add(block + j + half_size), bot);
                    j += LANES;
                }
            }
        } else {
            for block in (0..n).step_by(full_size) {
                for j in 0..half_size {
                    let w = twiddles[twiddle_pos + j];
                    let u = *ptr.add(block + j);
                    let v = *ptr.add(block + j + half_size);
                    *ptr.add(block + j) = u + v;
                    *ptr.add(block + j + half_size) = (u - v) * w;
                }
            }
        }
        half_size >>= 1;
    }
}

/// SIMD-accelerated pointwise multiply-accumulate for external product.
/// Computes: result_a[k] += da[k]*ra0[k] + db[k]*rb0[k]
///           result_b[k] += da[k]*ra1[k] + db[k]*rb1[k]
/// for k in 0..N_POLY, processing 8 at a time.
#[target_feature(enable = "avx512f")]
pub unsafe fn pointwise_accum(
    result_a: &mut [GF],
    result_b: &mut [GF],
    da: &[GF],
    db: &[GF],
    ra0: &[GF], // rows_ntt[j].0
    ra1: &[GF], // rows_ntt[j].1
    rb0: &[GF], // rows_ntt[L+j].0
    rb1: &[GF], // rows_ntt[L+j].1
) {
    let n = N_POLY;
    let mut k = 0;
    while k + LANES <= n {
        let da_v = load_gf(da.as_ptr().add(k) as *const GF);
        let db_v = load_gf(db.as_ptr().add(k) as *const GF);

        // result_a[k] += da*ra0 + db*rb0
        let acc_a = load_gf(result_a.as_ptr().add(k) as *const GF);
        let prod1 = simd_mul(da_v, load_gf(ra0.as_ptr().add(k) as *const GF));
        let prod2 = simd_mul(db_v, load_gf(rb0.as_ptr().add(k) as *const GF));
        let new_a = simd_add(acc_a, simd_add(prod1, prod2));
        store_gf(result_a.as_mut_ptr().add(k), new_a);

        // result_b[k] += da*ra1 + db*rb1
        let acc_b = load_gf(result_b.as_ptr().add(k) as *const GF);
        let prod3 = simd_mul(da_v, load_gf(ra1.as_ptr().add(k) as *const GF));
        let prod4 = simd_mul(db_v, load_gf(rb1.as_ptr().add(k) as *const GF));
        let new_b = simd_add(acc_b, simd_add(prod3, prod4));
        store_gf(result_b.as_mut_ptr().add(k), new_b);

        k += LANES;
    }
}

/// SIMD-accelerated in-place pointwise multiply: a[i] *= factors[i].
#[target_feature(enable = "avx512f")]
pub unsafe fn pointwise_mul_inplace(a: &mut [GF], factors: &[GF]) {
    let n = a.len();
    let mut k = 0;
    while k + LANES <= n {
        let av = load_gf(a.as_ptr().add(k) as *const GF);
        let bv = load_gf(factors.as_ptr().add(k) as *const GF);
        let c = simd_mul(av, bv);
        store_gf(a.as_mut_ptr().add(k), c);
        k += LANES;
    }
    while k < n {
        a[k] = a[k] * factors[k];
        k += 1;
    }
}

/// SIMD-accelerated multiply all elements by a scalar constant.
#[target_feature(enable = "avx512f")]
pub unsafe fn scalar_mul_inplace(dst: &mut [GF], scalar: GF) {
    let n = dst.len();
    let s = broadcast_gf(scalar);
    let mut k = 0;
    while k + LANES <= n {
        let a = load_gf(dst.as_ptr().add(k) as *const GF);
        let c = simd_mul(a, s);
        store_gf(dst.as_mut_ptr().add(k), c);
        k += LANES;
    }
    while k < n {
        dst[k] = dst[k] * scalar;
        k += 1;
    }
}
