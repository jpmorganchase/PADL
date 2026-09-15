// lattice_enc.rs — Ring-LWE / SIS commitment with exact sqrt q decryption.

use crate::field::*;
use crate::ntt::{negacyclic_intt, negacyclic_ntt};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

pub const KAPPA_SIS: usize = 4; // number of SIS rows (c_0 dimension)
pub const NUM_MSG_ROWS: usize = 2; // message rows: m and sqrt q·m

const P_HALF: u128 = P / 2;

/// Public matrix (M×K, NTT domain) plus the secrets needed for extraction.
pub struct EncKeys {
    pub d: usize,
    pub k: usize,
    pub a_mat: Vec<Vec<Vec<ArkField>>>, // M × K × d, NTT domain
    pub s_msg: Vec<Vec<ArkField>>,      // KAPPA_SIS secret polys for the m row
    pub s_scaled: Vec<Vec<ArkField>>,   // KAPPA_SIS secret polys for the sqrt q·m row
    pub psi: ArkField,
}

#[inline]
fn to_centered(value: ArkField) -> i128 {
    let x = to_u128(value);
    // avoid casting P (~2^128) to i128; keep the large magnitude in u128
    if x > P_HALF {
        -((P - x) as i128)
    } else {
        x as i128
    }
}

#[inline]
fn from_centered(x: i128) -> ArkField {
    from_u128(if x < 0 {
        P - x.unsigned_abs()
    } else {
        x as u128
    })
}

/// Reduce `t` into the centered interval (−q/2, q/2].
#[inline]
fn centered_rem(t: i128, q: i128) -> i128 {
    let mut r = t % q;
    if r < 0 {
        r += q;
    }
    if r > q / 2 {
        r - q
    } else {
        r
    }
}

/// Bound for uniform coefficient sampling: coefficients in [−2^15, 2^15].
const SAMPLE_BOUND: i128 = 1 << 15;

/// Sample a ring element with coefficients uniform in [−2^15, 2^15],
/// stored in centered field representation.
fn sample_bounded_uniform(d: usize, rng: &mut StdRng) -> Vec<ArkField> {
    (0..d)
        .map(|_| {
            let v = rng.gen_range(0i128..=(2 * SAMPLE_BOUND)) - SAMPLE_BOUND;
            from_centered(v)
        })
        .collect()
}

/// Sample K bounded-uniform randomness polynomials (commitment randomness r) from a seed.
pub fn sample_r(d: usize, k: usize, seed: u64) -> Vec<Vec<ArkField>> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..k)
        .map(|_| sample_bounded_uniform(d, &mut rng))
        .collect()
}

/// Sample a uniform ring element in NTT domain (uniform over the ring).
fn sample_uniform_ntt(d: usize, rng: &mut StdRng) -> Vec<ArkField> {
    (0..d).map(|_| from_u128(rng.gen::<u128>() % P)).collect()
}

fn root_2d(d: usize) -> ArkField {
    root_of_unity(2 * d as u128)
}

/// Generate the shared SIS block A_sis (κ_sis × K uniform ring elements, NTT
/// domain) from a global seed.
pub fn gen_a_sis(d: usize, k: usize, seed_sis: u64) -> Vec<Vec<Vec<ArkField>>> {
    let mut rng = StdRng::seed_from_u64(seed_sis);
    let mut a_sis: Vec<Vec<Vec<ArkField>>> = Vec::with_capacity(KAPPA_SIS);
    for _ in 0..KAPPA_SIS {
        let mut row = Vec::with_capacity(k);
        for _ in 0..k {
            row.push(sample_uniform_ntt(d, &mut rng));
        }
        a_sis.push(row);
    }
    a_sis
}

/// Build a recipient's keys from the shared A_sis and a per-recipient seed.
/// Returns the full matrix A_R = [A_sis ; B ; B'] plus the extraction secret.
pub fn commit_gen_with_sis(
    a_sis: &[Vec<Vec<ArkField>>],
    d: usize,
    k: usize,
    seed_r: u64,
) -> EncKeys {
    let mut rng = StdRng::seed_from_u64(seed_r);
    let psi = root_2d(d);
    let m_rows = KAPPA_SIS + NUM_MSG_ROWS;

    let mut a_mat: Vec<Vec<Vec<ArkField>>> = Vec::with_capacity(m_rows);
    for row in a_sis.iter().take(KAPPA_SIS) {
        a_mat.push(row.clone());
    }

    // Build one message row: B[kk] = Σ_j s_j·A_sis[j][kk] + e[kk].
    let build_msg_row = |a_mat: &Vec<Vec<Vec<ArkField>>>,
                         rng: &mut StdRng|
     -> (Vec<Vec<ArkField>>, Vec<Vec<ArkField>>) {
        let s: Vec<Vec<ArkField>> = (0..KAPPA_SIS)
            .map(|_| sample_bounded_uniform(d, rng))
            .collect();
        let s_ntt: Vec<Vec<ArkField>> = s.iter().map(|sj| negacyclic_ntt(sj, psi)).collect();
        let mut b_row: Vec<Vec<ArkField>> = Vec::with_capacity(k);
        for kk in 0..k {
            let e_kk = sample_bounded_uniform(d, rng);
            let e_ntt = negacyclic_ntt(&e_kk, psi);
            let mut b_kk = vec![from_u128(0); d];
            for i in 0..d {
                let mut acc = e_ntt[i];
                for j in 0..KAPPA_SIS {
                    acc = fadd(acc, fmul(s_ntt[j][i], a_mat[j][kk][i]));
                }
                b_kk[i] = acc;
            }
            b_row.push(b_kk);
        }
        (b_row, s)
    };

    let (b_msg, s_msg) = build_msg_row(&a_mat, &mut rng);
    a_mat.push(b_msg);
    let (b_scaled, s_scaled) = build_msg_row(&a_mat, &mut rng);
    a_mat.push(b_scaled);

    EncKeys {
        d,
        k,
        a_mat,
        s_msg,
        s_scaled,
        psi,
    }
}

/// Generate keys with A_sis derived from the same seed (single-key convenience).
pub fn commit_gen(d: usize, k: usize, seed: u64) -> EncKeys {
    let a_sis = gen_a_sis(d, k, seed);
    commit_gen_with_sis(&a_sis, d, k, seed)
}

/// Commit to a coefficient-domain message `m_coef` with ternary randomness
/// `r_coeffs` (K polynomials). Returns c (M × d, NTT domain).
pub fn commit(
    keys: &EncKeys,
    m_coef: &[ArkField],
    r_coeffs: &[Vec<ArkField>],
    sqrt_q: ArkField,
) -> Vec<Vec<ArkField>> {
    let d = keys.d;
    let k = keys.k;
    let m_rows = keys.a_mat.len();
    let r_ntt: Vec<Vec<ArkField>> = r_coeffs
        .iter()
        .map(|r| negacyclic_ntt(r, keys.psi))
        .collect();
    let m_ntt = negacyclic_ntt(m_coef, keys.psi);

    let mut c: Vec<Vec<ArkField>> = Vec::with_capacity(m_rows);
    for row in 0..m_rows {
        let mut cm = vec![from_u128(0); d];
        for i in 0..d {
            let mut acc = from_u128(0);
            for kk in 0..k {
                acc = fadd(acc, fmul(keys.a_mat[row][kk][i], r_ntt[kk][i]));
            }
            cm[i] = acc;
        }
        c.push(cm);
    }
    // Inject message into the two message rows.
    for i in 0..d {
        c[KAPPA_SIS][i] = fadd(c[KAPPA_SIS][i], m_ntt[i]);
        c[KAPPA_SIS + 1][i] = fadd(c[KAPPA_SIS + 1][i], fmul(sqrt_q, m_ntt[i]));
    }
    c
}

/// Commit with the message given directly in NTT domain (matching the STARK's
/// `cNtts`, where `mNtt` is added to rows M-2/M-1 without an INTT).
pub fn commit_ntt(
    keys: &EncKeys,
    m_ntt: &[ArkField],
    r_coeffs: &[Vec<ArkField>],
    sqrt_q: ArkField,
) -> Vec<Vec<ArkField>> {
    let d = keys.d;
    let k = keys.k;
    let m_rows = keys.a_mat.len();
    let r_ntt: Vec<Vec<ArkField>> = r_coeffs
        .iter()
        .map(|r| negacyclic_ntt(r, keys.psi))
        .collect();

    let mut c: Vec<Vec<ArkField>> = Vec::with_capacity(m_rows);
    for row in 0..m_rows {
        let mut cm = vec![from_u128(0); d];
        for i in 0..d {
            let mut acc = from_u128(0);
            for kk in 0..k {
                acc = fadd(acc, fmul(keys.a_mat[row][kk][i], r_ntt[kk][i]));
            }
            cm[i] = acc;
        }
        c.push(cm);
    }
    for i in 0..d {
        c[KAPPA_SIS][i] = fadd(c[KAPPA_SIS][i], m_ntt[i]);
        c[KAPPA_SIS + 1][i] = fadd(c[KAPPA_SIS + 1][i], fmul(sqrt_q, m_ntt[i]));
    }
    c
}

/// Extract the coefficient-domain message from a commitment.
pub fn extract(keys: &EncKeys, c: &[Vec<ArkField>], sqrt_q: ArkField) -> Vec<ArkField> {
    let d = keys.d;
    let psi = keys.psi;
    let s_msg_ntt: Vec<Vec<ArkField>> = keys.s_msg.iter().map(|s| negacyclic_ntt(s, psi)).collect();
    let s_scaled_ntt: Vec<Vec<ArkField>> = keys
        .s_scaled
        .iter()
        .map(|s| negacyclic_ntt(s, psi))
        .collect();

    // x = c_m − sᵀ·c_0 ,  x* = c_m* − (s')ᵀ·c_0   (pointwise, NTT domain)
    let mut x_ntt = vec![from_u128(0); d];
    let mut x2_ntt = vec![from_u128(0); d];
    for i in 0..d {
        let mut dot = from_u128(0);
        let mut dot2 = from_u128(0);
        for j in 0..KAPPA_SIS {
            dot = fadd(dot, fmul(s_msg_ntt[j][i], c[j][i]));
            dot2 = fadd(dot2, fmul(s_scaled_ntt[j][i], c[j][i]));
        }
        x_ntt[i] = fsub(c[KAPPA_SIS][i], dot);
        x2_ntt[i] = fsub(c[KAPPA_SIS + 1][i], dot2);
    }

    let x_coef = negacyclic_intt(&x_ntt, psi);
    let x2_coef = negacyclic_intt(&x2_ntt, psi);

    let inv_sqrt_q = finv(sqrt_q);
    let sq_i = to_u128(sqrt_q) as i128;
    let mut m_coef = vec![from_u128(0); d];
    for l in 0..d {
        let xv = x_coef[l];
        let x2v = x2_coef[l];
        // t = sqrt q·x − x*  (= sqrt q·(e·r) − (e'·r), message cancels exactly)
        let t = fsub(fmul(sqrt_q, xv), x2v);
        let k = centered_rem(to_centered(t), sq_i); // = −(e'·r), small
                                                    // m = (x* + k)·(sqrt q)⁻¹
        m_coef[l] = fmul(fadd(x2v, from_centered(k)), inv_sqrt_q);
    }
    m_coef
}

/// Extract a message that was committed in NTT domain (via `commit_ntt` or the
/// STARK's `cNtts`). Returns the recovered NTT-domain vector.
pub fn extract_ntt(keys: &EncKeys, c: &[Vec<ArkField>], sqrt_q: ArkField) -> Vec<ArkField> {
    let m_coef = extract(keys, c, sqrt_q);
    negacyclic_ntt(&m_coef, keys.psi)
}

/// End-to-end round trip: returns true iff extract(commit(m)) == m for a
/// random full-range message. Used for NAPI cross-checking.
pub fn roundtrip_ok(d: usize, k: usize, sqrt_q: ArkField, seed: u64) -> bool {
    let keys = commit_gen(d, k, seed);
    let mut rng = StdRng::seed_from_u64(seed ^ 0x9E3779B97F4A7C15);
    // Full-range message (no smallness requirement).
    let m_coef: Vec<ArkField> = (0..d).map(|_| from_u128(rng.gen::<u128>() % P)).collect();
    let r_coeffs: Vec<Vec<ArkField>> = (0..k)
        .map(|_| sample_bounded_uniform(d, &mut rng))
        .collect();
    let c = commit(&keys, &m_coef, &r_coeffs, sqrt_q);
    let rec = extract(&keys, &c, sqrt_q);
    rec == m_coef
}

#[cfg(test)]
mod tests {
    use super::*;

    const SQRT_Q: u128 = 18446744073709551615;

    #[test]
    fn roundtrip_full_range_message() {
        for seed in 0..8u64 {
            assert!(
                roundtrip_ok(256, 10, from_u128(SQRT_Q), seed),
                "seed {}",
                seed
            );
        }
    }

    #[test]
    fn roundtrip_larger_degree() {
        assert!(roundtrip_ok(1024, 10, from_u128(SQRT_Q), 42));
    }

    #[test]
    fn wrong_key_fails() {
        let d = 256;
        let k = 10;
        let keys = commit_gen(d, k, 1);
        let other = commit_gen(d, k, 2);
        let mut rng = StdRng::seed_from_u64(7);
        let m_coef: Vec<ArkField> = (0..d).map(|_| from_u128(rng.gen::<u128>() % P)).collect();
        let r_coeffs: Vec<Vec<ArkField>> = (0..k)
            .map(|_| sample_bounded_uniform(d, &mut rng))
            .collect();
        let c = commit(&keys, &m_coef, &r_coeffs, from_u128(SQRT_Q));
        let rec = extract(&other, &c, from_u128(SQRT_Q));
        assert_ne!(rec, m_coef);
    }
}
