use crate::field::GF;
use crate::ggsw::GgswCiphertext;
use crate::glwe::{GlweCiphertext, GlweSecretKey};
use crate::lwe::{LweCiphertext, LweSecretKey};
use crate::ntt::NttContext;
use crate::params::{B_KS, L_KS, N_LWE, N_POLY, SIGMA};
use crate::poly::Poly;
use rand::Rng;
use rand::SeedableRng;
use rand_distr::{Distribution, Normal};
use rayon::prelude::*;

/// Bootstrapping key: BSK[i] = GGSW_{GLWE_key}(LWE_key[i]) for i in 0..n
pub struct BootstrappingKey {
    pub entries: Vec<GgswCiphertext>, // n entries
}

/// Key-switching key: KSK[i][j] = LWE_s(s'_i * B_KS^j) for GLWE key coeff i, level j
/// Switches from dimension N_POLY (GLWE key) to dimension N_LWE (LWE key)
pub struct KeySwitchingKey {
    pub entries: Vec<Vec<LweCiphertext>>, // N_POLY × L_KS
}

/// Generate the bootstrapping key
pub fn gen_bootstrapping_key<R: Rng + SeedableRng>(
    lwe_sk: &LweSecretKey,
    glwe_sk: &GlweSecretKey,
    ctx: &NttContext,
    rng: &mut R,
) -> BootstrappingKey {
    // Generate independent seeds for parallel GGSW encryption
    let seeds: Vec<u64> = (0..N_LWE).map(|_| rng.gen()).collect();

    let entries: Vec<GgswCiphertext> = seeds
        .into_par_iter()
        .enumerate()
        .map(|(i, seed)| {
            let mut local_rng = R::seed_from_u64(seed);
            let bit = lwe_sk.key[i] as u64;
            GgswCiphertext::encrypt(bit, glwe_sk, ctx, &mut local_rng)
        })
        .collect();

    BootstrappingKey { entries }
}

/// Generate the key-switching key
/// Switches LWE ciphertext from key s' (GLWE key coefficients, dim N_POLY)
/// to key s (LWE key, dim N_LWE)
pub fn gen_key_switching_key<R: Rng>(
    lwe_sk: &LweSecretKey,
    glwe_sk: &GlweSecretKey,
    rng: &mut R,
) -> KeySwitchingKey {
    let normal = Normal::new(0.0, SIGMA).unwrap();
    let mut entries = Vec::with_capacity(N_POLY);

    for i in 0..N_POLY {
        let s_i = glwe_sk.key.coeffs[i].0; // s'_i (GLWE key coefficient)
        let mut level_entries = Vec::with_capacity(L_KS);

        for j in 0..L_KS {
            // KSK[i][j] = LWE_s(s'_i * B_KS^j)
            // This is an encryption under the LWE key of the scaled GLWE key coefficient
            let scale = B_KS.pow(j as u32);
            let msg_val = GF(s_i) * GF(scale); // s'_i * B^j mod Q

            // Sample random mask
            let a: Vec<GF> = (0..N_LWE).map(|_| GF::new(rng.gen::<u64>())).collect();

            // Compute <a, s_LWE>
            let mut dot = GF::ZERO;
            for k in 0..N_LWE {
                if lwe_sk.key[k] == 1 {
                    dot = dot + a[k];
                }
            }

            // b = <a, s> + s'_i * B^j + e
            let e = GF::from_signed(normal.sample(rng) as i64);
            let b = dot + msg_val + e;

            level_entries.push(LweCiphertext { a, b });
        }

        entries.push(level_entries);
    }

    KeySwitchingKey { entries }
}

/// GLWE-to-GLWE Key-Switching Key.
///
/// An RLev encryption of (s_BR - s_out) under s_out:
///   KSK[l] = RLWE_{s_out}((s_BR - s_out) · B^l)  for l = 0..L_KS-1
///
/// Each entry is a pair (a_l(X), b_l(X)) in NTT domain.
pub struct GlweKeySwitchingKey {
    /// L_KS RLWE ciphertexts as (a_ntt, b_ntt) pairs
    pub entries: Vec<(Vec<GF>, Vec<GF>)>, // L_KS entries, each (N_POLY NTT values, N_POLY NTT values)
}

/// Generate the GLWE key-switching key.
///
/// Switches GLWE from key `s_br` to key `s_out`.
/// `s_out` is constructed so its first N_LWE coefficients are the LWE key.
///
/// KSK[l] = RLWE_{s_out}((s_br - s_out) · B^l) for l = 0..L_KS-1
pub fn gen_glwe_key_switching_key<R: Rng>(
    s_br: &GlweSecretKey,
    s_out_key: &Poly, // s_out polynomial (first N_LWE coeffs = LWE key, rest = 0)
    ctx: &NttContext,
    rng: &mut R,
) -> GlweKeySwitchingKey {
    let normal = Normal::new(0.0, SIGMA).unwrap();

    // Compute s_diff = s_br - s_out in coefficient domain
    let mut s_diff_coeffs = vec![GF::ZERO; N_POLY];
    for i in 0..N_POLY {
        s_diff_coeffs[i] = s_br.key.coeffs[i] - s_out_key.coeffs[i];
    }

    // NTT of s_out (for encryption)
    let mut s_out_ntt = s_out_key.coeffs.clone();
    ctx.forward(&mut s_out_ntt);

    let mut entries = Vec::with_capacity(L_KS);

    for l in 0..L_KS {
        // Message polynomial: (s_br - s_out) · B^l
        let scale = GF(B_KS.pow(l as u32) as u64);
        let msg_coeffs: Vec<GF> = s_diff_coeffs.iter().map(|&c| c * scale).collect();

        // Encrypt under s_out: (a, b) where b = a·s_out + msg + e
        let a_coeffs: Vec<GF> = (0..N_POLY).map(|_| GF::new(rng.gen::<u64>())).collect();
        let e_coeffs: Vec<GF> = (0..N_POLY)
            .map(|_| GF::from_signed(normal.sample(rng) as i64))
            .collect();

        // NTT of a
        let mut a_ntt = a_coeffs.clone();
        ctx.forward(&mut a_ntt);

        // b = a·s_out + msg + e  (compute in NTT domain for a·s_out, then add coeff-domain terms)
        // Actually: do everything in coefficient domain for correctness
        // b_coeffs[i] = (INTT(a_ntt * s_out_ntt))[i] + msg_coeffs[i] + e_coeffs[i]
        // Simpler: compute a·s_out via NTT, then INTT, add msg+e, then NTT the result

        // a·s_out in NTT domain (pointwise)
        let mut as_ntt: Vec<GF> = (0..N_POLY).map(|j| a_ntt[j] * s_out_ntt[j]).collect();

        // INTT to get a·s_out in coefficient domain
        ctx.inverse(&mut as_ntt);
        let as_coeffs = as_ntt; // now coefficient domain

        // b = a·s_out + msg + e (coefficient domain)
        let b_coeffs: Vec<GF> = (0..N_POLY)
            .map(|i| as_coeffs[i] + msg_coeffs[i] + e_coeffs[i])
            .collect();

        // Convert to NTT domain for storage
        let mut b_ntt = b_coeffs;
        ctx.forward(&mut b_ntt);

        entries.push((a_ntt, b_ntt));
    }

    GlweKeySwitchingKey { entries }
}

/// Construct s_out polynomial: first N_LWE coefficients are the LWE key bits, rest are 0.
pub fn make_s_out_poly(lwe_sk: &LweSecretKey) -> Poly {
    let mut coeffs = vec![GF::ZERO; N_POLY];
    for i in 0..N_LWE {
        coeffs[i] = GF(lwe_sk.key[i] as u64);
    }
    Poly::from_coeffs(coeffs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_keygen_sizes() {
        let mut rng = StdRng::seed_from_u64(42);
        let ctx = NttContext::new();
        let lwe_sk = LweSecretKey::generate(&mut rng);
        let glwe_sk = GlweSecretKey::generate(&mut rng);

        let bsk = gen_bootstrapping_key(&lwe_sk, &glwe_sk, &ctx, &mut rng);
        assert_eq!(bsk.entries.len(), N_LWE);

        let ksk = gen_key_switching_key(&lwe_sk, &glwe_sk, &mut rng);
        assert_eq!(ksk.entries.len(), N_POLY);
        assert_eq!(ksk.entries[0].len(), L_KS);
    }
}
