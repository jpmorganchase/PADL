use crate::field::GF;
use crate::gadget::decompose_poly_pbs;
use crate::glwe::{GlweCiphertext, GlweSecretKey};
use crate::ntt::NttContext;
use crate::params::{B_PBS, L_PBS, N_POLY, SIGMA};
use crate::poly::Poly;
use rand::Rng;
use rand_distr::{Distribution, Normal};
use rayon::prelude::*;

#[cfg(target_arch = "x86_64")]
use crate::simd;

/// GGSW ciphertext: 2*l rows, each row is a GLWE ciphertext (a, b).
/// Structure: rows 0..l-1 have m*B^j in the mask (a) component;
///            rows l..2l-1 have m*B^j in the body (b) component.
/// The NTT-domain forms are precomputed for fast external products.
#[derive(Clone, Debug)]
pub struct GgswCiphertext {
    pub rows: Vec<GlweCiphertext>, // 2*L_PBS GLWE ciphertexts
    /// Precomputed NTT forms: rows_ntt[i] = (ntt(rows[i].a), ntt(rows[i].b))
    pub rows_ntt: Vec<(Vec<GF>, Vec<GF>)>,
}

impl GgswCiphertext {
    /// Encrypt a scalar m ∈ {0, 1} as a GGSW ciphertext under the GLWE key.
    /// C = Z + m * G where Z is 2l GLWE(0) encryptions.
    pub fn encrypt<R: Rng>(m: u64, sk: &GlweSecretKey, ctx: &NttContext, rng: &mut R) -> Self {
        let normal = Normal::new(0.0, SIGMA).unwrap();
        let mut rows = Vec::with_capacity(2 * L_PBS);

        for j in 0..L_PBS {
            // Row j: GLWE(0) with m * B^j added to the mask (a component)
            let a_coeffs: Vec<GF> = (0..N_POLY).map(|_| GF::new(rng.gen::<u64>())).collect();
            let e_coeffs: Vec<GF> = (0..N_POLY)
                .map(|_| GF::from_signed(normal.sample(rng) as i64))
                .collect();
            let a = Poly::from_coeffs(a_coeffs);
            let e = Poly::from_coeffs(e_coeffs);

            // b = a * s + e (encryption of 0)
            let b = &a.mul_ntt(&sk.key, ctx) + &e;

            // Add m * B^j to the mask
            let scale = GF::new(m * B_PBS.pow(j as u32));
            let mut a_modified = a;
            a_modified.coeffs[0] = a_modified.coeffs[0] + scale;

            rows.push(GlweCiphertext { a: a_modified, b });
        }

        for j in 0..L_PBS {
            // Row l+j: GLWE(0) with m * B^j added to the body (b component)
            let a_coeffs: Vec<GF> = (0..N_POLY).map(|_| GF::new(rng.gen::<u64>())).collect();
            let e_coeffs: Vec<GF> = (0..N_POLY)
                .map(|_| GF::from_signed(normal.sample(rng) as i64))
                .collect();
            let a = Poly::from_coeffs(a_coeffs);
            let e = Poly::from_coeffs(e_coeffs);

            // b = a * s + e + m * B^j
            let scale = GF::new(m * B_PBS.pow(j as u32));
            let mut b = &a.mul_ntt(&sk.key, ctx) + &e;
            b.coeffs[0] = b.coeffs[0] + scale;

            rows.push(GlweCiphertext { a, b });
        }

        // Precompute NTT forms of all row polynomials
        let rows_ntt: Vec<(Vec<GF>, Vec<GF>)> = rows
            .iter()
            .map(|row| {
                let mut a_ntt = row.a.coeffs.clone();
                let mut b_ntt = row.b.coeffs.clone();
                ctx.forward(&mut a_ntt);
                ctx.forward(&mut b_ntt);
                (a_ntt, b_ntt)
            })
            .collect();

        GgswCiphertext { rows, rows_ntt }
    }

    /// External product: GLWE ⊡ GGSW → GLWE
    /// Uses precomputed NTT forms and AVX-512 SIMD acceleration.
    /// Cost: 2*L forward NTTs (decomp polys) + 4*L pointwise muls + 2 inverse NTTs.
    pub fn external_product(&self, ct: &GlweCiphertext, ctx: &NttContext) -> GlweCiphertext {
        // Decompose both components
        let decomp_a = decompose_poly_pbs(&ct.a);
        let decomp_b = decompose_poly_pbs(&ct.b);

        // Forward NTT all 2*L decomposed polynomials in parallel
        let all_ntt: Vec<Vec<GF>> = (0..2 * L_PBS)
            .into_par_iter()
            .map(|i| {
                let poly = if i < L_PBS {
                    &decomp_a[i]
                } else {
                    &decomp_b[i - L_PBS]
                };
                let mut ntt = poly.coeffs.clone();
                ctx.forward(&mut ntt);
                ntt
            })
            .collect();

        // Accumulate pointwise products in NTT domain using SIMD
        let mut result_a_ntt = vec![GF::ZERO; N_POLY];
        let mut result_b_ntt = vec![GF::ZERO; N_POLY];

        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx512f") {
                for j in 0..L_PBS {
                    unsafe {
                        simd::pointwise_accum(
                            &mut result_a_ntt,
                            &mut result_b_ntt,
                            &all_ntt[j],
                            &all_ntt[L_PBS + j],
                            &self.rows_ntt[j].0,
                            &self.rows_ntt[j].1,
                            &self.rows_ntt[L_PBS + j].0,
                            &self.rows_ntt[L_PBS + j].1,
                        );
                    }
                }
            } else {
                Self::accumulate_scalar(
                    &all_ntt,
                    &self.rows_ntt,
                    &mut result_a_ntt,
                    &mut result_b_ntt,
                );
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Self::accumulate_scalar(
                &all_ntt,
                &self.rows_ntt,
                &mut result_a_ntt,
                &mut result_b_ntt,
            );
        }

        // Inverse NTT to get result polynomials
        ctx.inverse(&mut result_a_ntt);
        ctx.inverse(&mut result_b_ntt);

        GlweCiphertext {
            a: Poly::from_coeffs(result_a_ntt),
            b: Poly::from_coeffs(result_b_ntt),
        }
    }

    /// Scalar fallback for pointwise accumulation
    fn accumulate_scalar(
        all_ntt: &[Vec<GF>],
        rows_ntt: &[(Vec<GF>, Vec<GF>)],
        result_a: &mut [GF],
        result_b: &mut [GF],
    ) {
        for j in 0..L_PBS {
            for k in 0..N_POLY {
                let da = all_ntt[j][k];
                let db = all_ntt[L_PBS + j][k];
                result_a[k] = result_a[k] + da * rows_ntt[j].0[k] + db * rows_ntt[L_PBS + j].0[k];
                result_b[k] = result_b[k] + da * rows_ntt[j].1[k] + db * rows_ntt[L_PBS + j].1[k];
            }
        }
    }

    /// CMUX gate: if self encrypts bit b, output ct_b
    /// CMUX(C, ct0, ct1) = ct0 + (ct1 - ct0) ⊡ C
    pub fn cmux(
        &self,
        ct0: &GlweCiphertext,
        ct1: &GlweCiphertext,
        ctx: &NttContext,
    ) -> GlweCiphertext {
        let diff = ct1.sub(ct0);
        let product = self.external_product(&diff, ctx);
        ct0.add(&product)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::DELTA;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_cmux_select_0() {
        let mut rng = StdRng::seed_from_u64(42);
        let ctx = NttContext::new();
        let sk = GlweSecretKey::generate(&mut rng);

        // Encrypt bit = 0 in GGSW
        let ggsw = GgswCiphertext::encrypt(0, &sk, &ctx, &mut rng);

        // Two trivial GLWE ciphertexts
        let mut mu0_coeffs = vec![GF::ZERO; N_POLY];
        mu0_coeffs[0] = GF(DELTA * 1); // message = 1
        let ct0 = GlweCiphertext::trivial(&Poly::from_coeffs(mu0_coeffs));

        let mut mu1_coeffs = vec![GF::ZERO; N_POLY];
        mu1_coeffs[0] = GF(DELTA * 3); // message = 3
        let ct1 = GlweCiphertext::trivial(&Poly::from_coeffs(mu1_coeffs));

        // CMUX should select ct0 (bit=0)
        let result = ggsw.cmux(&ct0, &ct1, &ctx);
        let decrypted = sk.decrypt(&result, &ctx);
        let m = crate::lwe::decode_phase(decrypted.coeffs[0].0);
        assert_eq!(m, 1);
    }

    #[test]
    fn test_cmux_select_1() {
        let mut rng = StdRng::seed_from_u64(42);
        let ctx = NttContext::new();
        let sk = GlweSecretKey::generate(&mut rng);

        // Encrypt bit = 1 in GGSW
        let ggsw = GgswCiphertext::encrypt(1, &sk, &ctx, &mut rng);

        // Two trivial GLWE ciphertexts
        let mut mu0_coeffs = vec![GF::ZERO; N_POLY];
        mu0_coeffs[0] = GF(DELTA * 1); // message = 1
        let ct0 = GlweCiphertext::trivial(&Poly::from_coeffs(mu0_coeffs));

        let mut mu1_coeffs = vec![GF::ZERO; N_POLY];
        mu1_coeffs[0] = GF(DELTA * 3); // message = 3
        let ct1 = GlweCiphertext::trivial(&Poly::from_coeffs(mu1_coeffs));

        // CMUX should select ct1 (bit=1)
        let result = ggsw.cmux(&ct0, &ct1, &ctx);
        let decrypted = sk.decrypt(&result, &ctx);
        let m = crate::lwe::decode_phase(decrypted.coeffs[0].0);
        assert_eq!(m, 3);
    }
}
