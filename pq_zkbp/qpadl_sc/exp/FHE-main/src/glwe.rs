use crate::field::GF;
use crate::lwe::{LweCiphertext, LweCiphertextBig};
use crate::ntt::NttContext;
use crate::params::{N_LWE, N_POLY, SIGMA};
use crate::poly::Poly;
use rand::Rng;
use rand_distr::{Distribution, Normal};

/// GLWE ciphertext: (a(X), b(X)) ∈ R_Q^2 (for k=1)
/// Encrypts μ(X) such that b = a*s + Δ*μ + e
#[derive(Clone, Debug)]
pub struct GlweCiphertext {
    pub a: Poly,
    pub b: Poly,
}

/// GLWE secret key: polynomial s(X) with small coefficients
#[derive(Clone, Debug)]
pub struct GlweSecretKey {
    pub key: Poly, // binary coefficients
}

impl GlweSecretKey {
    /// Generate a random binary GLWE secret key
    pub fn generate<R: Rng>(rng: &mut R) -> Self {
        let coeffs: Vec<GF> = (0..N_POLY)
            .map(|_| GF::new(rng.gen_range(0..=1u64)))
            .collect();
        GlweSecretKey {
            key: Poly::from_coeffs(coeffs),
        }
    }

    /// Encrypt a polynomial message μ(X)
    pub fn encrypt<R: Rng>(&self, mu: &Poly, ctx: &NttContext, rng: &mut R) -> GlweCiphertext {
        // Sample random mask polynomial
        let a_coeffs: Vec<GF> = (0..N_POLY).map(|_| GF::new(rng.gen::<u64>())).collect();
        let a = Poly::from_coeffs(a_coeffs);

        // Sample error polynomial
        let normal = Normal::new(0.0, SIGMA).unwrap();
        let e_coeffs: Vec<GF> = (0..N_POLY)
            .map(|_| GF::from_signed(normal.sample(rng) as i64))
            .collect();
        let e = Poly::from_coeffs(e_coeffs);

        // b = a*s + μ + e
        let a_times_s = a.mul_ntt(&self.key, ctx);
        let b = &(&a_times_s + mu) + &e;

        GlweCiphertext { a, b }
    }

    /// Decrypt a GLWE ciphertext
    pub fn decrypt(&self, ct: &GlweCiphertext, ctx: &NttContext) -> Poly {
        // μ + e = b - a*s
        let a_times_s = ct.a.mul_ntt(&self.key, ctx);
        &ct.b - &a_times_s
    }

    /// Get the coefficients of the secret key as a vector (for key switching)
    pub fn key_coeffs(&self) -> Vec<u64> {
        self.key.coeffs.iter().map(|c| c.0).collect()
    }
}

impl GlweCiphertext {
    /// Create a trivial (noiseless) GLWE encryption of μ: (0, μ)
    pub fn trivial(mu: &Poly) -> Self {
        GlweCiphertext {
            a: Poly::zero(),
            b: mu.clone(),
        }
    }

    /// Add two GLWE ciphertexts
    pub fn add(&self, other: &Self) -> Self {
        GlweCiphertext {
            a: &self.a + &other.a,
            b: &self.b + &other.b,
        }
    }

    /// Subtract two GLWE ciphertexts
    pub fn sub(&self, other: &Self) -> Self {
        GlweCiphertext {
            a: &self.a - &other.a,
            b: &self.b - &other.b,
        }
    }

    /// Monomial rotation: X^k * ct (rotate both components)
    pub fn monomial_rotate(&self, k: usize) -> Self {
        GlweCiphertext {
            a: self.a.monomial_rotate(k),
            b: self.b.monomial_rotate(k),
        }
    }

    /// Sample extraction: extract LWE ciphertext for the constant coefficient.
    /// Output: LWE_{s'}(μ_0) where s' = (s_0, s_1, ..., s_{N-1}) (GLWE key coefficients)
    /// Formula: a_LWE = (a_0, -a_{N-1}, -a_{N-2}, ..., -a_1), b_LWE = b_0
    pub fn sample_extract(&self) -> LweCiphertextBig {
        let mut a_lwe = vec![GF::ZERO; N_POLY];
        a_lwe[0] = self.a.coeffs[0];
        for i in 1..N_POLY {
            a_lwe[i] = -self.a.coeffs[N_POLY - i];
        }

        LweCiphertextBig {
            a: a_lwe,
            b: self.b.coeffs[0],
        }
    }
}

/// Decrypt a big LWE ciphertext (dimension N_POLY) using GLWE secret key coefficients
pub fn decrypt_lwe_big(ct: &LweCiphertextBig, sk: &GlweSecretKey) -> GF {
    let mut dot = GF::ZERO;
    for i in 0..N_POLY {
        dot = dot + ct.a[i] * sk.key.coeffs[i];
    }
    ct.b - dot
}

/// Decrypt a small LWE ciphertext (dimension N_LWE) using LWE secret key
pub fn decrypt_lwe_small(ct: &LweCiphertext, sk: &crate::lwe::LweSecretKey) -> GF {
    let mut dot = GF::ZERO;
    for i in 0..N_LWE {
        if sk.key[i] == 1 {
            dot = dot + ct.a[i];
        }
    }
    ct.b - dot
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::DELTA;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_glwe_encrypt_decrypt() {
        let mut rng = StdRng::seed_from_u64(42);
        let ctx = NttContext::new();
        let sk = GlweSecretKey::generate(&mut rng);

        // Encrypt μ(X) = Δ*2 (constant polynomial)
        let mut mu_coeffs = vec![GF::ZERO; N_POLY];
        mu_coeffs[0] = GF(DELTA * 2);
        let mu = Poly::from_coeffs(mu_coeffs);

        let ct = sk.encrypt(&mu, &ctx, &mut rng);
        let decrypted = sk.decrypt(&ct, &ctx);

        // Check constant coefficient decodes to 2
        let phase = decrypted.coeffs[0].0;
        let m = crate::lwe::decode_phase(phase);
        assert_eq!(m, 2);
    }

    #[test]
    fn test_sample_extract() {
        let mut rng = StdRng::seed_from_u64(55);
        let ctx = NttContext::new();
        let sk = GlweSecretKey::generate(&mut rng);

        let mut mu_coeffs = vec![GF::ZERO; N_POLY];
        mu_coeffs[0] = GF(DELTA * 3);
        let mu = Poly::from_coeffs(mu_coeffs);

        let ct = sk.encrypt(&mu, &ctx, &mut rng);
        let lwe_big = ct.sample_extract();

        // Decrypt the big LWE
        let phase = decrypt_lwe_big(&lwe_big, &sk);
        let m = crate::lwe::decode_phase(phase.0);
        assert_eq!(m, 3);
    }
}
