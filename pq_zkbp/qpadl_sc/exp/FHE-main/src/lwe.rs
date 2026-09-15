use crate::field::GF;
use crate::params::{DELTA, N_LWE, Q, SIGMA, T_PLAIN};
use rand::Rng;
use rand_distr::{Distribution, Normal};

/// LWE ciphertext: (a, b) ∈ Z_Q^{n+1}
/// Encrypts m such that b = <a, s> + Δ*m + e (mod Q)
#[derive(Clone, Debug)]
pub struct LweCiphertext {
    pub a: Vec<GF>,
    pub b: GF,
}

/// LWE secret key: binary vector s ∈ {0,1}^n
#[derive(Clone, Debug)]
pub struct LweSecretKey {
    pub key: Vec<u8>, // 0 or 1
}

impl LweSecretKey {
    /// Generate a random binary secret key
    pub fn generate<R: Rng>(rng: &mut R) -> Self {
        let key: Vec<u8> = (0..N_LWE).map(|_| rng.gen_range(0..=1)).collect();
        LweSecretKey { key }
    }

    /// Encrypt a plaintext m ∈ Z_t
    pub fn encrypt<R: Rng>(&self, m: u64, rng: &mut R) -> LweCiphertext {
        assert!(m < T_PLAIN);

        // Sample random mask
        let a: Vec<GF> = (0..N_LWE).map(|_| GF::new(rng.gen::<u64>())).collect();

        // Compute <a, s>
        let mut dot = GF::ZERO;
        for i in 0..N_LWE {
            if self.key[i] == 1 {
                dot = dot + a[i];
            }
        }

        // Sample noise
        let normal = Normal::new(0.0, SIGMA).unwrap();
        let e: i64 = normal.sample(rng) as i64;
        let e_field = GF::from_signed(e);

        // b = <a, s> + Δ*m + e
        let delta_m = GF(DELTA.wrapping_mul(m));
        let b = dot + delta_m + e_field;

        LweCiphertext { a, b }
    }

    /// Decrypt an LWE ciphertext to recover m ∈ Z_t
    pub fn decrypt(&self, ct: &LweCiphertext) -> u64 {
        assert_eq!(ct.a.len(), N_LWE);

        // Compute <a, s>
        let mut dot = GF::ZERO;
        for i in 0..N_LWE {
            if self.key[i] == 1 {
                dot = dot + ct.a[i];
            }
        }

        // phase = b - <a, s> = Δ*m + e
        let phase = ct.b - dot;

        // Recover m by rounding: m = round(phase / Δ) mod t
        decode_phase(phase.0)
    }
}

/// Decode a phase value (Δ*m + e) to the plaintext m
/// m = round(phase * 2t / Q) mod t
pub fn decode_phase(phase: u64) -> u64 {
    // m = round(phase * 2t / Q) mod t
    // Use 128-bit arithmetic to avoid overflow
    let numerator = (phase as u128) * (2 * T_PLAIN) as u128;
    let m_approx = ((numerator + Q as u128 / 2) / (Q as u128)) as u64;
    m_approx % T_PLAIN
}

/// LWE ciphertext with dimension N_POLY (used after sample extraction)
#[derive(Clone, Debug)]
pub struct LweCiphertextBig {
    pub a: Vec<GF>, // dimension N_POLY
    pub b: GF,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = LweSecretKey::generate(&mut rng);

        for m in 0..T_PLAIN {
            let ct = sk.encrypt(m, &mut rng);
            let decrypted = sk.decrypt(&ct);
            assert_eq!(decrypted, m, "Failed for m={}", m);
        }
    }

    #[test]
    fn test_encrypt_decrypt_multiple() {
        let mut rng = StdRng::seed_from_u64(123);
        let sk = LweSecretKey::generate(&mut rng);

        for _ in 0..100 {
            let m = rng.gen_range(0..T_PLAIN);
            let ct = sk.encrypt(m, &mut rng);
            let decrypted = sk.decrypt(&ct);
            assert_eq!(decrypted, m);
        }
    }
}
