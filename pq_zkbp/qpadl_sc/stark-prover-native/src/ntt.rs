use crate::field::*;

pub fn ntt(coeffs: &[ArkField], omega: ArkField) -> Vec<ArkField> {
    let n = coeffs.len();
    if n == 1 {
        return vec![coeffs[0]];
    }
    debug_assert!(n.is_power_of_two());
    let half = n >> 1;
    let even: Vec<ArkField> = (0..half).map(|i| coeffs[2 * i]).collect();
    let odd: Vec<ArkField> = (0..half).map(|i| coeffs[2 * i + 1]).collect();
    let omega2 = fmul(omega, omega);
    let ee = ntt(&even, omega2);
    let oo = ntt(&odd, omega2);
    let mut out = vec![from_u128(0); n];
    let mut w = from_u128(1);
    for i in 0..half {
        let t = fmul(w, oo[i]);
        out[i] = fadd(ee[i], t);
        out[i + half] = fsub(ee[i], t);
        w = fmul(w, omega);
    }
    out
}

pub fn intt(vals: &[ArkField], omega: ArkField) -> Vec<ArkField> {
    let n = vals.len() as u128;
    let oi = finv(omega);
    let mut c = ntt(vals, oi);
    let ni = finv(from_u128(n));
    for x in &mut c {
        *x = fmul(*x, ni);
    }
    c
}

pub fn ntt_coset(coeffs: &[ArkField], omega: ArkField, g: ArkField) -> Vec<ArkField> {
    let mut shifted = coeffs.to_vec();
    let mut gp = from_u128(1);
    for v in shifted.iter_mut() {
        *v = fmul(*v, gp);
        gp = fmul(gp, g);
    }
    ntt(&shifted, omega)
}

pub fn poly_eval(coeffs: &[ArkField], x: ArkField) -> ArkField {
    let mut r = from_u128(0);
    for i in (0..coeffs.len()).rev() {
        r = fadd(fmul(r, x), coeffs[i]);
    }
    r
}

pub struct LdeCoset {
    pub lde_omega: ArkField,
    pub coset_gen: ArkField,
    pub lde_size: usize,
    pub domain: Vec<ArkField>,
}

pub fn build_lde_domain(n: usize, blowup: usize) -> LdeCoset {
    let lde_size = blowup * n;
    let lde_omega = root_of_unity(lde_size as u128);
    let coset_gen = fpow(from_u128(G_PRIM), (P - 1) / (2 * lde_size as u128));
    let mut domain = Vec::with_capacity(lde_size);
    let mut pow = from_u128(1);
    for _ in 0..lde_size {
        domain.push(fmul(coset_gen, pow));
        pow = fmul(pow, lde_omega);
    }
    LdeCoset {
        lde_omega,
        coset_gen,
        lde_size,
        domain,
    }
}

pub fn eval_on_coset(coeffs: &[ArkField], lde: &LdeCoset) -> Vec<ArkField> {
    let mut padded = coeffs.to_vec();
    padded.resize(lde.lde_size, from_u128(0));
    ntt_coset(&padded, lde.lde_omega, lde.coset_gen)
}

pub fn intt_coset(values: &[ArkField], lde: &LdeCoset) -> Vec<ArkField> {
    let mut shifted = intt(values, lde.lde_omega);
    let g_inv = finv(lde.coset_gen);
    let mut gp = from_u128(1);
    for v in shifted.iter_mut() {
        *v = fmul(*v, gp);
        gp = fmul(gp, g_inv);
    }
    shifted
}

pub fn negacyclic_ntt(coeffs: &[ArkField], psi: ArkField) -> Vec<ArkField> {
    let n = coeffs.len();
    let mut twisted = Vec::with_capacity(n);
    let mut p = from_u128(1);
    for i in 0..n {
        twisted.push(fmul(fmod(coeffs[i]), p));
        p = fmul(p, psi);
    }
    let omega = fmul(psi, psi);
    ntt(&twisted, omega)
}

/// Inverse of `negacyclic_ntt`: INTT with ω=ψ², then untwist by ψ^{-i}.
pub fn negacyclic_intt(vals: &[ArkField], psi: ArkField) -> Vec<ArkField> {
    let n = vals.len();
    let omega = fmul(psi, psi);
    let twisted = intt(vals, omega);
    let psi_inv = finv(psi);
    let mut out = Vec::with_capacity(n);
    let mut p = from_u128(1);
    for i in 0..n {
        out.push(fmul(twisted[i], p));
        p = fmul(p, psi_inv);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntt_roundtrip() {
        let n = 256;
        let omega = root_of_unity(n as u128);
        let coeffs: Vec<ArkField> = (0..n).map(|i| from_u128((i as u128 + 1) * 17)).collect();
        let evals = ntt(&coeffs, omega);
        let recovered = intt(&evals, omega);
        assert_eq!(coeffs, recovered);
    }

    #[test]
    fn coset_roundtrip() {
        let n = 64;
        let coeffs: Vec<ArkField> = (0..n).map(|i| from_u128(i as u128 * 7 + 3)).collect();
        let lde = build_lde_domain(n, 4);
        let evals = eval_on_coset(&coeffs, &lde);
        let recovered = intt_coset(&evals, &lde);
        for i in 0..n {
            assert_eq!(recovered[i], coeffs[i], "mismatch at {}", i);
        }
    }
}
