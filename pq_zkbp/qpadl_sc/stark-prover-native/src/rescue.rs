use crate::field::*;
use crate::ntt::intt;
use crate::rescue_consts;
use std::sync::OnceLock;

pub const RESCUE_ALPHA: u128 = 3;
pub const RESCUE_ROUNDS: usize = 8;
pub const RESCUE_WIDTH: usize = 12;
pub const RESCUE_CAPACITY: usize = 4;
pub const RESCUE_RATE: usize = 8;
pub const HASH_OUTPUT_LANES: usize = 2;
pub const NUM_HASHES: usize = 3;

pub fn rescue_m() -> &'static [[ArkField; 12]; 12] {
    static VALUES: OnceLock<[[ArkField; 12]; 12]> = OnceLock::new();
    VALUES.get_or_init(|| rescue_consts::RESCUE_M.map(|row| row.map(from_u128)))
}

pub fn rescue_minv() -> &'static [[ArkField; 12]; 12] {
    static VALUES: OnceLock<[[ArkField; 12]; 12]> = OnceLock::new();
    VALUES.get_or_init(|| rescue_consts::RESCUE_MINV.map(|row| row.map(from_u128)))
}

fn rescue_arc1() -> &'static [[ArkField; 12]; RESCUE_ROUNDS] {
    static VALUES: OnceLock<[[ArkField; 12]; RESCUE_ROUNDS]> = OnceLock::new();
    VALUES.get_or_init(|| rescue_consts::RESCUE_ARC1.map(|row| row.map(from_u128)))
}

fn rescue_arc2() -> &'static [[ArkField; 12]; RESCUE_ROUNDS] {
    static VALUES: OnceLock<[[ArkField; 12]; RESCUE_ROUNDS]> = OnceLock::new();
    VALUES.get_or_init(|| rescue_consts::RESCUE_ARC2.map(|row| row.map(from_u128)))
}

fn mds_multiply(v: &[ArkField; 12]) -> [ArkField; 12] {
    let mut out = [from_u128(0); 12];
    for i in 0..12 {
        let mut acc = from_u128(0);
        for j in 0..12 {
            acc = fadd(acc, fmul(rescue_m()[i][j], v[j]));
        }
        out[i] = acc;
    }
    out
}

fn sbox_forward(v: &[ArkField; 12]) -> [ArkField; 12] {
    let mut out = [from_u128(0); 12];
    for i in 0..12 {
        out[i] = fmul(fmul(v[i], v[i]), v[i]); // x^3
    }
    out
}

fn sbox_inverse(v: &[ArkField; 12]) -> [ArkField; 12] {
    let mut out = [from_u128(0); 12];
    for i in 0..12 {
        out[i] = fpow(v[i], rescue_consts::RESCUE_ALPHA_INV);
    }
    out
}

pub fn rescue_round(sigma_hat: &[ArkField; 12], round_idx: usize) -> [ArkField; 12] {
    let cubed = sbox_forward(sigma_hat);
    let after_mds1 = mds_multiply(&cubed);
    let mut mid = [from_u128(0); 12];
    for i in 0..12 {
        mid[i] = fadd(after_mds1[i], rescue_arc1()[round_idx][i]);
    }
    let inv_cubed = sbox_inverse(&mid);
    let after_mds2 = mds_multiply(&inv_cubed);
    let mut s_next = [from_u128(0); 12];
    for i in 0..12 {
        s_next[i] = fadd(after_mds2[i], rescue_arc2()[round_idx][i]);
    }
    s_next
}

pub fn rescue_sponge_hash(coeffs: &[ArkField]) -> [ArkField; 2] {
    let n = coeffs.len();
    assert!(n % RESCUE_RATE == 0);
    let num_blocks = n / RESCUE_RATE;
    let mut state = [from_u128(0); 12];

    for blk in 0..num_blocks {
        for j in 0..RESCUE_RATE {
            state[j] = fadd(state[j], coeffs[blk * RESCUE_RATE + j]);
        }
        let rounds = if blk < num_blocks - 1 {
            RESCUE_ROUNDS
        } else {
            RESCUE_ROUNDS - 1
        };
        for r in 0..rounds {
            state = rescue_round(&state, r);
        }
    }
    [state[0], state[1]]
}

pub struct HashTrace {
    pub state_trace: Vec<[ArkField; 12]>, // N rows
    pub sigma_trace: Vec<[ArkField; 8]>,  // N rows
}

pub fn build_hash_trace(coeffs: &[ArkField]) -> HashTrace {
    let n = coeffs.len();
    assert!(n % RESCUE_RATE == 0);
    let num_blocks = n / RESCUE_RATE;

    let mut state_trace: Vec<[ArkField; 12]> = vec![[from_u128(0); 12]; n];
    let mut sigma_trace: Vec<[ArkField; 8]> = vec![[from_u128(0); 8]; n];

    let mut state = [from_u128(0); 12];

    for blk in 0..num_blocks {
        let base_row = blk * RESCUE_ROUNDS;
        state_trace[base_row] = state;

        let mut sigma_hat = state;
        for j in 0..RESCUE_RATE {
            sigma_hat[j] = fadd(state[j], coeffs[blk * RESCUE_RATE + j]);
        }
        let mut sig = [from_u128(0); 8];
        for j in 0..RESCUE_RATE {
            sig[j] = sigma_hat[j];
        }
        sigma_trace[base_row] = sig;

        let mut cur = sigma_hat;
        let rounds_in_block = if blk < num_blocks - 1 {
            RESCUE_ROUNDS
        } else {
            RESCUE_ROUNDS - 1
        };
        for r in 0..rounds_in_block {
            let next = rescue_round(&cur, r % RESCUE_ROUNDS);
            let next_row = base_row + r + 1;
            if next_row < n {
                state_trace[next_row] = next;
                let mut sig = [from_u128(0); 8];
                for j in 0..RESCUE_RATE {
                    sig[j] = next[j];
                }
                sigma_trace[next_row] = sig;
            }
            cur = next;
        }
        state = cur;
    }

    HashTrace {
        state_trace,
        sigma_trace,
    }
}

pub fn build_absorb_selector_values(n: usize) -> Vec<ArkField> {
    let mut vals = vec![from_u128(0); n];
    for t in (0..n).step_by(RESCUE_ROUNDS) {
        vals[t] = from_u128(1);
    }
    vals
}

pub fn build_periodic_arc_values(n: usize, arc_table: &[[u128; 12]], comp: usize) -> Vec<ArkField> {
    (0..n)
        .map(|t| from_u128(arc_table[t % RESCUE_ROUNDS][comp]))
        .collect()
}

pub fn eval_absorb_selector_at_z(z: ArkField, n: usize) -> ArkField {
    let n_big = n as u128;
    let z_n = fpow(z, n_big);
    let z_n8 = fpow(z, n_big / 8);
    let numer = fsub(z_n, from_u128(1));
    let denom = fmul(from_u128(8), fsub(z_n8, from_u128(1)));
    fmul(numer, finv(denom))
}

pub fn eval_periodic_at_z(
    values8: &[ArkField; 8],
    z: ArkField,
    n: usize,
    omega: ArkField,
) -> ArkField {
    let n_big = n as u128;
    let z_n = fpow(z, n_big);
    let z_nm1 = fsub(z_n, from_u128(1));
    let inv8 = finv(from_u128(8));
    let z_n8 = fpow(z, n_big / 8);
    let omega_n8 = fpow(omega, n_big / 8);

    let mut sum = from_u128(0);
    let omega_n8_inv = finv(omega_n8);
    let mut omega_n8_neg_r = from_u128(1);
    for r in 0..8 {
        let denom = fsub(fmul(z_n8, omega_n8_neg_r), from_u128(1));
        sum = fadd(sum, fmul(values8[r], finv(denom)));
        omega_n8_neg_r = fmul(omega_n8_neg_r, omega_n8_inv);
    }
    fmul(fmul(z_nm1, inv8), sum)
}

// Interpolate hash state/sigma columns
pub fn interpolate_hash_trace(
    ht: &HashTrace,
    n: usize,
    omega: ArkField,
) -> (Vec<Vec<ArkField>>, Vec<Vec<ArkField>>) {
    let mut state_polys = Vec::with_capacity(12);
    for i in 0..12 {
        let vals: Vec<ArkField> = (0..n).map(|t| ht.state_trace[t][i]).collect();
        state_polys.push(intt(&vals, omega));
    }
    let mut sigma_polys = Vec::with_capacity(8);
    for j in 0..8 {
        let vals: Vec<ArkField> = (0..n).map(|t| ht.sigma_trace[t][j]).collect();
        sigma_polys.push(intt(&vals, omega));
    }
    (state_polys, sigma_polys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sponge_hash_deterministic() {
        let coeffs = vec![from_u128(1); 64];
        let h1 = rescue_sponge_hash(&coeffs);
        let h2 = rescue_sponge_hash(&coeffs);
        assert_eq!(h1, h2);
        assert_ne!(h1[0], from_u128(0));
    }

    #[test]
    fn test_hash_trace_matches_sponge() {
        let n = 64;
        let coeffs: Vec<ArkField> = (0..n)
            .map(|i| from_u128(((i * 17 + 3) % 100) as u128))
            .collect();
        let expected = rescue_sponge_hash(&coeffs);
        let ht = build_hash_trace(&coeffs);
        assert_eq!(ht.state_trace[n - 1][0], expected[0]);
        assert_eq!(ht.state_trace[n - 1][1], expected[1]);
    }
}
