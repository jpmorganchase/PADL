use crate::field::*;
use std::sync::OnceLock;

pub const NUM_BYTES: usize = 8;
pub const TABLE_SIZE: usize = 256;

pub const POW256: [u128; 8] = [
    1,
    256,
    65536,
    16777216,
    4294967296,
    1099511627776,
    281474976710656,
    72057594037927936,
];

pub fn pow256_fields() -> &'static [ArkField; 8] {
    static VALUES: OnceLock<[ArkField; 8]> = OnceLock::new();
    VALUES.get_or_init(|| POW256.map(from_u128))
}

pub fn decompose_bytes64(value: ArkField) -> [ArkField; 8] {
    let v = to_u128(value);
    assert!(v < (1u128 << 64), "value >= 2^64");
    let mut bytes = [from_u128(0); 8];
    let mut x = v;
    for j in 0..8 {
        bytes[j] = from_u128(x & 0xFF);
        x >>= 8;
    }
    bytes
}

/// Little-endian 2-byte split of a value in [0, 2^16). Used for the r-range check.
pub fn decompose_bytes16(value: ArkField) -> [ArkField; 2] {
    let v = to_u128(value);
    assert!(v < (1u128 << 16), "value >= 2^16");
    [from_u128(v & 0xFF), from_u128((v >> 8) & 0xFF)]
}

pub fn build_table_values(n: usize) -> Vec<ArkField> {
    assert!(n >= TABLE_SIZE);
    let mut t = vec![from_u128(0); n];
    for i in 0..TABLE_SIZE {
        t[i] = from_u128(i as u128);
    }
    t
}

pub fn compute_multiplicity(
    n: usize,
    dm_bytes: &[Vec<ArkField>; 8],
    ds_bytes: &[Vec<ArkField>; 8],
    extra: &[Vec<ArkField>],
) -> Vec<ArkField> {
    let mut mu = vec![from_u128(0); n];
    for j in 0..NUM_BYTES {
        for i in 0..n {
            let dm = to_u128(dm_bytes[j][i]) as usize;
            let ds = to_u128(ds_bytes[j][i]) as usize;
            mu[dm] = fadd(mu[dm], from_u128(1));
            mu[ds] = fadd(mu[ds], from_u128(1));
        }
    }
    for col in extra {
        for i in 0..n {
            let index = to_u128(col[i]) as usize;
            mu[index] = fadd(mu[index], from_u128(1));
        }
    }
    mu
}

pub fn compute_helper_inverse(beta: ArkField, values: &[ArkField]) -> Vec<ArkField> {
    values
        .iter()
        .map(|&v| {
            let denom = fsub(beta, v);
            assert!(denom != from_u128(0), "beta == value");
            finv(denom)
        })
        .collect()
}

pub fn compute_z_lup(
    n: usize,
    pm_cols: &[Vec<ArkField>; 8],
    ps_cols: &[Vec<ArkField>; 8],
    pr_cols: &[Vec<ArkField>],
    mu_col: &[ArkField],
    q_col: &[ArkField],
) -> Vec<ArkField> {
    let mut z_lup = vec![from_u128(0); n];
    for i in 0..n - 1 {
        let mut contrib = from_u128(0);
        for j in 0..NUM_BYTES {
            contrib = fadd(contrib, pm_cols[j][i]);
            contrib = fadd(contrib, ps_cols[j][i]);
        }
        for col in pr_cols {
            contrib = fadd(contrib, col[i]);
        }
        contrib = fsub(contrib, fmul(mu_col[i], q_col[i]));
        z_lup[i + 1] = fadd(z_lup[i], contrib);
    }
    // Check closing
    let mut last = from_u128(0);
    for j in 0..NUM_BYTES {
        last = fadd(last, pm_cols[j][n - 1]);
        last = fadd(last, ps_cols[j][n - 1]);
    }
    for col in pr_cols {
        last = fadd(last, col[n - 1]);
    }
    last = fsub(last, fmul(mu_col[n - 1], q_col[n - 1]));
    let closing = fadd(z_lup[n - 1], last);
    assert_eq!(closing, from_u128(0), "LogUp accumulator does not close");
    z_lup
}
