use crate::field::*;

pub fn poly_mul(a: &[ArkField], b: &[ArkField]) -> Vec<ArkField> {
    if a.is_empty() || b.is_empty() {
        return vec![];
    }
    let mut out = vec![from_u128(0); a.len() + b.len() - 1];
    for (i, &ai) in a.iter().enumerate() {
        if ai == from_u128(0) {
            continue;
        }
        for (j, &bj) in b.iter().enumerate() {
            out[i + j] = fadd(out[i + j], fmul(ai, bj));
        }
    }
    out
}

pub fn poly_sub(a: &[ArkField], b: &[ArkField]) -> Vec<ArkField> {
    let n = a.len().max(b.len());
    let mut out = vec![from_u128(0); n];
    for (j, &v) in a.iter().enumerate() {
        out[j] = fadd(out[j], v);
    }
    for (j, &v) in b.iter().enumerate() {
        out[j] = fsub(out[j], v);
    }
    out
}

pub fn poly_add_into(out: &mut Vec<ArkField>, a: &[ArkField]) {
    if a.len() > out.len() {
        out.resize(a.len(), from_u128(0));
    }
    for (j, &v) in a.iter().enumerate() {
        out[j] = fadd(out[j], v);
    }
}

pub fn poly_add_scaled(a: &[ArkField], b: &[ArkField], s: ArkField) -> Vec<ArkField> {
    let n = a.len().max(b.len());
    let mut out = vec![from_u128(0); n];
    for (j, &v) in a.iter().enumerate() {
        out[j] = fadd(out[j], v);
    }
    for (j, &v) in b.iter().enumerate() {
        out[j] = fadd(out[j], fmul(s, v));
    }
    out
}

pub fn blind_with_n_minus_1(poly: &[ArkField], blind: &[ArkField], n: usize) -> Vec<ArkField> {
    let b = blind.len();
    let mut out = vec![from_u128(0); n + b];
    for (j, &v) in poly.iter().enumerate() {
        out[j] = fmod(v);
    }
    for j in 0..b {
        out[j] = fsub(out[j], blind[j]);
        out[n + j] = fadd(out[n + j], blind[j]);
    }
    out
}

pub fn shift_up(poly: &[ArkField], s: usize) -> Vec<ArkField> {
    let mut out = vec![from_u128(0); poly.len() + s];
    for (j, &v) in poly.iter().enumerate() {
        out[j + s] = fmod(v);
    }
    out
}

pub fn div_by_xn_minus_1(poly: &[ArkField], n: usize) -> (Vec<ArkField>, Vec<ArkField>) {
    let mut cur: Vec<ArkField> = poly.iter().map(|&v| fmod(v)).collect();
    let quot_len = if cur.len() > n { cur.len() - n } else { 0 };
    let mut quot = vec![from_u128(0); quot_len];
    for j in (n..cur.len()).rev() {
        let q = cur[j];
        quot[j - n] = q;
        cur[j] = from_u128(0);
        cur[j - n] = fadd(cur[j - n], q);
    }
    let rem = cur[..n.min(cur.len())].to_vec();
    (quot, rem)
}
