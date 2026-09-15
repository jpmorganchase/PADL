pub mod aurora;
pub mod field;
pub mod fri;
pub mod hash;
pub mod lattice_enc;
pub mod logup;
pub mod merkle;
pub mod ntt;
pub mod poly;
pub mod prover;
pub mod rescue;
pub mod rescue_consts;
pub mod transcript;

use napi_derive::napi;
use rayon::prelude::*;

fn parse_field(value: &str) -> field::ArkField {
    field::from_u128(value.parse::<u128>().unwrap() % field::P)
}

fn field_string(value: field::ArkField) -> String {
    field::to_u128(value).to_string()
}

#[napi]
pub fn ping() -> String {
    "pong from Rust NAPI + ruint".to_string()
}

/// Lattice commitment round-trip check: extract(commit(m)) == m for a random
/// full-range message. Returns true on success.
#[napi]
pub fn lattice_enc_roundtrip_test(d: u32, k: u32, sqrt_q: String, seed: f64) -> bool {
    let sq = parse_field(&sqrt_q);
    lattice_enc::roundtrip_ok(d as usize, k as usize, sq, seed as u64)
}

/// Generate the global public commitment matrix A (M×K×d, NTT domain, row-major
/// [m][k][i]) derived deterministically from `seed`. Rows 0..κ_sis are the SIS
/// block; the last two rows are the structured B, B' rows.
#[napi]
pub fn lattice_keygen(d: u32, k: u32, seed: f64) -> Vec<String> {
    let keys = lattice_enc::commit_gen(d as usize, k as usize, seed as u64);
    let mut out = Vec::with_capacity(
        (lattice_enc::KAPPA_SIS + lattice_enc::NUM_MSG_ROWS) * k as usize * d as usize,
    );
    for row in &keys.a_mat {
        for col in row {
            for v in col {
                out.push(field_string(*v));
            }
        }
    }
    out
}

/// Commit to an NTT-domain message vector under the global key `seed`, using
/// fresh ternary randomness from `r_seed`. Returns c flattened row-major (M×d).
#[napi]
pub fn lattice_commit_ntt(
    d: u32,
    k: u32,
    sqrt_q: String,
    seed: f64,
    vals_ntt: Vec<String>,
    r_seed: f64,
) -> Vec<String> {
    let dd = d as usize;
    let kk = k as usize;
    let sq = parse_field(&sqrt_q);
    let keys = lattice_enc::commit_gen(dd, kk, seed as u64);
    let vals: Vec<field::ArkField> = vals_ntt.iter().map(|s| parse_field(s)).collect();
    let r = lattice_enc::sample_r(dd, kk, r_seed as u64);
    let c = lattice_enc::commit_ntt(&keys, &vals, &r, sq);
    let mut out = Vec::with_capacity(c.len() * dd);
    for row in &c {
        for v in row {
            out.push(field_string(*v));
        }
    }
    out
}

/// Decrypt an NTT-domain commitment (flattened row-major M×d) under key `seed`.
/// Returns the recovered NTT-domain message vector (length d).
#[napi]
pub fn lattice_extract_ntt(
    d: u32,
    k: u32,
    sqrt_q: String,
    seed: f64,
    c_flat: Vec<String>,
) -> Vec<String> {
    let dd = d as usize;
    let sq = parse_field(&sqrt_q);
    let keys = lattice_enc::commit_gen(dd, k as usize, seed as u64);
    let m_rows = lattice_enc::KAPPA_SIS + lattice_enc::NUM_MSG_ROWS;
    let c: Vec<Vec<field::ArkField>> = (0..m_rows)
        .map(|row| {
            (0..dd)
                .map(|i| parse_field(&c_flat[row * dd + i]))
                .collect()
        })
        .collect();
    lattice_enc::extract_ntt(&keys, &c, sq)
        .iter()
        .map(|&v| field_string(v))
        .collect()
}

/// Shared SIS block A_sis (κ_sis×K×d, NTT domain, row-major) from a global seed.
#[napi]
pub fn lattice_keygen_sis(d: u32, k: u32, seed_sis: f64) -> Vec<String> {
    let a_sis = lattice_enc::gen_a_sis(d as usize, k as usize, seed_sis as u64);
    let mut out = Vec::with_capacity(lattice_enc::KAPPA_SIS * k as usize * d as usize);
    for row in &a_sis {
        for col in row {
            for v in col {
                out.push(field_string(*v));
            }
        }
    }
    out
}

/// Full per-recipient matrix A_R = [A_sis ; B_R ; B'_R] (M×K×d, row-major).
/// A_sis from `seed_sis` (shared), B rows from `seed_r` (recipient).
#[napi]
pub fn lattice_keygen_recipient(d: u32, k: u32, seed_sis: f64, seed_r: f64) -> Vec<String> {
    let dd = d as usize;
    let kk = k as usize;
    let a_sis = lattice_enc::gen_a_sis(dd, kk, seed_sis as u64);
    let keys = lattice_enc::commit_gen_with_sis(&a_sis, dd, kk, seed_r as u64);
    let mut out =
        Vec::with_capacity((lattice_enc::KAPPA_SIS + lattice_enc::NUM_MSG_ROWS) * kk * dd);
    for row in &keys.a_mat {
        for col in row {
            for v in col {
                out.push(field_string(*v));
            }
        }
    }
    out
}

/// Commit under a recipient key (A_sis from `seed_sis`, B from `seed_r`).
#[napi]
pub fn lattice_commit_ntt_r(
    d: u32,
    k: u32,
    sqrt_q: String,
    seed_sis: f64,
    seed_r: f64,
    vals_ntt: Vec<String>,
    r_seed: f64,
) -> Vec<String> {
    let dd = d as usize;
    let kk = k as usize;
    let sq = parse_field(&sqrt_q);
    let a_sis = lattice_enc::gen_a_sis(dd, kk, seed_sis as u64);
    let keys = lattice_enc::commit_gen_with_sis(&a_sis, dd, kk, seed_r as u64);
    let vals: Vec<field::ArkField> = vals_ntt.iter().map(|s| parse_field(s)).collect();
    let r = lattice_enc::sample_r(dd, kk, r_seed as u64);
    let c = lattice_enc::commit_ntt(&keys, &vals, &r, sq);
    let mut out = Vec::with_capacity(c.len() * dd);
    for row in &c {
        for v in row {
            out.push(field_string(*v));
        }
    }
    out
}

/// Decrypt under a recipient key (A_sis from `seed_sis`, secret from `seed_r`).
#[napi]
pub fn lattice_extract_ntt_r(
    d: u32,
    k: u32,
    sqrt_q: String,
    seed_sis: f64,
    seed_r: f64,
    c_flat: Vec<String>,
) -> Vec<String> {
    let dd = d as usize;
    let kk = k as usize;
    let sq = parse_field(&sqrt_q);
    let a_sis = lattice_enc::gen_a_sis(dd, kk, seed_sis as u64);
    let keys = lattice_enc::commit_gen_with_sis(&a_sis, dd, kk, seed_r as u64);
    let m_rows = lattice_enc::KAPPA_SIS + lattice_enc::NUM_MSG_ROWS;
    let c: Vec<Vec<field::ArkField>> = (0..m_rows)
        .map(|row| {
            (0..dd)
                .map(|i| parse_field(&c_flat[row * dd + i]))
                .collect()
        })
        .collect();
    lattice_enc::extract_ntt(&keys, &c, sq)
        .iter()
        .map(|&v| field_string(v))
        .collect()
}

#[napi]
pub fn field_mul_test(a: String, b: String) -> String {
    field_string(field::fmul(parse_field(&a), parse_field(&b)))
}

// Cross-validation: transcript init state as hex
#[napi]
pub fn transcript_init_hex() -> String {
    let tr = transcript::FiatShamirTranscript::new();
    hash::bytes_to_hex(&tr.state)
}

// Cross-validation: keccak of leaf_hash_from_values([1,2,3])
#[napi]
pub fn leaf_hash_test() -> String {
    let h = hash::leaf_hash_from_values(&[
        field::from_u128(1),
        field::from_u128(2),
        field::from_u128(3),
    ]);
    hash::bytes_to_hex(&h)
}

// Cross-validation: rescue sponge hash
#[napi]
pub fn rescue_hash_test(coeffs_str: Vec<String>) -> Vec<String> {
    let coeffs: Vec<field::ArkField> = coeffs_str.iter().map(|s| parse_field(s)).collect();
    let h = rescue::rescue_sponge_hash(&coeffs);
    vec![field_string(h[0]), field_string(h[1])]
}

// NTT round-trip test
#[napi]
pub fn ntt_roundtrip_test(size: u32) -> bool {
    let n = size as usize;
    let omega = field::root_of_unity(n as u128);
    let coeffs: Vec<field::ArkField> = (0..n)
        .map(|i| field::from_u128((i as u128 + 1) * 17))
        .collect();
    let evals = ntt::ntt(&coeffs, omega);
    let recovered = ntt::intt(&evals, omega);
    coeffs == recovered
}

/// Full prover entry point called from TypeScript.
/// Accepts all inputs as string arrays (BigInt doesn't cross NAPI natively),
/// builds A-oracle setup in Rust, runs the prover, returns JSON proof.
#[napi]
pub fn prove_range_hash(
    a_mat_flat: Vec<String>, // M*K*d values, row-major [m][k][i]
    m_count: u32,
    k_count: u32,
    d: u32,
    b_coeffs_flat: Vec<String>, // K*d values
    m_ntt: Vec<String>,
    m_orig_ntt: Vec<String>,
    m_sender_ntt: Vec<String>,
    sqrt_q: String,
    c_ntts_flat: Vec<String>, // M*d values
    token_m: Vec<String>,     // [2]
    token_s: Vec<String>,     // [2]
    token_o: Vec<String>,     // [2]
    grinding_bits: Option<u32>,
) -> String {
    let m = m_count as usize;
    let k = k_count as usize;
    let n = d as usize;
    let sq = parse_field(&sqrt_q);

    let parse_vec =
        |v: &[String]| -> Vec<field::ArkField> { v.iter().map(|s| parse_field(s)).collect() };

    // Rebuild a_mat[M][K][d]
    let a_flat = parse_vec(&a_mat_flat);
    let mut a_mat: Vec<Vec<Vec<field::ArkField>>> = Vec::with_capacity(m);
    for mm in 0..m {
        let mut row = Vec::with_capacity(k);
        for kk in 0..k {
            let base = (mm * k + kk) * n;
            row.push(a_flat[base..base + n].to_vec());
        }
        a_mat.push(row);
    }

    // Rebuild b_coeffs[K][d]
    let b_flat = parse_vec(&b_coeffs_flat);
    let mut b_coeffs: Vec<Vec<field::ArkField>> = Vec::with_capacity(k);
    for kk in 0..k {
        let base = kk * n;
        b_coeffs.push(b_flat[base..base + n].to_vec());
    }

    // Rebuild c_ntts[M][d]
    let c_flat = parse_vec(&c_ntts_flat);
    let mut c_ntts: Vec<Vec<field::ArkField>> = Vec::with_capacity(m);
    for mm in 0..m {
        let base = mm * n;
        c_ntts.push(c_flat[base..base + n].to_vec());
    }

    let m_ntt_v = parse_vec(&m_ntt);
    let m_orig_v = parse_vec(&m_orig_ntt);
    let m_sender_v = parse_vec(&m_sender_ntt);
    let tok_m = [parse_field(&token_m[0]), parse_field(&token_m[1])];
    let tok_s = [parse_field(&token_s[0]), parse_field(&token_s[1])];
    let tok_o = [parse_field(&token_o[0]), parse_field(&token_o[1])];

    // Build A-oracle setup (same as TS buildAOracleSetupRangeHash)
    let omega = field::root_of_unity(n as u128);
    let blowup = 16usize;
    let cap_height = 6usize;

    let a_polys: Vec<Vec<Vec<field::ArkField>>> = a_mat
        .par_iter()
        .map(|row| {
            row.iter()
                .map(|a| {
                    ntt::intt(
                        &a.iter().map(|&v| field::fmod(v)).collect::<Vec<_>>(),
                        omega,
                    )
                })
                .collect()
        })
        .collect();

    let lde = ntt::build_lde_domain(n, blowup);

    let a_lde: Vec<Vec<Vec<field::ArkField>>> = a_polys
        .par_iter()
        .map(|row| row.iter().map(|p| ntt::eval_on_coset(p, &lde)).collect())
        .collect();

    // Table column t
    let t_ntt_v = logup::build_table_values(n);
    let t_poly = ntt::intt(&t_ntt_v, omega);
    let t_lde = ntt::eval_on_coset(&t_poly, &lde);

    // Merkle tree for A-oracle (unsalted, M*K+1 cols, parallel leaf hashing)
    let a_leaves: Vec<[u8; 32]> = (0..lde.lde_size)
        .into_par_iter()
        .map(|i| {
            let mut vals = Vec::with_capacity(m * k + 1);
            for mm in 0..m {
                for kk in 0..k {
                    vals.push(a_lde[mm][kk][i]);
                }
            }
            vals.push(t_lde[i]);
            hash::leaf_hash_from_values(&vals)
        })
        .collect();
    let cap_r0 = merkle::layer_cap_height(cap_height, lde.lde_size);
    let a_tree = merkle::BatchedMerkleTree::new(a_leaves, cap_r0);
    let a_cap = a_tree.cap();

    // a_oracle_hash = keccak256(concat(cap))
    let mut cap_concat = Vec::new();
    for hc in &a_cap {
        cap_concat.extend_from_slice(hc);
    }
    let a_oracle_hash_bytes = hash::keccak256(&cap_concat);
    let a_oracle_hash = hash::bytes_to_hex(&a_oracle_hash_bytes);

    let proof = prover::prove(
        &a_polys,
        &a_lde,
        &a_tree,
        &a_cap,
        &a_oracle_hash,
        &t_poly,
        &t_ntt_v,
        &t_lde,
        &lde,
        m,
        k,
        sq,
        &c_ntts,
        &b_coeffs,
        &m_ntt_v,
        &m_orig_v,
        &m_sender_v,
        &tok_m,
        &tok_s,
        &tok_o,
        grinding_bits.unwrap_or(23) as usize,
    );

    serde_json::to_string(&proof).unwrap()
}
