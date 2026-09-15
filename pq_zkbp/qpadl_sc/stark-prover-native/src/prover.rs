use crate::aurora::*;
use crate::field::*;
use crate::fri::*;
use crate::hash::*;
use crate::logup::*;
use crate::merkle::*;
use crate::ntt::*;
use crate::poly::*;
use crate::rescue::*;
use crate::rescue_consts;
use crate::transcript::*;
use rand::RngCore;
use rayon::prelude::*;

// STARK parameters
const BLOWUP: usize = 16;
const NUM_QUERIES: usize = 23;
const CAP_HEIGHT: usize = 6;
const FRI_ARITY: usize = 4;
const FINAL_POLY_BOUND: usize = 16;
const GRINDING_BATCH_SIZE: u64 = 1 << 20;

fn blinding_budget(_n: usize, num_queries: usize) -> usize {
    num_queries + 1
}
fn blinding_budget_source(num_queries: usize) -> usize {
    num_queries + 8
}
fn blinding_budget_state(num_queries: usize) -> usize {
    num_queries + 2
}
fn blinding_budget_sigma(num_queries: usize) -> usize {
    num_queries + 1
}
fn cp_blind_budget(num_queries: usize) -> usize {
    num_queries + 1
}
fn cp_chunk_width(n: usize) -> usize {
    n
}
fn d_max(n: usize, b_s: usize) -> usize {
    2 * n + 3 * b_s + 1
}
fn cp_num_chunks_hash(n: usize, b_s: usize) -> usize {
    (d_max(n, b_s) + n - 1) / n
}
fn num_alpha_slots(k: usize) -> usize {
    3 * k + 124
}

// Column offsets (mirror TS)
fn trace_off_bntt(_k: usize) -> usize {
    0
}
fn trace_off_ghat(k: usize) -> usize {
    k
}
fn trace_off_glo(k: usize) -> usize {
    2 * k
}
fn trace_off_ghi(k: usize) -> usize {
    3 * k
}
fn trace_off_m(k: usize) -> usize {
    4 * k
}
fn trace_off_m_orig(k: usize) -> usize {
    4 * k + 1
}
fn trace_off_m_sender(k: usize) -> usize {
    4 * k + 2
}
fn trace_off_dm(k: usize) -> usize {
    4 * k + 3
}
fn trace_off_ds(k: usize) -> usize {
    4 * k + 11
}
fn trace_off_mu(k: usize) -> usize {
    4 * k + 19
}
fn trace_off_raur(k: usize) -> usize {
    4 * k + 20
}
fn trace_off_hash_state(k: usize, hi: usize) -> usize {
    4 * k + 21 + hi * 20
}
fn trace_off_hash_sigma(k: usize, hi: usize) -> usize {
    4 * k + 21 + hi * 20 + 12
}
fn trace_col_count(k: usize) -> usize {
    4 * k + 81
}

// Range-check shift (η = 2^15): b ∈ [−2^15, 2^15) ⇒ b + 2^15 ∈ [0, 2^16) = 2 bytes.
const R_SHIFT: u128 = 1 << 15;
// Interaction columns: pm[8], ps[8], pr[2K], qcol, zlup.
fn inter_col_count(k: usize) -> usize {
    18 + 2 * k
}
fn inter_off_pr(_k: usize) -> usize {
    16
}
fn inter_off_qcol(k: usize) -> usize {
    16 + 2 * k
}
fn inter_off_zlup(k: usize) -> usize {
    17 + 2 * k
}

fn alpha_off_c1a(k: usize) -> usize {
    3 * k + 22
}
fn alpha_off_c1b(k: usize) -> usize {
    3 * k + 46
}
fn alpha_off_c2(k: usize) -> usize {
    3 * k + 82
}
fn alpha_off_c3(k: usize) -> usize {
    3 * k + 118
}

fn rand_field() -> ArkField {
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    let v = u128::from_le_bytes(buf);
    from_u128(v % P)
}

fn rand_poly(len: usize) -> Vec<ArkField> {
    (0..len).map(|_| rand_field()).collect()
}

/// Full proof structure — all fields serialized to JS via serde
#[derive(serde::Serialize)]
pub struct ProofData {
    pub a_oracle_hash: String,
    pub debug_rho0: String,
    pub debug_alpha: String,
    pub debug_beta_lup: String,
    pub debug_cvec_hash: String,
    pub debug_tr_state_pre_rho0: String,
    pub trace_length: usize,
    pub num_columns: usize,
    pub blowup: usize,
    pub cap_height: usize,
    pub blind_b: usize,
    pub blind_b_source: usize,
    pub blind_b_state: usize,
    pub blind_b_sigma: usize,
    pub cp_blind_h: usize,
    pub num_chunks: usize,
    pub cp_chunk_width: usize,
    pub beta_aur: String,
    pub omega: String,
    pub psi: String,
    pub lde_omega: String,
    pub coset_gen: String,

    pub token_m: Vec<String>,
    pub token_s: Vec<String>,
    pub token_o: Vec<String>,

    // Merkle caps + openings (hex strings)
    pub trace_cap: Vec<String>,
    pub trace_positions: Vec<usize>,
    pub trace_col_values: Vec<Vec<String>>,
    pub trace_salts: Vec<String>,
    pub trace_batch_proof: Vec<String>,

    pub inter_cap: Vec<String>,
    pub inter_col_values: Vec<Vec<String>>,
    pub inter_salts: Vec<String>,
    pub inter_batch_proof: Vec<String>,

    pub aux_cap: Vec<String>,
    pub aux_col_values: Vec<Vec<String>>,
    pub aux_salts: Vec<String>,
    pub aux_batch_proof: Vec<String>,

    pub cp_chunk_cap: Vec<String>,
    pub cp_chunk_col_values: Vec<Vec<String>>,
    pub cp_chunk_salts: Vec<String>,
    pub cp_chunk_batch_proof: Vec<String>,

    pub mask_cap: Vec<String>,
    pub mask_values: Vec<String>,
    pub mask_salts: Vec<String>,
    pub mask_batch_proof: Vec<String>,

    pub split_cap: Vec<String>,
    pub split_col_values: Vec<Vec<String>>,
    pub split_salts: Vec<String>,
    pub split_batch_proof: Vec<String>,

    pub a_cap: Vec<String>,
    pub a_col_values: Vec<Vec<String>>,
    pub a_batch_proof: Vec<String>,

    // OOD openings
    pub ood_bntt_z: Vec<String>,
    pub ood_ghat_z: Vec<String>,
    pub ood_glo_z: Vec<String>,
    pub ood_ghi_z: Vec<String>,
    pub ood_a_z: Vec<String>,
    pub ood_t_z: String,
    pub ood_m_z: String,
    pub ood_m_orig_z: String,
    pub ood_m_sender_z: String,
    pub ood_dm_z: Vec<String>,
    pub ood_ds_z: Vec<String>,
    pub ood_pm_z: Vec<String>,
    pub ood_ps_z: Vec<String>,
    pub ood_pr_z: Vec<String>,
    pub ood_qcol_z: String,
    pub ood_mu_z: String,
    pub ood_zlup_z: String,
    pub ood_zlup_omega_z: String,
    pub ood_raur_z: String,
    pub ood_r_z: String,
    pub ood_q_z: String,
    pub ood_q1_z: String,
    pub ood_cp_chunk_z: Vec<String>,

    pub ood_hash_state_z: Vec<Vec<String>>,
    pub ood_hash_state_omega_z: Vec<Vec<String>>,
    pub ood_hash_sigma_z: Vec<Vec<String>>,
    pub ood_source_shifts: Vec<Vec<String>>,

    // FRI
    pub fri_caps: Vec<Vec<String>>,
    pub fri_layer_positions: Vec<Vec<usize>>,
    pub fri_layer_values: Vec<Vec<String>>,
    pub fri_layer_salts: Vec<Vec<String>>,
    pub fri_layer_proofs: Vec<Vec<String>>,
    pub fri_final_poly: Vec<String>,
    pub grinding_nonce: String,
    pub query_indices: Vec<usize>,
}

fn to_s(v: ArkField) -> String {
    to_u128(v).to_string()
}
fn hash_hex(h: &[u8; 32]) -> String {
    bytes_to_hex(h)
}

fn grinding_hash(state: &[u8; 32], nonce: u64) -> [u8; 32] {
    let mut input = [0u8; 40];
    input[..32].copy_from_slice(state);
    input[32..].copy_from_slice(&nonce.to_be_bytes());
    keccak256(&input)
}

fn grind_transcript_state(state: &[u8; 32], grinding_bits: usize) -> (u64, [u8; 32]) {
    if grinding_bits == 0 {
        return (0, grinding_hash(state, 0));
    }

    let mut batch_start = 0u64;
    loop {
        let batch_end = batch_start.saturating_add(GRINDING_BATCH_SIZE);
        if let Some(result) = (batch_start..batch_end)
            .into_par_iter()
            .find_map_any(|nonce| {
                let candidate = grinding_hash(state, nonce);
                (leading_zero_bits_bytes(&candidate) >= grinding_bits)
                    .then_some((nonce, candidate))
            })
        {
            return result;
        }
        if batch_end == u64::MAX {
            let candidate = grinding_hash(state, u64::MAX);
            assert!(
                leading_zero_bits_bytes(&candidate) >= grinding_bits,
                "exhausted grinding nonce space"
            );
            return (u64::MAX, candidate);
        }
        batch_start = batch_end;
    }
}

#[cfg(test)]
mod grinding_tests {
    use super::*;

    #[test]
    fn parallel_grinding_returns_a_valid_nonce() {
        let state = [0x42; 32];
        let (nonce, candidate) = grind_transcript_state(&state, 12);

        assert_eq!(candidate, grinding_hash(&state, nonce));
        assert!(leading_zero_bits_bytes(&candidate) >= 12);
    }

    #[test]
    fn zero_bit_grinding_preserves_zero_nonce() {
        let state = [0x42; 32];
        let (nonce, candidate) = grind_transcript_state(&state, 0);

        assert_eq!(nonce, 0);
        assert_eq!(candidate, grinding_hash(&state, 0));
    }
}

pub fn prove(
    // A-oracle setup (precomputed)
    a_polys: &[Vec<Vec<ArkField>>], // M × K × N coefficient polys
    a_lde: &[Vec<Vec<ArkField>>],   // M × K × ldeSize LDE values
    a_tree: &BatchedMerkleTree,
    a_cap: &[[u8; 32]],
    a_oracle_hash: &str,
    t_poly: &[ArkField],
    t_ntt: &[ArkField],
    t_lde: &[ArkField],
    lde: &LdeCoset,
    // Public params
    m_count: usize, // M
    k_count: usize, // K
    sqrt_q: ArkField,
    c_ntts: &[Vec<ArkField>], // M × N
    // Witness
    b_coeffs: &[Vec<ArkField>], // K × N ternary
    m_ntt: &[ArkField],
    m_orig_ntt: &[ArkField],
    m_sender_ntt: &[ArkField],
    token_m: &[ArkField; 2],
    token_s: &[ArkField; 2],
    token_o: &[ArkField; 2],
    grinding_bits: usize,
) -> ProofData {
    assert!(grinding_bits <= 64, "grinding_bits must not exceed 64");
    let n = m_ntt.len();
    let n_big = n as u128;
    let omega = root_of_unity(n_big);
    let psi = root_of_unity(2 * n_big);
    let m = m_count;
    let k = k_count;
    let sqrt_qn = fmod(sqrt_q);

    let b = blinding_budget(n, NUM_QUERIES);
    let b_source = blinding_budget_source(NUM_QUERIES);
    let b_s = blinding_budget_state(NUM_QUERIES);
    let b_sigma = blinding_budget_sigma(NUM_QUERIES);
    let h = cp_blind_budget(NUM_QUERIES);
    let w = cp_chunk_width(n);
    let d_chunks = cp_num_chunks_hash(n, b_s);

    // ── 1. Bare coefficient polys ──
    let b_coeff_norm: Vec<Vec<ArkField>> = b_coeffs
        .iter()
        .map(|row| row.iter().map(|&v| fmod(v)).collect())
        .collect();
    // r-range: split (b + 2^15) ∈ [0,2^16) into low/high bytes per column
    let mut glo_cols: Vec<Vec<ArkField>> = vec![vec![from_u128(0); n]; k];
    let mut ghi_cols: Vec<Vec<ArkField>> = vec![vec![from_u128(0); n]; k];
    for kk in 0..k {
        for i in 0..n {
            let by = decompose_bytes16(fadd(b_coeff_norm[kk][i], from_u128(R_SHIFT)));
            glo_cols[kk][i] = by[0];
            ghi_cols[kk][i] = by[1];
        }
    }

    let r_byte_cols: Vec<Vec<ArkField>> = glo_cols.iter().chain(ghi_cols.iter()).cloned().collect();

    let f_polys_bare: Vec<Vec<ArkField>> = b_coeff_norm
        .iter()
        .map(|c| {
            let mut psij = from_u128(1);
            c.iter()
                .map(|&v| {
                    let r = fmul(v, psij);
                    psij = fmul(psij, psi);
                    r
                })
                .collect()
        })
        .collect();
    let g_polys_bare: Vec<Vec<ArkField>> = b_coeff_norm.iter().map(|c| intt(c, omega)).collect();
    let glo_polys_bare: Vec<Vec<ArkField>> = glo_cols.iter().map(|c| intt(c, omega)).collect();
    let ghi_polys_bare: Vec<Vec<ArkField>> = ghi_cols.iter().map(|c| intt(c, omega)).collect();

    // ── 2. m, m_orig, m_sender polys ──
    let m_vals: Vec<ArkField> = m_ntt.iter().map(|&v| fmod(v)).collect();
    let m_orig_vals: Vec<ArkField> = m_orig_ntt.iter().map(|&v| fmod(v)).collect();
    let m_sender_vals: Vec<ArkField> = m_sender_ntt.iter().map(|&v| fmod(v)).collect();
    let m_poly_bare = intt(&m_vals, omega);
    let m_orig_poly_bare = intt(&m_orig_vals, omega);
    let m_sender_poly_bare = intt(&m_sender_vals, omega);

    // ── 3. Byte decomposition ──
    let mut dm_byte_cols: [Vec<ArkField>; 8] = Default::default();
    let mut ds_byte_cols: [Vec<ArkField>; 8] = Default::default();
    for j in 0..8 {
        dm_byte_cols[j] = vec![from_u128(0); n];
        ds_byte_cols[j] = vec![from_u128(0); n];
    }
    for i in 0..n {
        let mb = decompose_bytes64(m_vals[i]);
        let sb = decompose_bytes64(m_sender_vals[i]);
        for j in 0..8 {
            dm_byte_cols[j][i] = mb[j];
            ds_byte_cols[j][i] = sb[j];
        }
    }
    let dm_polys_bare: Vec<Vec<ArkField>> = dm_byte_cols.iter().map(|c| intt(c, omega)).collect();
    let ds_polys_bare: Vec<Vec<ArkField>> = ds_byte_cols.iter().map(|c| intt(c, omega)).collect();
    let mu_vals = compute_multiplicity(n, &dm_byte_cols, &ds_byte_cols, &r_byte_cols);
    let mu_poly_bare = intt(&mu_vals, omega);

    // ── 5. Hash traces ──
    let source_vals = [m_vals.clone(), m_sender_vals.clone(), m_orig_vals.clone()];
    let mut hash_traces = Vec::new();
    for hi in 0..NUM_HASHES {
        hash_traces.push(build_hash_trace(&source_vals[hi]));
    }
    let tokens = [token_m, token_s, token_o];
    for hi in 0..NUM_HASHES {
        for lane in 0..HASH_OUTPUT_LANES {
            let actual = hash_traces[hi].state_trace[n - 1][lane];
            assert_eq!(
                actual,
                fmod(tokens[hi][lane]),
                "hash {} lane {} mismatch",
                hi,
                lane
            );
        }
    }

    let mut hash_state_polys_bare = Vec::new();
    let mut hash_sigma_polys_bare = Vec::new();
    for hi in 0..NUM_HASHES {
        let (sp, sigp) = interpolate_hash_trace(&hash_traces[hi], n, omega);
        hash_state_polys_bare.push(sp);
        hash_sigma_polys_bare.push(sigp);
    }

    // ── 6-7. Blinding + masking ──
    let r_aur_poly = rand_poly(n + b);

    let bntt_polys: Vec<Vec<ArkField>> = f_polys_bare
        .iter()
        .enumerate()
        .map(|(_, p)| blind_with_n_minus_1(p, &rand_poly(b), n))
        .collect();
    let ghat_polys: Vec<Vec<ArkField>> = g_polys_bare
        .iter()
        .map(|p| blind_with_n_minus_1(p, &rand_poly(b), n))
        .collect();
    let glo_polys: Vec<Vec<ArkField>> = glo_polys_bare
        .iter()
        .map(|p| blind_with_n_minus_1(p, &rand_poly(b), n))
        .collect();
    let ghi_polys: Vec<Vec<ArkField>> = ghi_polys_bare
        .iter()
        .map(|p| blind_with_n_minus_1(p, &rand_poly(b), n))
        .collect();
    let m_poly = blind_with_n_minus_1(&m_poly_bare, &rand_poly(b_source), n);
    let m_orig_poly = blind_with_n_minus_1(&m_orig_poly_bare, &rand_poly(b_source), n);
    let m_sender_poly = blind_with_n_minus_1(&m_sender_poly_bare, &rand_poly(b_source), n);
    let dm_polys: Vec<Vec<ArkField>> = dm_polys_bare
        .iter()
        .map(|p| blind_with_n_minus_1(p, &rand_poly(b), n))
        .collect();
    let ds_polys: Vec<Vec<ArkField>> = ds_polys_bare
        .iter()
        .map(|p| blind_with_n_minus_1(p, &rand_poly(b), n))
        .collect();
    let mu_poly = blind_with_n_minus_1(&mu_poly_bare, &rand_poly(b), n);

    let mut hash_state_polys = Vec::new();
    let mut hash_sigma_polys = Vec::new();
    for hi in 0..NUM_HASHES {
        let sp: Vec<Vec<ArkField>> = hash_state_polys_bare[hi]
            .iter()
            .map(|p| blind_with_n_minus_1(p, &rand_poly(b_s), n))
            .collect();
        hash_state_polys.push(sp);
        let sigp: Vec<Vec<ArkField>> = hash_sigma_polys_bare[hi]
            .iter()
            .map(|p| blind_with_n_minus_1(p, &rand_poly(b_sigma), n))
            .collect();
        hash_sigma_polys.push(sigp);
    }

    // ── 8. LDE all round 0 columns (parallel) ──
    let bntt_lde: Vec<Vec<ArkField>> = bntt_polys
        .par_iter()
        .map(|p| eval_on_coset(p, lde))
        .collect();
    let ghat_lde: Vec<Vec<ArkField>> = ghat_polys
        .par_iter()
        .map(|p| eval_on_coset(p, lde))
        .collect();
    let glo_lde: Vec<Vec<ArkField>> = glo_polys
        .par_iter()
        .map(|p| eval_on_coset(p, lde))
        .collect();
    let ghi_lde: Vec<Vec<ArkField>> = ghi_polys
        .par_iter()
        .map(|p| eval_on_coset(p, lde))
        .collect();
    let (m_lde, (m_orig_lde, m_sender_lde)) = rayon::join(
        || eval_on_coset(&m_poly, lde),
        || {
            rayon::join(
                || eval_on_coset(&m_orig_poly, lde),
                || eval_on_coset(&m_sender_poly, lde),
            )
        },
    );
    let dm_lde: Vec<Vec<ArkField>> = dm_polys.par_iter().map(|p| eval_on_coset(p, lde)).collect();
    let ds_lde: Vec<Vec<ArkField>> = ds_polys.par_iter().map(|p| eval_on_coset(p, lde)).collect();
    let (mu_lde, r_aur_lde) = rayon::join(
        || eval_on_coset(&mu_poly, lde),
        || eval_on_coset(&r_aur_poly, lde),
    );

    // Hash column LDEs in parallel
    let all_hash_polys: Vec<(&Vec<ArkField>, usize, usize, bool)> = {
        let mut v = Vec::new();
        for hi in 0..NUM_HASHES {
            for ci in 0..12 {
                v.push((&hash_state_polys[hi][ci], hi, ci, true));
            }
            for cj in 0..8 {
                v.push((&hash_sigma_polys[hi][cj], hi, cj, false));
            }
        }
        v
    };
    let all_hash_ldes: Vec<(Vec<ArkField>, usize, usize, bool)> = all_hash_polys
        .par_iter()
        .map(|&(p, hi, idx, is_state)| (eval_on_coset(p, lde), hi, idx, is_state))
        .collect();
    let mut hash_state_lde: Vec<Vec<Vec<ArkField>>> = vec![vec![vec![]; 12]; NUM_HASHES];
    let mut hash_sigma_lde: Vec<Vec<Vec<ArkField>>> = vec![vec![vec![]; 8]; NUM_HASHES];
    for (lde_vals, hi, idx, is_state) in all_hash_ldes {
        if is_state {
            hash_state_lde[hi][idx] = lde_vals;
        } else {
            hash_sigma_lde[hi][idx] = lde_vals;
        }
    }

    // ── 9. Round 0 Merkle commit (parallel leaf hashing) ──
    let trace_cols = trace_col_count(k);
    let trace_salts_all = random_salts(lde.lde_size);
    let trace_leaf_hashes: Vec<[u8; 32]> = (0..lde.lde_size)
        .into_par_iter()
        .map(|i| {
            let mut row = vec![from_u128(0); trace_cols];
            for kk in 0..k {
                row[trace_off_bntt(k) + kk] = bntt_lde[kk][i];
                row[trace_off_ghat(k) + kk] = ghat_lde[kk][i];
                row[trace_off_glo(k) + kk] = glo_lde[kk][i];
                row[trace_off_ghi(k) + kk] = ghi_lde[kk][i];
            }
            row[trace_off_m(k)] = m_lde[i];
            row[trace_off_m_orig(k)] = m_orig_lde[i];
            row[trace_off_m_sender(k)] = m_sender_lde[i];
            for j in 0..NUM_BYTES {
                row[trace_off_dm(k) + j] = dm_lde[j][i];
                row[trace_off_ds(k) + j] = ds_lde[j][i];
            }
            row[trace_off_mu(k)] = mu_lde[i];
            row[trace_off_raur(k)] = r_aur_lde[i];
            for hi in 0..NUM_HASHES {
                for ci in 0..12 {
                    row[trace_off_hash_state(k, hi) + ci] = hash_state_lde[hi][ci][i];
                }
                for cj in 0..8 {
                    row[trace_off_hash_sigma(k, hi) + cj] = hash_sigma_lde[hi][cj][i];
                }
            }
            leaf_hash_from_values_salt(&row, &trace_salts_all[i])
        })
        .collect();
    let cap_r0 = layer_cap_height(CAP_HEIGHT, lde.lde_size);
    let trace_tree = BatchedMerkleTree::new(trace_leaf_hashes, cap_r0);
    let trace_cap = trace_tree.cap();

    // ── 10. c polys ──
    let c_polys: Vec<Vec<ArkField>> = c_ntts
        .iter()
        .map(|cm| intt(&cm.iter().map(|&v| fmod(v)).collect::<Vec<_>>(), omega))
        .collect();
    let c_lde: Vec<Vec<ArkField>> = c_polys.iter().map(|p| eval_on_coset(p, lde)).collect();

    // ── 11. Transcript + challenges ──
    let mut tr = FiatShamirTranscript::new();
    tr.append_u64(m as u64);
    tr.append_u64(n as u64);
    tr.append_u64(k as u64);
    tr.append_u64(BLOWUP as u64);
    tr.append_u64(CAP_HEIGHT as u64);
    tr.append_u64(b as u64);
    tr.append_u64(b_source as u64);
    tr.append_u64(b_s as u64);
    tr.append_u64(b_sigma as u64);
    tr.append_u64(h as u64);
    tr.append_u64(w as u64);
    tr_append_hex32(&mut tr, a_oracle_hash);
    tr.append_field(sqrt_qn);
    let cvh = cvec_hash(c_ntts);
    let cvh_hex = bytes_to_hex(&cvh);
    tr_append_hex32(&mut tr, &cvh_hex);
    for &t in token_m {
        tr.append_field(fmod(t));
    }
    for &t in token_s {
        tr.append_field(fmod(t));
    }
    for &t in token_o {
        tr.append_field(fmod(t));
    }
    for hc in &trace_cap {
        tr.append(hc);
    }

    let tr_state_pre_rho0 = hash_hex(&tr.state);
    let rho0 = tr.challenge(P);
    let mut rhos = vec![from_u128(0); m];
    {
        let mut acc = rho0;
        for mm in 0..m {
            rhos[mm] = acc;
            acc = fmul(acc, rho0);
        }
    }
    let rho_msg = fadd(rhos[m - 2], fmul(rhos[m - 1], sqrt_qn));

    let alpha = tr.challenge(P);
    let n_quotients = num_alpha_slots(k);
    let mut alpha_pows = vec![from_u128(0); n_quotients];
    alpha_pows[0] = alpha;
    for i in 1..n_quotients {
        alpha_pows[i] = fmul(alpha_pows[i - 1], alpha);
    }

    let lam_k: Vec<ArkField> = (0..k).map(|_| tr.challenge(P)).collect();
    let beta_lup = tr.challenge(P);

    // ── 12. Interaction columns ──
    let pm_vals_cols: Vec<Vec<ArkField>> = dm_byte_cols
        .iter()
        .map(|col| compute_helper_inverse(beta_lup, col))
        .collect();
    let ps_vals_cols: Vec<Vec<ArkField>> = ds_byte_cols
        .iter()
        .map(|col| compute_helper_inverse(beta_lup, col))
        .collect();
    let q_col_vals = compute_helper_inverse(beta_lup, t_ntt);
    // pr: helper inverses for the 2K r-byte columns (glo then ghi)
    let pr_vals_cols: Vec<Vec<ArkField>> = r_byte_cols
        .iter()
        .map(|col| compute_helper_inverse(beta_lup, col))
        .collect();

    let pm_vals_arr: [Vec<ArkField>; 8] = pm_vals_cols.try_into().unwrap();
    let ps_vals_arr: [Vec<ArkField>; 8] = ps_vals_cols.try_into().unwrap();
    let z_lup_vals = compute_z_lup(
        n,
        &pm_vals_arr,
        &ps_vals_arr,
        &pr_vals_cols,
        &mu_vals,
        &q_col_vals,
    );

    let pm_polys: Vec<Vec<ArkField>> = pm_vals_arr
        .iter()
        .map(|col| blind_with_n_minus_1(&intt(col, omega), &rand_poly(b), n))
        .collect();
    let ps_polys: Vec<Vec<ArkField>> = ps_vals_arr
        .iter()
        .map(|col| blind_with_n_minus_1(&intt(col, omega), &rand_poly(b), n))
        .collect();
    let pr_polys: Vec<Vec<ArkField>> = pr_vals_cols
        .iter()
        .map(|col| blind_with_n_minus_1(&intt(col, omega), &rand_poly(b), n))
        .collect();
    let q_col_poly = blind_with_n_minus_1(&intt(&q_col_vals, omega), &rand_poly(b), n);
    let z_lup_poly = blind_with_n_minus_1(&intt(&z_lup_vals, omega), &rand_poly(b), n);

    let pm_lde: Vec<Vec<ArkField>> = pm_polys.par_iter().map(|p| eval_on_coset(p, lde)).collect();
    let ps_lde: Vec<Vec<ArkField>> = ps_polys.par_iter().map(|p| eval_on_coset(p, lde)).collect();
    let pr_lde: Vec<Vec<ArkField>> = pr_polys.par_iter().map(|p| eval_on_coset(p, lde)).collect();
    let (q_col_lde, z_lup_lde) = rayon::join(
        || eval_on_coset(&q_col_poly, lde),
        || eval_on_coset(&z_lup_poly, lde),
    );

    // ── 15. Round 0.5 Merkle commit ──
    let inter_salts_all = random_salts(lde.lde_size);
    let inter_leaves: Vec<[u8; 32]> = (0..lde.lde_size)
        .into_par_iter()
        .map(|i| {
            let mut row = vec![from_u128(0); inter_col_count(k)];
            for j in 0..8 {
                row[j] = pm_lde[j][i];
                row[8 + j] = ps_lde[j][i];
            }
            for j in 0..2 * k {
                row[inter_off_pr(k) + j] = pr_lde[j][i];
            }
            row[inter_off_qcol(k)] = q_col_lde[i];
            row[inter_off_zlup(k)] = z_lup_lde[i];
            leaf_hash_from_values_salt(&row, &inter_salts_all[i])
        })
        .collect();
    let inter_tree = BatchedMerkleTree::new(inter_leaves, cap_r0);
    let inter_cap = inter_tree.cap();
    for hc in &inter_cap {
        tr.append(hc);
    }

    // ── 16. Aurora ──
    let beta_aur = fadd(fmod(r_aur_poly[0]), fmod(r_aur_poly[n]));
    tr.append_field(beta_aur);
    let rho_aurora = tr.challenge(P);

    let sigma_alpha = sigma_alpha_coeffs(alpha, n, omega);
    let lambda_alpha = lambda_alpha_coeffs(alpha, n, omega, psi);
    let alpha_n = fpow(alpha, n_big);
    let alpha_n_plus1 = fadd(alpha_n, from_u128(1));

    let mut g_batch = vec![];
    let mut f_batch = vec![];
    for kk in 0..k {
        g_batch = poly_add_scaled(&g_batch, &ghat_polys[kk], lam_k[kk]);
        f_batch = poly_add_scaled(&f_batch, &bntt_polys[kk], lam_k[kk]);
    }
    let term1 = poly_mul(&g_batch, &sigma_alpha);
    let term2 = poly_mul(&f_batch, &lambda_alpha);
    let p_zero_target = poly_sub(&term1, &term2);
    let mut p_blinded = vec![from_u128(0); p_zero_target.len()];
    for j in 0..p_zero_target.len() {
        p_blinded[j] = fmul(rho_aurora, p_zero_target[j]);
    }
    poly_add_into(&mut p_blinded, &r_aur_poly);
    p_blinded[0] = fsub(p_blinded[0], beta_aur);
    let (q_poly_aur, rem_n) = div_by_xn_minus_1(&p_blinded, n);
    assert_eq!(
        fmod(rem_n.get(0).copied().unwrap_or_else(|| from_u128(0))),
        from_u128(0)
    );
    let r_col_poly: Vec<ArkField> = if rem_n.len() > 1 {
        rem_n[1..].to_vec()
    } else {
        vec![]
    };
    let q0_poly: Vec<ArkField> = q_poly_aur[..q_poly_aur.len().min(n)].to_vec();
    let q1_poly: Vec<ArkField> = q_poly_aur.get(n..).unwrap_or(&[]).to_vec();
    assert!(q1_poly.len() <= b - 1, "Aurora Q1 degree overflow");

    let aux_r_lde = eval_on_coset(&r_col_poly, lde);
    let aux_q0_lde = eval_on_coset(&q0_poly, lde);
    let aux_q1_lde = eval_on_coset(&q1_poly, lde);
    let aux_salts_all = random_salts(lde.lde_size);
    let aux_leaves: Vec<[u8; 32]> = (0..lde.lde_size)
        .into_par_iter()
        .map(|i| {
            leaf_hash_from_values_salt(
                &[aux_r_lde[i], aux_q0_lde[i], aux_q1_lde[i]],
                &aux_salts_all[i],
            )
        })
        .collect();
    let aux_tree = BatchedMerkleTree::new(aux_leaves, cap_r0);
    let aux_cap = aux_tree.cap();
    for hc in &aux_cap {
        tr.append(hc);
    }

    // ── 18. Periodic LDEs for hash constraints ──
    let omega_shift = BLOWUP;
    let f_abs_vals = build_absorb_selector_values(n);
    let f_abs_poly = intt(&f_abs_vals, omega);
    let f_abs_lde = eval_on_coset(&f_abs_poly, lde);

    let mut arc1_lde = Vec::new();
    let mut arc2_lde = Vec::new();
    for comp in 0..12 {
        let a1_vals = build_periodic_arc_values(n, &rescue_consts::RESCUE_ARC1, comp);
        arc1_lde.push(eval_on_coset(&intt(&a1_vals, omega), lde));
        let a2_vals = build_periodic_arc_values(n, &rescue_consts::RESCUE_ARC2, comp);
        arc2_lde.push(eval_on_coset(&intt(&a2_vals, omega), lde));
    }

    let source_ldes = [m_lde.clone(), m_sender_lde.clone(), m_orig_lde.clone()];
    let omega_nm1 = fpow(omega, n_big - 1);

    // Precompute per-point divisors (parallel)
    let precomp: Vec<(ArkField, ArkField, ArkField, ArkField)> = (0..lde.lde_size)
        .into_par_iter()
        .map(|i| {
            let x = lde.domain[i];
            let x_n = fpow(x, n_big);
            let zd = finv(fsub(x_n, from_u128(1)));
            let ixm1 = finv(fsub(x, from_u128(1)));
            let diff = fsub(x, omega_nm1);
            let ixmo = finv(diff);
            (zd, ixm1, diff, ixmo)
        })
        .collect();
    let zd_inv: Vec<ArkField> = precomp.iter().map(|t| t.0).collect();
    let inv_x_minus_1: Vec<ArkField> = precomp.iter().map(|t| t.1).collect();
    let x_minus_omnm1: Vec<ArkField> = precomp.iter().map(|t| t.2).collect();
    let inv_x_minus_omnm1: Vec<ArkField> = precomp.iter().map(|t| t.3).collect();

    // ── 19. Build CP on LDE (parallel) ──
    let cp_lde: Vec<ArkField> = (0..lde.lde_size)
        .into_par_iter()
        .map(|i| {
            let mut cp = from_u128(0);

            // Slot 0: matmul + msg
            let mut matmul = from_u128(0);
            for mm in 0..m {
                let mut inner = from_u128(0);
                for kk in 0..k {
                    inner = fadd(inner, fmul(a_lde[mm][kk][i], bntt_lde[kk][i]));
                }
                matmul = fadd(matmul, fmul(rhos[mm], fsub(inner, c_lde[mm][i])));
            }
            matmul = fadd(matmul, fmul(rho_msg, m_lde[i]));
            cp = fmul(alpha_pows[0], fmul(matmul, zd_inv[i]));

            // Range check: (ghat + 2^15) − (gLo + 256·gHi) = 0
            for kk in 0..k {
                let rc = fsub(
                    fadd(ghat_lde[kk][i], from_u128(R_SHIFT)),
                    fadd(glo_lde[kk][i], fmul(from_u128(256), ghi_lde[kk][i])),
                );
                cp = fadd(cp, fmul(alpha_pows[1 + kk], fmul(rc, zd_inv[i])));
            }

            let bal = fsub(m_orig_lde[i], fadd(m_sender_lde[i], m_lde[i]));
            cp = fadd(cp, fmul(alpha_pows[k + 1], fmul(bal, zd_inv[i])));

            let mut recomp_m = m_lde[i];
            for j in 0..8 {
                recomp_m = fsub(recomp_m, fmul(pow256_fields()[j], dm_lde[j][i]));
            }
            cp = fadd(cp, fmul(alpha_pows[k + 2], fmul(recomp_m, zd_inv[i])));

            let mut recomp_s = m_sender_lde[i];
            for j in 0..8 {
                recomp_s = fsub(recomp_s, fmul(pow256_fields()[j], ds_lde[j][i]));
            }
            cp = fadd(cp, fmul(alpha_pows[k + 3], fmul(recomp_s, zd_inv[i])));

            let i_next = (i + omega_shift) % lde.lde_size;
            let mut acc_trans = fsub(z_lup_lde[i_next], z_lup_lde[i]);
            for j in 0..8 {
                acc_trans = fsub(acc_trans, pm_lde[j][i]);
                acc_trans = fsub(acc_trans, ps_lde[j][i]);
            }
            for j in 0..2 * k {
                acc_trans = fsub(acc_trans, pr_lde[j][i]);
            }
            acc_trans = fadd(acc_trans, fmul(mu_lde[i], q_col_lde[i]));
            cp = fadd(cp, fmul(alpha_pows[k + 4], fmul(acc_trans, zd_inv[i])));

            for j in 0..8 {
                let ic = fsub(
                    fmul(pm_lde[j][i], fsub(beta_lup, dm_lde[j][i])),
                    from_u128(1),
                );
                cp = fadd(cp, fmul(alpha_pows[k + 5 + j], fmul(ic, zd_inv[i])));
            }
            for j in 0..8 {
                let ic = fsub(
                    fmul(ps_lde[j][i], fsub(beta_lup, ds_lde[j][i])),
                    from_u128(1),
                );
                cp = fadd(cp, fmul(alpha_pows[k + 13 + j], fmul(ic, zd_inv[i])));
            }
            for j in 0..2 * k {
                let rbv = if j < k {
                    glo_lde[j][i]
                } else {
                    ghi_lde[j - k][i]
                };
                let ic = fsub(fmul(pr_lde[j][i], fsub(beta_lup, rbv)), from_u128(1));
                cp = fadd(cp, fmul(alpha_pows[k + 21 + j], fmul(ic, zd_inv[i])));
            }
            let ic_t = fsub(fmul(q_col_lde[i], fsub(beta_lup, t_lde[i])), from_u128(1));
            cp = fadd(cp, fmul(alpha_pows[k + 21 + 2 * k], fmul(ic_t, zd_inv[i])));

            // Hash constraints
            let base_c1a = alpha_off_c1a(k);
            let base_c1b = alpha_off_c1b(k);
            let base_c2 = alpha_off_c2(k);
            let base_c3 = alpha_off_c3(k);

            for hi in 0..NUM_HASHES {
                // C1a
                for j in 0..RESCUE_RATE {
                    let shift_idx = (i + j * omega_shift) % lde.lde_size;
                    let src_shifted = source_ldes[hi][shift_idx];
                    let c1a_num = fsub(
                        hash_sigma_lde[hi][j][i],
                        fadd(hash_state_lde[hi][j][i], fmul(f_abs_lde[i], src_shifted)),
                    );
                    cp = fadd(
                        cp,
                        fmul(
                            alpha_pows[base_c1a + hi * RESCUE_RATE + j],
                            fmul(c1a_num, zd_inv[i]),
                        ),
                    );
                }

                // C1b
                let i_omega = (i + omega_shift) % lde.lde_size;
                let mut s_next = [from_u128(0); 12];
                for ci in 0..12 {
                    s_next[ci] = hash_state_lde[hi][ci][i_omega];
                }

                let mut s_minus_arc2 = [from_u128(0); 12];
                for ci in 0..12 {
                    s_minus_arc2[ci] = fsub(s_next[ci], arc2_lde[ci][i]);
                }
                let mut m_inv_applied = [from_u128(0); 12];
                for ci in 0..12 {
                    for cj in 0..12 {
                        m_inv_applied[ci] = fadd(
                            m_inv_applied[ci],
                            fmul(rescue_minv()[ci][cj], s_minus_arc2[cj]),
                        );
                    }
                }
                let lhs_cubed: Vec<ArkField> =
                    m_inv_applied.iter().map(|&v| fmul(fmul(v, v), v)).collect();

                let mut sigma_hat = [from_u128(0); 12];
                for cj in 0..RESCUE_RATE {
                    sigma_hat[cj] = hash_sigma_lde[hi][cj][i];
                }
                for cj in RESCUE_RATE..12 {
                    sigma_hat[cj] = hash_state_lde[hi][cj][i];
                }
                let sig_cubed: Vec<ArkField> =
                    sigma_hat.iter().map(|&v| fmul(fmul(v, v), v)).collect();
                let mut m_applied = [from_u128(0); 12];
                for ci in 0..12 {
                    for cj in 0..12 {
                        m_applied[ci] =
                            fadd(m_applied[ci], fmul(rescue_m()[ci][cj], sig_cubed[cj]));
                    }
                }
                let mut rhs = [from_u128(0); 12];
                for ci in 0..12 {
                    rhs[ci] = fadd(m_applied[ci], arc1_lde[ci][i]);
                }

                for ci in 0..12 {
                    let c1b_num = fsub(lhs_cubed[ci], rhs[ci]);
                    cp = fadd(
                        cp,
                        fmul(
                            alpha_pows[base_c1b + hi * 12 + ci],
                            fmul(fmul(c1b_num, x_minus_omnm1[i]), zd_inv[i]),
                        ),
                    );
                }

                // C2
                for ci in 0..12 {
                    cp = fadd(
                        cp,
                        fmul(
                            alpha_pows[base_c2 + hi * 12 + ci],
                            fmul(hash_state_lde[hi][ci][i], inv_x_minus_1[i]),
                        ),
                    );
                }

                // C3
                for lane in 0..HASH_OUTPUT_LANES {
                    let c3_num = fsub(hash_state_lde[hi][lane][i], fmod(tokens[hi][lane]));
                    cp = fadd(
                        cp,
                        fmul(
                            alpha_pows[base_c3 + hi * HASH_OUTPUT_LANES + lane],
                            fmul(c3_num, inv_x_minus_omnm1[i]),
                        ),
                    );
                }
            }

            cp
        })
        .collect();

    // ── 20. Chunk CP ──
    let cp_coeffs = intt_coset(&cp_lde, lde);
    // Degree overflow check
    for j in (d_chunks * w)..cp_coeffs.len() {
        assert_eq!(
            fmod(cp_coeffs[j]),
            from_u128(0),
            "CP degree overflow at coeff {}",
            j
        );
    }
    let mut cp_chunks: Vec<Vec<ArkField>> = Vec::new();
    for j in 0..d_chunks {
        let mut chunk = vec![from_u128(0); w];
        for t in 0..w {
            let idx = j * w + t;
            if idx < cp_coeffs.len() {
                chunk[t] = fmod(cp_coeffs[idx]);
            }
        }
        cp_chunks.push(chunk);
    }
    let mut t_blind: Vec<Vec<ArkField>> = vec![vec![]; d_chunks + 1];
    for j in 1..d_chunks {
        t_blind[j] = rand_poly(h);
    }
    let mut cp_chunk_polys = Vec::new();
    for j in 0..d_chunks {
        let mut cj = cp_chunks[j].clone();
        let shifted = shift_up(&t_blind[j + 1], w);
        poly_add_into(&mut cj, &shifted);
        cj = poly_sub(&cj, &t_blind[j]);
        cp_chunk_polys.push(cj);
    }
    let cp_chunk_lde: Vec<Vec<ArkField>> = cp_chunk_polys
        .par_iter()
        .map(|p| eval_on_coset(p, lde))
        .collect();

    let cp_chunk_salts_all = random_salts(lde.lde_size);
    let cp_chunk_leaves: Vec<[u8; 32]> = (0..lde.lde_size)
        .into_par_iter()
        .map(|i| {
            let row: Vec<ArkField> = (0..d_chunks).map(|j| cp_chunk_lde[j][i]).collect();
            leaf_hash_from_values_salt(&row, &cp_chunk_salts_all[i])
        })
        .collect();
    let cp_chunk_tree = BatchedMerkleTree::new(cp_chunk_leaves, cap_r0);
    let cp_chunk_cap = cp_chunk_tree.cap();
    for hc in &cp_chunk_cap {
        tr.append(hc);
    }

    // ── 21. OOD point z ──
    let z = tr.challenge(P);
    let omega_z = fmul(omega, z);

    // ── 22. OOD openings ──
    let ood_bntt_z: Vec<ArkField> = bntt_polys.iter().map(|p| poly_eval(p, z)).collect();
    let ood_ghat_z: Vec<ArkField> = ghat_polys.iter().map(|p| poly_eval(p, z)).collect();
    let ood_glo_z: Vec<ArkField> = glo_polys.iter().map(|p| poly_eval(p, z)).collect();
    let ood_ghi_z: Vec<ArkField> = ghi_polys.iter().map(|p| poly_eval(p, z)).collect();
    let mut ood_a_z = Vec::with_capacity(m * k);
    for mm in 0..m {
        for kk in 0..k {
            ood_a_z.push(poly_eval(&a_polys[mm][kk], z));
        }
    }
    let ood_t_z = poly_eval(t_poly, z);
    let ood_m_z = poly_eval(&m_poly, z);
    let ood_m_orig_z = poly_eval(&m_orig_poly, z);
    let ood_m_sender_z = poly_eval(&m_sender_poly, z);
    let ood_dm_z: Vec<ArkField> = dm_polys.iter().map(|p| poly_eval(p, z)).collect();
    let ood_ds_z: Vec<ArkField> = ds_polys.iter().map(|p| poly_eval(p, z)).collect();
    let ood_pm_z: Vec<ArkField> = pm_polys.iter().map(|p| poly_eval(p, z)).collect();
    let ood_ps_z: Vec<ArkField> = ps_polys.iter().map(|p| poly_eval(p, z)).collect();
    let ood_pr_z: Vec<ArkField> = pr_polys.iter().map(|p| poly_eval(p, z)).collect();
    let ood_qcol_z = poly_eval(&q_col_poly, z);
    let ood_mu_z = poly_eval(&mu_poly, z);
    let ood_zlup_z = poly_eval(&z_lup_poly, z);
    let ood_zlup_omega_z = poly_eval(&z_lup_poly, omega_z);
    let ood_raur_z = poly_eval(&r_aur_poly, z);
    let ood_r_z = poly_eval(&r_col_poly, z);
    let ood_q_z = poly_eval(&q0_poly, z);
    let ood_q1_z = poly_eval(&q1_poly, z);
    let ood_cp_chunk_z: Vec<ArkField> = cp_chunk_polys.iter().map(|p| poly_eval(p, z)).collect();

    let mut ood_hash_state_z = Vec::new();
    let mut ood_hash_state_omega_z = Vec::new();
    let mut ood_hash_sigma_z = Vec::new();
    for hi in 0..NUM_HASHES {
        ood_hash_state_z.push(
            hash_state_polys[hi]
                .iter()
                .map(|p| poly_eval(p, z))
                .collect::<Vec<_>>(),
        );
        ood_hash_state_omega_z.push(
            hash_state_polys[hi]
                .iter()
                .map(|p| poly_eval(p, omega_z))
                .collect::<Vec<_>>(),
        );
        ood_hash_sigma_z.push(
            hash_sigma_polys[hi]
                .iter()
                .map(|p| poly_eval(p, z))
                .collect::<Vec<_>>(),
        );
    }

    let source_polys = [m_poly.clone(), m_sender_poly.clone(), m_orig_poly.clone()];
    let mut ood_source_shifts = Vec::new();
    for hi in 0..NUM_HASHES {
        let mut shifts = Vec::new();
        for j in 1..=7u128 {
            let omega_j_z = fmul(fpow(omega, j), z);
            shifts.push(poly_eval(&source_polys[hi], omega_j_z));
        }
        ood_source_shifts.push(shifts);
    }

    // ── 23. Prover-side OOD sanity check ──
    {
        let z_n = fpow(z, n_big);
        let zd_inv_z = finv(fsub(z_n, from_u128(1)));

        // Slot 0: matmul + msg
        let mut matmul_z = from_u128(0);
        for mm in 0..m {
            let mut inner = from_u128(0);
            for kk in 0..k {
                inner = fadd(inner, fmul(ood_a_z[mm * k + kk], ood_bntt_z[kk]));
            }
            let c_at_z = poly_eval(&c_polys[mm], z);
            matmul_z = fadd(matmul_z, fmul(rhos[mm], fsub(inner, c_at_z)));
        }
        matmul_z = fadd(matmul_z, fmul(rho_msg, ood_m_z));
        let mut cp_expected = fmul(alpha_pows[0], fmul(matmul_z, zd_inv_z));

        for kk in 0..k {
            let rc = fsub(
                fadd(ood_ghat_z[kk], from_u128(R_SHIFT)),
                fadd(ood_glo_z[kk], fmul(from_u128(256), ood_ghi_z[kk])),
            );
            cp_expected = fadd(cp_expected, fmul(alpha_pows[1 + kk], fmul(rc, zd_inv_z)));
        }
        cp_expected = fadd(
            cp_expected,
            fmul(
                alpha_pows[k + 1],
                fmul(fsub(ood_m_orig_z, fadd(ood_m_sender_z, ood_m_z)), zd_inv_z),
            ),
        );
        let mut rm_z = ood_m_z;
        for j in 0..8 {
            rm_z = fsub(rm_z, fmul(pow256_fields()[j], ood_dm_z[j]));
        }
        cp_expected = fadd(cp_expected, fmul(alpha_pows[k + 2], fmul(rm_z, zd_inv_z)));
        let mut rs_z = ood_m_sender_z;
        for j in 0..8 {
            rs_z = fsub(rs_z, fmul(pow256_fields()[j], ood_ds_z[j]));
        }
        cp_expected = fadd(cp_expected, fmul(alpha_pows[k + 3], fmul(rs_z, zd_inv_z)));

        let mut acc_z = fsub(ood_zlup_omega_z, ood_zlup_z);
        for j in 0..8 {
            acc_z = fsub(acc_z, ood_pm_z[j]);
            acc_z = fsub(acc_z, ood_ps_z[j]);
        }
        for j in 0..2 * k {
            acc_z = fsub(acc_z, ood_pr_z[j]);
        }
        acc_z = fadd(acc_z, fmul(ood_mu_z, ood_qcol_z));
        cp_expected = fadd(cp_expected, fmul(alpha_pows[k + 4], fmul(acc_z, zd_inv_z)));

        for j in 0..8 {
            cp_expected = fadd(
                cp_expected,
                fmul(
                    alpha_pows[k + 5 + j],
                    fmul(
                        fsub(fmul(ood_pm_z[j], fsub(beta_lup, ood_dm_z[j])), from_u128(1)),
                        zd_inv_z,
                    ),
                ),
            );
        }
        for j in 0..8 {
            cp_expected = fadd(
                cp_expected,
                fmul(
                    alpha_pows[k + 13 + j],
                    fmul(
                        fsub(fmul(ood_ps_z[j], fsub(beta_lup, ood_ds_z[j])), from_u128(1)),
                        zd_inv_z,
                    ),
                ),
            );
        }
        for j in 0..2 * k {
            let rbv = if j < k {
                ood_glo_z[j]
            } else {
                ood_ghi_z[j - k]
            };
            cp_expected = fadd(
                cp_expected,
                fmul(
                    alpha_pows[k + 21 + j],
                    fmul(
                        fsub(fmul(ood_pr_z[j], fsub(beta_lup, rbv)), from_u128(1)),
                        zd_inv_z,
                    ),
                ),
            );
        }
        cp_expected = fadd(
            cp_expected,
            fmul(
                alpha_pows[k + 21 + 2 * k],
                fmul(
                    fsub(fmul(ood_qcol_z, fsub(beta_lup, ood_t_z)), from_u128(1)),
                    zd_inv_z,
                ),
            ),
        );

        // Hash constraints at z
        let f_abs_z = eval_absorb_selector_at_z(z, n);
        let z_minus_omnm1 = fsub(z, omega_nm1);
        let inv_z_minus_1 = finv(fsub(z, from_u128(1)));
        let inv_z_minus_omnm1 = finv(z_minus_omnm1);
        let source_ood_z = [ood_m_z, ood_m_sender_z, ood_m_orig_z];

        for hi in 0..NUM_HASHES {
            for j in 0..RESCUE_RATE {
                let src = if j == 0 {
                    source_ood_z[hi]
                } else {
                    ood_source_shifts[hi][j - 1]
                };
                let c1a = fsub(
                    ood_hash_sigma_z[hi][j],
                    fadd(ood_hash_state_z[hi][j], fmul(f_abs_z, src)),
                );
                cp_expected = fadd(
                    cp_expected,
                    fmul(
                        alpha_pows[alpha_off_c1a(k) + hi * RESCUE_RATE + j],
                        fmul(c1a, zd_inv_z),
                    ),
                );
            }

            let s_next_z = &ood_hash_state_omega_z[hi];
            let mut arc2_at_z = [from_u128(0); 12];
            let mut arc1_at_z = [from_u128(0); 12];
            for ci in 0..12 {
                let a2: [ArkField; 8] =
                    std::array::from_fn(|r| from_u128(rescue_consts::RESCUE_ARC2[r][ci]));
                arc2_at_z[ci] = eval_periodic_at_z(&a2, z, n, omega);
                let a1: [ArkField; 8] =
                    std::array::from_fn(|r| from_u128(rescue_consts::RESCUE_ARC1[r][ci]));
                arc1_at_z[ci] = eval_periodic_at_z(&a1, z, n, omega);
            }
            let sm_a2: Vec<ArkField> = (0..12)
                .map(|ci| fsub(s_next_z[ci], arc2_at_z[ci]))
                .collect();
            let mut m_inv_z = [from_u128(0); 12];
            for ci in 0..12 {
                for cj in 0..12 {
                    m_inv_z[ci] = fadd(m_inv_z[ci], fmul(rescue_minv()[ci][cj], sm_a2[cj]));
                }
            }
            let lhs_c: Vec<ArkField> = m_inv_z.iter().map(|&v| fmul(fmul(v, v), v)).collect();

            let mut sig_hat_z = [from_u128(0); 12];
            for cj in 0..RESCUE_RATE {
                sig_hat_z[cj] = ood_hash_sigma_z[hi][cj];
            }
            for cj in RESCUE_RATE..12 {
                sig_hat_z[cj] = ood_hash_state_z[hi][cj];
            }
            let sc_z: Vec<ArkField> = sig_hat_z.iter().map(|&v| fmul(fmul(v, v), v)).collect();
            let mut m_app_z = [from_u128(0); 12];
            for ci in 0..12 {
                for cj in 0..12 {
                    m_app_z[ci] = fadd(m_app_z[ci], fmul(rescue_m()[ci][cj], sc_z[cj]));
                }
            }
            let rhs_c: Vec<ArkField> = (0..12).map(|ci| fadd(m_app_z[ci], arc1_at_z[ci])).collect();

            for ci in 0..12 {
                let c1b_num = fsub(lhs_c[ci], rhs_c[ci]);
                cp_expected = fadd(
                    cp_expected,
                    fmul(
                        alpha_pows[alpha_off_c1b(k) + hi * 12 + ci],
                        fmul(fmul(c1b_num, z_minus_omnm1), zd_inv_z),
                    ),
                );
            }
            for ci in 0..12 {
                cp_expected = fadd(
                    cp_expected,
                    fmul(
                        alpha_pows[alpha_off_c2(k) + hi * 12 + ci],
                        fmul(ood_hash_state_z[hi][ci], inv_z_minus_1),
                    ),
                );
            }
            for lane in 0..HASH_OUTPUT_LANES {
                let c3n = fsub(ood_hash_state_z[hi][lane], fmod(tokens[hi][lane]));
                cp_expected = fadd(
                    cp_expected,
                    fmul(
                        alpha_pows[alpha_off_c3(k) + hi * HASH_OUTPUT_LANES + lane],
                        fmul(c3n, inv_z_minus_omnm1),
                    ),
                );
            }
        }

        let q_at_z = fadd(ood_q_z, fmul(z_n, ood_q1_z));
        let lhs_aur = fadd(
            fmul(
                rho_aurora,
                fsub(
                    fmul(poly_eval(&g_batch, z), poly_eval(&sigma_alpha, z)),
                    fmul(poly_eval(&f_batch, z), poly_eval(&lambda_alpha, z)),
                ),
            ),
            ood_raur_z,
        );
        let rhs_aur = fadd(
            beta_aur,
            fadd(fmul(z, ood_r_z), fmul(q_at_z, fsub(z_n, from_u128(1)))),
        );
        assert_eq!(lhs_aur, rhs_aur, "prover OOD Aurora self-check failed");

        let mut cp_at_z = from_u128(0);
        let z_w = fpow(z, w as u128);
        let mut z_pow = from_u128(1);
        for j in 0..d_chunks {
            cp_at_z = fadd(cp_at_z, fmul(z_pow, ood_cp_chunk_z[j]));
            z_pow = fmul(z_pow, z_w);
        }
        assert_eq!(cp_at_z, cp_expected, "prover OOD CP self-check failed");
    }

    // Absorb OOD into transcript
    for &v in &ood_bntt_z {
        tr.append_field(v);
    }
    for &v in &ood_ghat_z {
        tr.append_field(v);
    }
    for &v in &ood_glo_z {
        tr.append_field(v);
    }
    for &v in &ood_ghi_z {
        tr.append_field(v);
    }
    for &v in &ood_a_z {
        tr.append_field(v);
    }
    tr.append_field(ood_t_z);
    tr.append_field(ood_m_z);
    tr.append_field(ood_m_orig_z);
    tr.append_field(ood_m_sender_z);
    for &v in &ood_dm_z {
        tr.append_field(v);
    }
    for &v in &ood_ds_z {
        tr.append_field(v);
    }
    for &v in &ood_pm_z {
        tr.append_field(v);
    }
    for &v in &ood_ps_z {
        tr.append_field(v);
    }
    for &v in &ood_pr_z {
        tr.append_field(v);
    }
    tr.append_field(ood_qcol_z);
    tr.append_field(ood_mu_z);
    tr.append_field(ood_zlup_z);
    tr.append_field(ood_zlup_omega_z);
    tr.append_field(ood_raur_z);
    tr.append_field(ood_r_z);
    tr.append_field(ood_q_z);
    tr.append_field(ood_q1_z);
    for &v in &ood_cp_chunk_z {
        tr.append_field(v);
    }
    for hi in 0..NUM_HASHES {
        for &v in &ood_hash_state_z[hi] {
            tr.append_field(v);
        }
    }
    for hi in 0..NUM_HASHES {
        for &v in &ood_hash_state_omega_z[hi] {
            tr.append_field(v);
        }
    }
    for hi in 0..NUM_HASHES {
        for &v in &ood_hash_sigma_z[hi] {
            tr.append_field(v);
        }
    }
    for hi in 0..NUM_HASHES {
        for &v in &ood_source_shifts[hi] {
            tr.append_field(v);
        }
    }

    // ── 24. Mask R_deep ──
    let b_deep = b_source;
    let mask_poly = rand_poly(n + b_deep);
    let mask_lde = eval_on_coset(&mask_poly, lde);
    let mask_salts_all = random_salts(lde.lde_size);
    let mask_leaves: Vec<[u8; 32]> = mask_lde
        .par_iter()
        .enumerate()
        .map(|(i, &v)| leaf_hash_from_values_salt(&[v], &mask_salts_all[i]))
        .collect();
    let mask_tree = BatchedMerkleTree::new(mask_leaves, cap_r0);
    let mask_cap = mask_tree.cap();
    for hc in &mask_cap {
        tr.append(hc);
    }

    // ── 25. DEEP combiners γ ──
    let gam = |n: usize, tr: &mut FiatShamirTranscript| -> Vec<ArkField> {
        (0..n).map(|_| tr.challenge(P)).collect()
    };
    let g_bntt_z = gam(k, &mut tr);
    let g_ghat_z = gam(k, &mut tr);
    let g_glo_z = gam(k, &mut tr);
    let g_ghi_z = gam(k, &mut tr);
    let g_a_z = gam(m * k, &mut tr);
    let g_t_z = tr.challenge(P);
    let g_m = tr.challenge(P);
    let g_m_orig = tr.challenge(P);
    let g_m_sender = tr.challenge(P);
    let g_dm_z = gam(8, &mut tr);
    let g_ds_z = gam(8, &mut tr);
    let g_pm_z = gam(8, &mut tr);
    let g_ps_z = gam(8, &mut tr);
    let g_pr_z = gam(2 * k, &mut tr);
    let g_qcol = tr.challenge(P);
    let g_mu = tr.challenge(P);
    let g_zlup = tr.challenge(P);
    let g_zlup_omega = tr.challenge(P);
    let g_raur = tr.challenge(P);
    let g_r = tr.challenge(P);
    let g_q = tr.challenge(P);
    let g_cp_chunk = gam(d_chunks, &mut tr);
    let mut g_hash_state_z = Vec::new();
    let mut g_hash_state_omega_z = Vec::new();
    let mut g_hash_sigma_z = Vec::new();
    let mut g_source_shifts = Vec::new();
    for _ in 0..NUM_HASHES {
        g_hash_state_z.push(gam(12, &mut tr));
        g_hash_state_omega_z.push(gam(12, &mut tr));
        g_hash_sigma_z.push(gam(8, &mut tr));
    }
    for _ in 0..NUM_HASHES {
        g_source_shifts.push(gam(7, &mut tr));
    }

    // ── 26. DEEP polynomial h(x) (parallel) ──
    let h_lde: Vec<ArkField> = (0..lde.lde_size)
        .into_par_iter()
        .map(|i| {
            let ell = lde.domain[i];
            let inv_ell_z = finv(fsub(ell, z));
            let inv_ell_omega_z = finv(fsub(ell, omega_z));

            let mut val = from_u128(0);
            for kk in 0..k {
                val = fadd(
                    val,
                    fmul(
                        g_bntt_z[kk],
                        fmul(fsub(bntt_lde[kk][i], ood_bntt_z[kk]), inv_ell_z),
                    ),
                );
            }
            for kk in 0..k {
                val = fadd(
                    val,
                    fmul(
                        g_ghat_z[kk],
                        fmul(fsub(ghat_lde[kk][i], ood_ghat_z[kk]), inv_ell_z),
                    ),
                );
            }
            for kk in 0..k {
                val = fadd(
                    val,
                    fmul(
                        g_glo_z[kk],
                        fmul(fsub(glo_lde[kk][i], ood_glo_z[kk]), inv_ell_z),
                    ),
                );
            }
            for kk in 0..k {
                val = fadd(
                    val,
                    fmul(
                        g_ghi_z[kk],
                        fmul(fsub(ghi_lde[kk][i], ood_ghi_z[kk]), inv_ell_z),
                    ),
                );
            }
            for mm in 0..m {
                for kk in 0..k {
                    val = fadd(
                        val,
                        fmul(
                            g_a_z[mm * k + kk],
                            fmul(fsub(a_lde[mm][kk][i], ood_a_z[mm * k + kk]), inv_ell_z),
                        ),
                    );
                }
            }
            val = fadd(val, fmul(g_t_z, fmul(fsub(t_lde[i], ood_t_z), inv_ell_z)));
            val = fadd(val, fmul(g_m, fmul(fsub(m_lde[i], ood_m_z), inv_ell_z)));
            val = fadd(
                val,
                fmul(g_m_orig, fmul(fsub(m_orig_lde[i], ood_m_orig_z), inv_ell_z)),
            );
            val = fadd(
                val,
                fmul(
                    g_m_sender,
                    fmul(fsub(m_sender_lde[i], ood_m_sender_z), inv_ell_z),
                ),
            );
            for j in 0..8 {
                val = fadd(
                    val,
                    fmul(g_dm_z[j], fmul(fsub(dm_lde[j][i], ood_dm_z[j]), inv_ell_z)),
                );
            }
            for j in 0..8 {
                val = fadd(
                    val,
                    fmul(g_ds_z[j], fmul(fsub(ds_lde[j][i], ood_ds_z[j]), inv_ell_z)),
                );
            }
            for j in 0..8 {
                val = fadd(
                    val,
                    fmul(g_pm_z[j], fmul(fsub(pm_lde[j][i], ood_pm_z[j]), inv_ell_z)),
                );
            }
            for j in 0..8 {
                val = fadd(
                    val,
                    fmul(g_ps_z[j], fmul(fsub(ps_lde[j][i], ood_ps_z[j]), inv_ell_z)),
                );
            }
            for j in 0..2 * k {
                val = fadd(
                    val,
                    fmul(g_pr_z[j], fmul(fsub(pr_lde[j][i], ood_pr_z[j]), inv_ell_z)),
                );
            }
            val = fadd(
                val,
                fmul(g_qcol, fmul(fsub(q_col_lde[i], ood_qcol_z), inv_ell_z)),
            );
            val = fadd(val, fmul(g_mu, fmul(fsub(mu_lde[i], ood_mu_z), inv_ell_z)));
            val = fadd(
                val,
                fmul(g_zlup, fmul(fsub(z_lup_lde[i], ood_zlup_z), inv_ell_z)),
            );
            val = fadd(
                val,
                fmul(
                    g_zlup_omega,
                    fmul(fsub(z_lup_lde[i], ood_zlup_omega_z), inv_ell_omega_z),
                ),
            );
            val = fadd(
                val,
                fmul(g_raur, fmul(fsub(r_aur_lde[i], ood_raur_z), inv_ell_z)),
            );
            val = fadd(val, fmul(g_r, fmul(fsub(aux_r_lde[i], ood_r_z), inv_ell_z)));
            val = fadd(
                val,
                fmul(g_q, fmul(fsub(aux_q0_lde[i], ood_q_z), inv_ell_z)),
            );
            val = fadd(
                val,
                fmul(
                    fadd(g_q, from_u128(1)),
                    fmul(fsub(aux_q1_lde[i], ood_q1_z), inv_ell_z),
                ),
            );
            for j in 0..d_chunks {
                val = fadd(
                    val,
                    fmul(
                        g_cp_chunk[j],
                        fmul(fsub(cp_chunk_lde[j][i], ood_cp_chunk_z[j]), inv_ell_z),
                    ),
                );
            }

            for hi in 0..NUM_HASHES {
                for ci in 0..12 {
                    val = fadd(
                        val,
                        fmul(
                            g_hash_state_z[hi][ci],
                            fmul(
                                fsub(hash_state_lde[hi][ci][i], ood_hash_state_z[hi][ci]),
                                inv_ell_z,
                            ),
                        ),
                    );
                    val = fadd(
                        val,
                        fmul(
                            g_hash_state_omega_z[hi][ci],
                            fmul(
                                fsub(hash_state_lde[hi][ci][i], ood_hash_state_omega_z[hi][ci]),
                                inv_ell_omega_z,
                            ),
                        ),
                    );
                }
                for cj in 0..8 {
                    val = fadd(
                        val,
                        fmul(
                            g_hash_sigma_z[hi][cj],
                            fmul(
                                fsub(hash_sigma_lde[hi][cj][i], ood_hash_sigma_z[hi][cj]),
                                inv_ell_z,
                            ),
                        ),
                    );
                }
            }
            for hi in 0..NUM_HASHES {
                let src_val = source_ldes[hi][i];
                for j in 1..=7u128 {
                    let om_j_z = fmul(fpow(omega, j), z);
                    let inv_ell_omjz = finv(fsub(ell, om_j_z));
                    val = fadd(
                        val,
                        fmul(
                            g_source_shifts[hi][(j - 1) as usize],
                            fmul(
                                fsub(src_val, ood_source_shifts[hi][(j - 1) as usize]),
                                inv_ell_omjz,
                            ),
                        ),
                    );
                }
            }

            fadd(val, mask_lde[i])
        })
        .collect();

    // ── 27. Split h = g0 + x^N·g1 ──
    let h_coeffs = intt_coset(&h_lde, lde);
    let g0_coeffs: Vec<ArkField> = h_coeffs[..n].to_vec();
    let g1_coeffs: Vec<ArkField> = if h_coeffs.len() > n {
        h_coeffs[n..n + b_deep].to_vec()
    } else {
        vec![]
    };
    let g0_lde = eval_on_coset(&g0_coeffs, lde);
    let g1_lde = eval_on_coset(&g1_coeffs, lde);

    let split_salts_all = random_salts(lde.lde_size);
    let split_leaves: Vec<[u8; 32]> = (0..lde.lde_size)
        .into_par_iter()
        .map(|i| leaf_hash_from_values_salt(&[g0_lde[i], g1_lde[i]], &split_salts_all[i]))
        .collect();
    let split_tree = BatchedMerkleTree::new(split_leaves, cap_r0);
    let split_cap = split_tree.cap();
    for hc in &split_cap {
        tr.append(hc);
    }

    let lambda = tr.challenge(P);
    let lambda2 = fmul(lambda, lambda);
    let lambda3 = fmul(lambda2, lambda);
    let lambda4 = fmul(lambda3, lambda);
    let h_batch_evals: Vec<ArkField> = (0..lde.lde_size)
        .map(|i| {
            let x = lde.domain[i];
            fadd(
                fadd(g0_lde[i], fmul(lambda, g1_lde[i])),
                fadd(
                    fmul(lambda2, fmul(x, aux_r_lde[i])),
                    fadd(
                        fmul(lambda3, aux_q0_lde[i]),
                        fmul(lambda4, fmul(fpow(x, (n - b + 1) as u128), aux_q1_lde[i])),
                    ),
                ),
            )
        })
        .collect();

    // ── 29. FRI ──
    let fri_result = fri_commit(
        h_batch_evals,
        lde,
        n,
        CAP_HEIGHT,
        FINAL_POLY_BOUND,
        FRI_ARITY,
        &mut tr,
    );

    // ── 30. Grinding ──
    let (grinding_nonce, grinding_state) = grind_transcript_state(&tr.state, grinding_bits);
    tr.state = grinding_state;

    // ── 31. Query indices ──
    let query_indices: Vec<usize> = (0..NUM_QUERIES)
        .map(|_| tr.challenge_index(lde.lde_size / FRI_ARITY))
        .collect();

    // ── 32. Openings at query positions ──
    let mut pos_set: Vec<usize> = query_indices.clone();
    pos_set.sort_unstable();
    pos_set.dedup();
    let positions = pos_set;

    let trace_col_vals: Vec<Vec<ArkField>> = positions
        .iter()
        .map(|&p| {
            let mut row = vec![from_u128(0); trace_cols];
            for kk in 0..k {
                row[trace_off_bntt(k) + kk] = bntt_lde[kk][p];
                row[trace_off_ghat(k) + kk] = ghat_lde[kk][p];
                row[trace_off_glo(k) + kk] = glo_lde[kk][p];
                row[trace_off_ghi(k) + kk] = ghi_lde[kk][p];
            }
            row[trace_off_m(k)] = m_lde[p];
            row[trace_off_m_orig(k)] = m_orig_lde[p];
            row[trace_off_m_sender(k)] = m_sender_lde[p];
            for j in 0..8 {
                row[trace_off_dm(k) + j] = dm_lde[j][p];
                row[trace_off_ds(k) + j] = ds_lde[j][p];
            }
            row[trace_off_mu(k)] = mu_lde[p];
            row[trace_off_raur(k)] = r_aur_lde[p];
            for hi in 0..NUM_HASHES {
                for ci in 0..12 {
                    row[trace_off_hash_state(k, hi) + ci] = hash_state_lde[hi][ci][p];
                }
                for cj in 0..8 {
                    row[trace_off_hash_sigma(k, hi) + cj] = hash_sigma_lde[hi][cj][p];
                }
            }
            row
        })
        .collect();
    let trace_salts: Vec<[u8; 16]> = positions.iter().map(|&p| trace_salts_all[p]).collect();
    let trace_batch_proof = trace_tree.open_batch(&positions);

    let inter_col_vals: Vec<Vec<ArkField>> = positions
        .iter()
        .map(|&p| {
            let mut row = vec![from_u128(0); inter_col_count(k)];
            for j in 0..8 {
                row[j] = pm_lde[j][p];
                row[8 + j] = ps_lde[j][p];
            }
            for j in 0..2 * k {
                row[inter_off_pr(k) + j] = pr_lde[j][p];
            }
            row[inter_off_qcol(k)] = q_col_lde[p];
            row[inter_off_zlup(k)] = z_lup_lde[p];
            row
        })
        .collect();
    let inter_salts: Vec<[u8; 16]> = positions.iter().map(|&p| inter_salts_all[p]).collect();
    let inter_batch_proof = inter_tree.open_batch(&positions);

    let aux_col_vals: Vec<Vec<ArkField>> = positions
        .iter()
        .map(|&p| vec![aux_r_lde[p], aux_q0_lde[p], aux_q1_lde[p]])
        .collect();
    let aux_salts: Vec<[u8; 16]> = positions.iter().map(|&p| aux_salts_all[p]).collect();
    let aux_batch_proof = aux_tree.open_batch(&positions);

    let cp_chunk_col_vals: Vec<Vec<ArkField>> = positions
        .iter()
        .map(|&p| (0..d_chunks).map(|j| cp_chunk_lde[j][p]).collect())
        .collect();
    let cp_chunk_salts: Vec<[u8; 16]> = positions.iter().map(|&p| cp_chunk_salts_all[p]).collect();
    let cp_chunk_batch_proof = cp_chunk_tree.open_batch(&positions);

    let mask_values: Vec<ArkField> = positions.iter().map(|&p| mask_lde[p]).collect();
    let mask_salts: Vec<[u8; 16]> = positions.iter().map(|&p| mask_salts_all[p]).collect();
    let mask_batch_proof = mask_tree.open_batch(&positions);

    let split_col_vals: Vec<Vec<ArkField>> = positions
        .iter()
        .map(|&p| vec![g0_lde[p], g1_lde[p]])
        .collect();
    let split_salts: Vec<[u8; 16]> = positions.iter().map(|&p| split_salts_all[p]).collect();
    let split_batch_proof = split_tree.open_batch(&positions);

    let a_col_vals: Vec<Vec<ArkField>> = positions
        .iter()
        .map(|&p| {
            let mut row = Vec::with_capacity(m * k + 1);
            for mm in 0..m {
                for kk in 0..k {
                    row.push(a_lde[mm][kk][p]);
                }
            }
            row.push(t_lde[p]);
            row
        })
        .collect();
    let a_batch_proof = a_tree.open_batch(&positions);

    // FRI layer openings
    let mut fri_layer_positions = Vec::new();
    let mut fri_layer_values = Vec::new();
    let mut fri_layer_salts_out = Vec::new();
    let mut fri_layer_proofs = Vec::new();
    for r in 0..fri_result.trees.len() {
        let evals_r = &fri_result.layers[r].evals;
        let n_r = evals_r.len();
        let quarter_r = n_r / FRI_ARITY;
        let mut set = std::collections::BTreeSet::new();
        for &q in &query_indices {
            let i_r = q % quarter_r;
            set.insert(i_r);
            set.insert(i_r + quarter_r);
            set.insert(i_r + 2 * quarter_r);
            set.insert(i_r + 3 * quarter_r);
        }
        let pos: Vec<usize> = set.into_iter().collect();
        fri_layer_positions.push(pos.clone());
        fri_layer_values.push(pos.iter().map(|&p| evals_r[p]).collect::<Vec<_>>());
        fri_layer_salts_out.push(
            pos.iter()
                .map(|&p| fri_result.salts[r][p])
                .collect::<Vec<_>>(),
        );
        fri_layer_proofs.push(fri_result.trees[r].open_batch(&pos));
    }

    // ── Build proof ──
    ProofData {
        a_oracle_hash: a_oracle_hash.to_string(),
        debug_rho0: to_s(rho0),
        debug_alpha: to_s(alpha),
        debug_beta_lup: to_s(beta_lup),
        debug_cvec_hash: hash_hex(&cvh),
        debug_tr_state_pre_rho0: tr_state_pre_rho0,
        trace_length: n,
        num_columns: k,
        blowup: BLOWUP,
        cap_height: CAP_HEIGHT,
        blind_b: b,
        blind_b_source: b_source,
        blind_b_state: b_s,
        blind_b_sigma: b_sigma,
        cp_blind_h: h,
        num_chunks: d_chunks,
        cp_chunk_width: w,
        beta_aur: to_s(beta_aur),
        omega: to_s(omega),
        psi: to_s(psi),
        lde_omega: to_s(lde.lde_omega),
        coset_gen: to_s(lde.coset_gen),
        token_m: token_m.iter().map(|&v| to_s(v)).collect(),
        token_s: token_s.iter().map(|&v| to_s(v)).collect(),
        token_o: token_o.iter().map(|&v| to_s(v)).collect(),

        trace_cap: trace_cap.iter().map(|h| hash_hex(h)).collect(),
        trace_positions: positions.clone(),
        trace_col_values: trace_col_vals
            .iter()
            .map(|r| r.iter().map(|&v| to_s(v)).collect())
            .collect(),
        trace_salts: trace_salts.iter().map(|s| bytes_to_hex(s)).collect(),
        trace_batch_proof: trace_batch_proof.iter().map(|h| hash_hex(h)).collect(),

        inter_cap: inter_cap.iter().map(|h| hash_hex(h)).collect(),
        inter_col_values: inter_col_vals
            .iter()
            .map(|r| r.iter().map(|&v| to_s(v)).collect())
            .collect(),
        inter_salts: inter_salts.iter().map(|s| bytes_to_hex(s)).collect(),
        inter_batch_proof: inter_batch_proof.iter().map(|h| hash_hex(h)).collect(),

        aux_cap: aux_cap.iter().map(|h| hash_hex(h)).collect(),
        aux_col_values: aux_col_vals
            .iter()
            .map(|r| r.iter().map(|&v| to_s(v)).collect())
            .collect(),
        aux_salts: aux_salts.iter().map(|s| bytes_to_hex(s)).collect(),
        aux_batch_proof: aux_batch_proof.iter().map(|h| hash_hex(h)).collect(),

        cp_chunk_cap: cp_chunk_cap.iter().map(|h| hash_hex(h)).collect(),
        cp_chunk_col_values: cp_chunk_col_vals
            .iter()
            .map(|r| r.iter().map(|&v| to_s(v)).collect())
            .collect(),
        cp_chunk_salts: cp_chunk_salts.iter().map(|s| bytes_to_hex(s)).collect(),
        cp_chunk_batch_proof: cp_chunk_batch_proof.iter().map(|h| hash_hex(h)).collect(),

        mask_cap: mask_cap.iter().map(|h| hash_hex(h)).collect(),
        mask_values: mask_values.iter().map(|&v| to_s(v)).collect(),
        mask_salts: mask_salts.iter().map(|s| bytes_to_hex(s)).collect(),
        mask_batch_proof: mask_batch_proof.iter().map(|h| hash_hex(h)).collect(),

        split_cap: split_cap.iter().map(|h| hash_hex(h)).collect(),
        split_col_values: split_col_vals
            .iter()
            .map(|r| r.iter().map(|&v| to_s(v)).collect())
            .collect(),
        split_salts: split_salts.iter().map(|s| bytes_to_hex(s)).collect(),
        split_batch_proof: split_batch_proof.iter().map(|h| hash_hex(h)).collect(),

        a_cap: a_cap.iter().map(|h| hash_hex(h)).collect(),
        a_col_values: a_col_vals
            .iter()
            .map(|r| r.iter().map(|&v| to_s(v)).collect())
            .collect(),
        a_batch_proof: a_batch_proof.iter().map(|h| hash_hex(h)).collect(),

        ood_bntt_z: ood_bntt_z.iter().map(|&v| to_s(v)).collect(),
        ood_ghat_z: ood_ghat_z.iter().map(|&v| to_s(v)).collect(),
        ood_glo_z: ood_glo_z.iter().map(|&v| to_s(v)).collect(),
        ood_ghi_z: ood_ghi_z.iter().map(|&v| to_s(v)).collect(),
        ood_a_z: ood_a_z.iter().map(|&v| to_s(v)).collect(),
        ood_t_z: to_s(ood_t_z),
        ood_m_z: to_s(ood_m_z),
        ood_m_orig_z: to_s(ood_m_orig_z),
        ood_m_sender_z: to_s(ood_m_sender_z),
        ood_dm_z: ood_dm_z.iter().map(|&v| to_s(v)).collect(),
        ood_ds_z: ood_ds_z.iter().map(|&v| to_s(v)).collect(),
        ood_pm_z: ood_pm_z.iter().map(|&v| to_s(v)).collect(),
        ood_ps_z: ood_ps_z.iter().map(|&v| to_s(v)).collect(),
        ood_pr_z: ood_pr_z.iter().map(|&v| to_s(v)).collect(),
        ood_qcol_z: to_s(ood_qcol_z),
        ood_mu_z: to_s(ood_mu_z),
        ood_zlup_z: to_s(ood_zlup_z),
        ood_zlup_omega_z: to_s(ood_zlup_omega_z),
        ood_raur_z: to_s(ood_raur_z),
        ood_r_z: to_s(ood_r_z),
        ood_q_z: to_s(ood_q_z),
        ood_q1_z: to_s(ood_q1_z),
        ood_cp_chunk_z: ood_cp_chunk_z.iter().map(|&v| to_s(v)).collect(),

        ood_hash_state_z: ood_hash_state_z
            .iter()
            .map(|r| r.iter().map(|&v| to_s(v)).collect())
            .collect(),
        ood_hash_state_omega_z: ood_hash_state_omega_z
            .iter()
            .map(|r| r.iter().map(|&v| to_s(v)).collect())
            .collect(),
        ood_hash_sigma_z: ood_hash_sigma_z
            .iter()
            .map(|r| r.iter().map(|&v| to_s(v)).collect())
            .collect(),
        ood_source_shifts: ood_source_shifts
            .iter()
            .map(|r| r.iter().map(|&v| to_s(v)).collect())
            .collect(),

        fri_caps: fri_result
            .caps
            .iter()
            .map(|cap| cap.iter().map(|h| hash_hex(h)).collect())
            .collect(),
        fri_layer_positions,
        fri_layer_values: fri_layer_values
            .iter()
            .map(|r| r.iter().map(|&v| to_s(v)).collect())
            .collect(),
        fri_layer_salts: fri_layer_salts_out
            .iter()
            .map(|r| r.iter().map(|s| bytes_to_hex(s)).collect())
            .collect(),
        fri_layer_proofs: fri_layer_proofs
            .iter()
            .map(|r| r.iter().map(|h| hash_hex(h)).collect())
            .collect(),
        fri_final_poly: fri_result.final_poly.iter().map(|&v| to_s(v)).collect(),
        grinding_nonce: grinding_nonce.to_string(),
        query_indices,
    }
}
