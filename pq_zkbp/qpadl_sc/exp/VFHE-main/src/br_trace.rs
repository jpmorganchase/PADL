use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;

use tfhe_goldilocks::field::GF;
use tfhe_goldilocks::gadget::decompose_element_unsigned;
use tfhe_goldilocks::ggsw::GgswCiphertext;
use tfhe_goldilocks::glwe::GlweCiphertext;
use tfhe_goldilocks::ntt::NttContext;
use tfhe_goldilocks::params::{LOG_B_PBS, L_PBS, N_POLY, T_PLAIN};
use tfhe_goldilocks::poly::Poly;

use crate::br_columns::{NUM_BR_COLS, NUM_BR_PRE_COLS};

pub trait BlindRotationKeyEntry {
    fn a_ntt(&self, row: usize, index: usize) -> GF;
    fn b_ntt(&self, row: usize, index: usize) -> GF;
}

impl BlindRotationKeyEntry for GgswCiphertext {
    fn a_ntt(&self, row: usize, index: usize) -> GF {
        self.rows_ntt[row].0[index]
    }

    fn b_ntt(&self, row: usize, index: usize) -> GF {
        self.rows_ntt[row].1[index]
    }
}

fn bsk_a_ntt<B: BlindRotationKeyEntry>(bsk: &[B], block: usize, row: usize, index: usize) -> GF {
    bsk.get(block)
        .map_or(GF::ZERO, |entry| entry.a_ntt(row, index))
}

fn bsk_b_ntt<B: BlindRotationKeyEntry>(bsk: &[B], block: usize, row: usize, index: usize) -> GF {
    bsk.get(block)
        .map_or(GF::ZERO, |entry| entry.b_ntt(row, index))
}

/// Compute is-zero gadget inverse hint for unsigned digits.
fn compute_inv_hint(digits: &[u64]) -> GF {
    let sigma_top = (255 - digits[4]) + (255 - digits[5]) + (255 - digits[6]) + (255 - digits[7]);
    if sigma_top == 0 {
        GF::ZERO
    } else {
        GF(sigma_top).inv()
    }
}

/// Result of blind rotation trace generation.
pub struct BlindRotateTraceData {
    pub witness: RowMajorMatrix<Goldilocks>,
    pub preprocessed: RowMajorMatrix<Goldilocks>,
    pub public_values: Vec<Goldilocks>,
    pub num_blocks: usize,
    pub final_acc: GlweCiphertext,
}

/// Generate the full blind rotation trace for `num_blocks` CMUX iterations.
///
/// The trace is padded to the next power of 2 in blocks (each block = 1024 rows).
/// Padding blocks use ã_i = 0 (identity rotation).
///
/// `a_tilde_values`: the modulus-switched rotation amounts (one per real CMUX block).
/// `b_prime`: the modulus-switched body value (used to rotate the test vector).
/// `test_vector`: the LUT polynomial (N_POLY coefficients).
/// `bsk`: bootstrapping key entries (one GGSW per real block; padding entries are added internally).
pub fn generate_blind_rotate_trace<B: BlindRotationKeyEntry>(
    a_tilde_values: &[u32],
    b_prime: u32,
    test_vector: &Poly,
    bsk: &[B],
) -> BlindRotateTraceData {
    generate_blind_rotate_trace_with_centering(a_tilde_values, b_prime, test_vector, bsk, true)
}

/// Generate a blind-rotation trace using HasteBoots' direct `X^{-b}` LUT rotation.
pub fn generate_haste_blind_rotate_trace<B: BlindRotationKeyEntry>(
    a_tilde_values: &[u32],
    b_prime: u32,
    test_vector: &Poly,
    bsk: &[B],
) -> BlindRotateTraceData {
    generate_blind_rotate_trace_with_centering(a_tilde_values, b_prime, test_vector, bsk, false)
}

fn generate_blind_rotate_trace_with_centering<B: BlindRotationKeyEntry>(
    a_tilde_values: &[u32],
    b_prime: u32,
    test_vector: &Poly,
    bsk: &[B],
    center_lut: bool,
) -> BlindRotateTraceData {
    let num_real_blocks = a_tilde_values.len();
    assert_eq!(bsk.len(), num_real_blocks);
    // Pad to next power of 2 in total blocks
    let num_blocks = num_real_blocks.next_power_of_two();
    let total_rows = num_blocks * N_POLY;

    let ctx = NttContext::new();

    // The legacy VFHE path uses half-box centering; HasteBoots rotates directly by -b.
    let half_box = if center_lut {
        (N_POLY / (2 * T_PLAIN as usize)) as u32
    } else {
        0
    };
    let b_shifted = (b_prime + half_box) % (2 * N_POLY as u32);
    let neg_b = ((2 * N_POLY as u32 - b_shifted) % (2 * N_POLY as u32)) as usize;
    let init_acc = GlweCiphertext {
        a: Poly::from_coeffs(vec![GF::ZERO; N_POLY]),
        b: test_vector.monomial_rotate(neg_b),
    };

    // Precompute init_b_ntt for boundary constraint
    let mut init_b_ntt_vals = init_acc.b.coeffs.clone();
    ctx.forward(&mut init_b_ntt_vals);

    // Precompute ψ powers for exponentiation chain
    let psi = ctx.psi_powers[1];

    // All ã_i values (real + padding with 0)
    let all_a_tilde: Vec<u32> = a_tilde_values
        .iter()
        .copied()
        .chain(std::iter::repeat(0).take(num_blocks - num_real_blocks))
        .collect();

    // ===== Simulate blind rotation, recording trace =====
    let mut witness = vec![Goldilocks::ZERO; total_rows * NUM_BR_COLS];
    let mut preprocessed = vec![Goldilocks::ZERO; total_rows * NUM_BR_PRE_COLS];

    let mut current_acc = init_acc;

    for block_idx in 0..num_blocks {
        let a_tilde = all_a_tilde[block_idx];

        // --- Compute CMUX for this block ---
        // Rotation
        let acc_rot = GlweCiphertext {
            a: current_acc.a.monomial_rotate(a_tilde as usize),
            b: current_acc.b.monomial_rotate(a_tilde as usize),
        };

        // Difference
        let delta_a_coeffs: Vec<GF> = (0..N_POLY)
            .map(|j| acc_rot.a.coeffs[j] - current_acc.a.coeffs[j])
            .collect();
        let delta_b_coeffs: Vec<GF> = (0..N_POLY)
            .map(|j| acc_rot.b.coeffs[j] - current_acc.b.coeffs[j])
            .collect();

        // Decomposition (unsigned)
        let decomp_a_digits: Vec<Vec<u64>> = (0..N_POLY)
            .map(|j| decompose_element_unsigned(delta_a_coeffs[j], LOG_B_PBS, L_PBS))
            .collect();
        let decomp_b_digits: Vec<Vec<u64>> = (0..N_POLY)
            .map(|j| decompose_element_unsigned(delta_b_coeffs[j], LOG_B_PBS, L_PBS))
            .collect();
        let inv_hint_a: Vec<GF> = (0..N_POLY)
            .map(|j| compute_inv_hint(&decomp_a_digits[j]))
            .collect();
        let inv_hint_b: Vec<GF> = (0..N_POLY)
            .map(|j| compute_inv_hint(&decomp_b_digits[j]))
            .collect();

        // NTT of decomposition polynomials
        let mut decomp_a_ntt: Vec<Vec<GF>> = Vec::with_capacity(L_PBS);
        for l in 0..L_PBS {
            let coeffs: Vec<GF> = (0..N_POLY).map(|j| GF(decomp_a_digits[j][l])).collect();
            let mut ntt = coeffs;
            ctx.forward(&mut ntt);
            decomp_a_ntt.push(ntt);
        }
        let mut decomp_b_ntt: Vec<Vec<GF>> = Vec::with_capacity(L_PBS);
        for l in 0..L_PBS {
            let coeffs: Vec<GF> = (0..N_POLY).map(|j| GF(decomp_b_digits[j][l])).collect();
            let mut ntt = coeffs;
            ctx.forward(&mut ntt);
            decomp_b_ntt.push(ntt);
        }

        // External product
        let mut ext_a_ntt = vec![GF::ZERO; N_POLY];
        let mut ext_b_ntt = vec![GF::ZERO; N_POLY];
        for l in 0..L_PBS {
            for j in 0..N_POLY {
                let da = decomp_a_ntt[l][j];
                let db = decomp_b_ntt[l][j];
                ext_a_ntt[j] = ext_a_ntt[j]
                    + da * bsk_a_ntt(bsk, block_idx, l, j)
                    + db * bsk_a_ntt(bsk, block_idx, L_PBS + l, j);
                ext_b_ntt[j] = ext_b_ntt[j]
                    + da * bsk_b_ntt(bsk, block_idx, l, j)
                    + db * bsk_b_ntt(bsk, block_idx, L_PBS + l, j);
            }
        }

        // ACC NTT forms
        let mut acc_a_ntt = current_acc.a.coeffs.clone();
        let mut acc_b_ntt = current_acc.b.coeffs.clone();
        ctx.forward(&mut acc_a_ntt);
        ctx.forward(&mut acc_b_ntt);

        let mut acc_rot_a_ntt = acc_rot.a.coeffs.clone();
        let mut acc_rot_b_ntt = acc_rot.b.coeffs.clone();
        ctx.forward(&mut acc_rot_a_ntt);
        ctx.forward(&mut acc_rot_b_ntt);

        // Next ACC
        let next_acc_a_ntt: Vec<GF> = (0..N_POLY).map(|j| acc_a_ntt[j] + ext_a_ntt[j]).collect();
        let next_acc_b_ntt: Vec<GF> = (0..N_POLY).map(|j| acc_b_ntt[j] + ext_b_ntt[j]).collect();

        // Twiddles
        let phi_val = psi.pow(a_tilde as u64);
        let rho_val = phi_val * phi_val;
        let twiddle_vals: Vec<GF> = (0..N_POLY)
            .map(|j| psi.pow(((2 * j as u64 + 1) * a_tilde as u64) % (2 * N_POLY as u64)))
            .collect();

        // Exponentiation chain: R_k = Π_{i=0}^{k-1} (1 + bit_i * (ψ^{2^i} - 1))
        let a_tilde_bits: Vec<u8> = (0..11).map(|k| ((a_tilde >> k) & 1) as u8).collect();
        let mut exp_chain = [GF(0); 11];
        {
            let mut r = GF(1); // R_0
            let mut p = psi; // ψ^{2^0}
            for k in 0..11 {
                // R_{k+1} = R_k * (1 + bit_k * (ψ^{2^k} - 1))
                if a_tilde_bits[k] == 1 {
                    r = r * p;
                }
                // else r stays the same (multiply by 1)
                exp_chain[k] = r;
                p = p * p; // ψ^{2^(k+1)}
            }
        }

        // --- Fill trace rows for this block ---
        let block_start = block_idx * N_POLY;

        for j in 0..N_POLY {
            let row_offset = (block_start + j) * NUM_BR_COLS;
            let mut col = 0;

            // CMUX core columns (no digit_bits):
            // acc_a_ntt, acc_b_ntt
            witness[row_offset + col] = Goldilocks::new(acc_a_ntt[j].0);
            col += 1;
            witness[row_offset + col] = Goldilocks::new(acc_b_ntt[j].0);
            col += 1;
            // acc_rot_a_ntt, acc_rot_b_ntt
            witness[row_offset + col] = Goldilocks::new(acc_rot_a_ntt[j].0);
            col += 1;
            witness[row_offset + col] = Goldilocks::new(acc_rot_b_ntt[j].0);
            col += 1;
            // delta_a_coeff, delta_b_coeff
            witness[row_offset + col] = Goldilocks::new(delta_a_coeffs[j].0);
            col += 1;
            witness[row_offset + col] = Goldilocks::new(delta_b_coeffs[j].0);
            col += 1;
            // decomp_a[8]
            for l in 0..8 {
                witness[row_offset + col] = Goldilocks::new(decomp_a_digits[j][l]);
                col += 1;
            }
            // decomp_b[8]
            for l in 0..8 {
                witness[row_offset + col] = Goldilocks::new(decomp_b_digits[j][l]);
                col += 1;
            }
            // inv_hint_a, inv_hint_b
            witness[row_offset + col] = Goldilocks::new(inv_hint_a[j].0);
            col += 1;
            witness[row_offset + col] = Goldilocks::new(inv_hint_b[j].0);
            col += 1;
            // decomp_a_ntt[8]
            for l in 0..8 {
                witness[row_offset + col] = Goldilocks::new(decomp_a_ntt[l][j].0);
                col += 1;
            }
            // decomp_b_ntt[8]
            for l in 0..8 {
                witness[row_offset + col] = Goldilocks::new(decomp_b_ntt[l][j].0);
                col += 1;
            }
            // ext_a_ntt, ext_b_ntt
            witness[row_offset + col] = Goldilocks::new(ext_a_ntt[j].0);
            col += 1;
            witness[row_offset + col] = Goldilocks::new(ext_b_ntt[j].0);
            col += 1;
            // next_acc_a_ntt, next_acc_b_ntt
            witness[row_offset + col] = Goldilocks::new(next_acc_a_ntt[j].0);
            col += 1;
            witness[row_offset + col] = Goldilocks::new(next_acc_b_ntt[j].0);
            col += 1;
            // twiddle, phi, rho
            witness[row_offset + col] = Goldilocks::new(twiddle_vals[j].0);
            col += 1;
            witness[row_offset + col] = Goldilocks::new(phi_val.0);
            col += 1;
            witness[row_offset + col] = Goldilocks::new(rho_val.0);
            col += 1;

            // range_mult_a[8] and range_mult_b[8] — filled in second pass
            col += 16;

            // a_tilde_bits[11]
            for k in 0..11 {
                witness[row_offset + col] = Goldilocks::new(a_tilde_bits[k] as u64);
                col += 1;
            }
            // exp_chain[11]
            for k in 0..11 {
                witness[row_offset + col] = Goldilocks::new(exp_chain[k].0);
                col += 1;
            }

            debug_assert_eq!(col, NUM_BR_COLS);

            // --- Preprocessed row ---
            let pre_offset = (block_start + j) * NUM_BR_PRE_COLS;
            // bsk_a_ntt[16]
            for l in 0..16 {
                preprocessed[pre_offset + l] = Goldilocks::new(bsk_a_ntt(bsk, block_idx, l, j).0);
            }
            // bsk_b_ntt[16]
            for l in 0..16 {
                preprocessed[pre_offset + 16 + l] =
                    Goldilocks::new(bsk_b_ntt(bsk, block_idx, l, j).0);
            }
            // is_last_in_block
            preprocessed[pre_offset + 32] = if j == N_POLY - 1 {
                Goldilocks::ONE
            } else {
                Goldilocks::ZERO
            };
            // block_id
            preprocessed[pre_offset + 33] = Goldilocks::new(block_idx as u64);
            // ntt_idx
            preprocessed[pre_offset + 34] = Goldilocks::new(j as u64);
            // is_first_block
            preprocessed[pre_offset + 35] = if block_idx == 0 {
                Goldilocks::ONE
            } else {
                Goldilocks::ZERO
            };
            // is_last_block
            preprocessed[pre_offset + 36] = if block_idx == num_blocks - 1 {
                Goldilocks::ONE
            } else {
                Goldilocks::ZERO
            };
            // range_table: row_index % 256
            preprocessed[pre_offset + 37] = Goldilocks::new(((block_start + j) % 256) as u64);
        }

        // --- Advance ACC for next block ---
        let mut next_a_coeffs = next_acc_a_ntt;
        let mut next_b_coeffs = next_acc_b_ntt;
        ctx.inverse(&mut next_a_coeffs);
        ctx.inverse(&mut next_b_coeffs);
        current_acc = GlweCiphertext {
            a: Poly::from_coeffs(next_a_coeffs),
            b: Poly::from_coeffs(next_b_coeffs),
        };
    }

    // === Second pass: compute range_mult histograms ===
    // For each digit column l ∈ [0, 16), and each table value v ∈ [0, 256),
    // count how many rows in the trace have digit_shifted == v.
    // Distribute that count to the rows where range_table == v.
    //
    // range_mult_a[l] column starts at offset 47 (after twiddle/phi/rho = col 46)
    // range_mult_b[l] column starts at offset 47 + 8 = 55
    let range_mult_col_offset = 47; // acc(2)+rot(2)+delta(2)+decomp(16)+inv_hint(2)+ntt(16)+ext(2)+next(2)+twiddle(3) = 47

    for digit_idx in 0..16 {
        // Build histogram: count[v] = number of rows where this digit == v
        let mut histogram = [0u64; 256];
        let digit_col = if digit_idx < 8 {
            6 + digit_idx // decomp_a starts at col 6
        } else {
            6 + 8 + (digit_idx - 8) // decomp_b starts at col 14
        };

        for row in 0..total_rows {
            let row_offset = row * NUM_BR_COLS;
            let digit_val = witness[row_offset + digit_col];
            // Unsigned digits are stored directly as u64 in [0, 255]
            let raw = digit_val.as_canonical_u64();
            debug_assert!(raw < 256, "digit out of range: {}", raw);
            histogram[raw as usize] += 1;
        }

        // Distribute histogram to range_mult columns:
        // At each row, range_table = row % 256. The range_mult for this digit
        // at row r is: histogram[range_table[r]] distributed across the
        // (total_rows / 256) rows that share this table value.
        // We place the full count at the FIRST row with each table value.
        let mult_col = range_mult_col_offset + digit_idx;
        let mut placed = [false; 256];
        for row in 0..total_rows {
            let table_val = (row % 256) as usize;
            if !placed[table_val] {
                witness[row * NUM_BR_COLS + mult_col] = Goldilocks::new(histogram[table_val]);
                placed[table_val] = true;
            }
            // else remains 0 (already initialized)
        }
    }

    let mut final_acc_a_ntt = current_acc.a.coeffs.clone();
    let mut final_acc_b_ntt = current_acc.b.coeffs.clone();
    ctx.forward(&mut final_acc_a_ntt);
    ctx.forward(&mut final_acc_b_ntt);
    let mut public_values = Vec::with_capacity(num_blocks + 3 * N_POLY);
    public_values.extend(
        all_a_tilde
            .iter()
            .map(|&value| Goldilocks::new(value as u64)),
    );
    public_values.extend(init_b_ntt_vals.iter().map(|value| Goldilocks::new(value.0)));
    public_values.extend(final_acc_a_ntt.iter().map(|value| Goldilocks::new(value.0)));
    public_values.extend(final_acc_b_ntt.iter().map(|value| Goldilocks::new(value.0)));

    BlindRotateTraceData {
        witness: RowMajorMatrix::new(witness, NUM_BR_COLS),
        preprocessed: RowMajorMatrix::new(preprocessed, NUM_BR_PRE_COLS),
        public_values,
        num_blocks,
        final_acc: current_acc,
    }
}

pub fn generate_br_public_values(
    a_tilde_values: &[u32],
    b_prime: u32,
    test_vector: &Poly,
    claimed_final_acc: &GlweCiphertext,
) -> Vec<Goldilocks> {
    generate_br_public_values_with_centering(
        a_tilde_values,
        b_prime,
        test_vector,
        claimed_final_acc,
        true,
    )
}

pub fn generate_haste_br_public_values(
    a_tilde_values: &[u32],
    b_prime: u32,
    test_vector: &Poly,
    claimed_final_acc: &GlweCiphertext,
) -> Vec<Goldilocks> {
    generate_br_public_values_with_centering(
        a_tilde_values,
        b_prime,
        test_vector,
        claimed_final_acc,
        false,
    )
}

fn generate_br_public_values_with_centering(
    a_tilde_values: &[u32],
    b_prime: u32,
    test_vector: &Poly,
    claimed_final_acc: &GlweCiphertext,
    center_lut: bool,
) -> Vec<Goldilocks> {
    let num_blocks = a_tilde_values.len().next_power_of_two();
    let mut values = Vec::with_capacity(num_blocks + 3 * N_POLY);
    values.extend(
        a_tilde_values
            .iter()
            .copied()
            .chain(std::iter::repeat(0).take(num_blocks - a_tilde_values.len()))
            .map(|value| Goldilocks::new(value as u64)),
    );

    let ctx = NttContext::new();
    let half_box = if center_lut {
        (N_POLY / (2 * T_PLAIN as usize)) as u32
    } else {
        0
    };
    let b_shifted = (b_prime + half_box) % (2 * N_POLY as u32);
    let neg_b = ((2 * N_POLY as u32 - b_shifted) % (2 * N_POLY as u32)) as usize;
    let mut init_b_ntt = test_vector.monomial_rotate(neg_b).coeffs;
    ctx.forward(&mut init_b_ntt);
    values.extend(init_b_ntt.iter().map(|value| Goldilocks::new(value.0)));

    let mut final_a_ntt = claimed_final_acc.a.coeffs.clone();
    let mut final_b_ntt = claimed_final_acc.b.coeffs.clone();
    ctx.forward(&mut final_a_ntt);
    ctx.forward(&mut final_b_ntt);
    values.extend(final_a_ntt.iter().map(|value| Goldilocks::new(value.0)));
    values.extend(final_b_ntt.iter().map(|value| Goldilocks::new(value.0)));
    values
}

pub fn br_periodic_columns_from_public_values(
    public_values: &[Goldilocks],
    num_blocks: usize,
) -> Vec<Vec<Goldilocks>> {
    assert_eq!(public_values.len(), num_blocks + 3 * N_POLY);
    let init_b_start = num_blocks;
    let final_a_start = init_b_start + N_POLY;
    let final_b_start = final_a_start + N_POLY;

    let a_tilde = public_values[..num_blocks]
        .iter()
        .flat_map(|&value| std::iter::repeat(value).take(N_POLY))
        .collect();
    let init_b_ntt = public_values[init_b_start..final_a_start].to_vec();
    let final_acc_a_ntt = public_values[final_a_start..final_b_start].to_vec();
    let final_acc_b_ntt = public_values[final_b_start..].to_vec();

    vec![a_tilde, init_b_ntt, final_acc_a_ntt, final_acc_b_ntt]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periodic_columns_are_derived_from_compact_public_values() {
        let num_blocks = 2;
        let mut public_values = (0..num_blocks + 3 * N_POLY)
            .map(|value| Goldilocks::new(value as u64))
            .collect::<Vec<_>>();
        let periodic = br_periodic_columns_from_public_values(&public_values, num_blocks);

        assert_eq!(periodic[0][0], public_values[0]);
        assert_eq!(periodic[0][N_POLY], public_values[1]);
        assert_eq!(periodic[1][0], public_values[num_blocks]);
        assert_eq!(periodic[2][0], public_values[num_blocks + N_POLY]);
        assert_eq!(periodic[3][0], public_values[num_blocks + 2 * N_POLY]);

        public_values[0] = Goldilocks::new(99);
        let changed = br_periodic_columns_from_public_values(&public_values, num_blocks);
        assert!(changed[0][..N_POLY]
            .iter()
            .all(|&value| value == public_values[0]));
        assert_ne!(changed[0], periodic[0]);
    }
}

pub fn generate_br_preprocessed<B: BlindRotationKeyEntry>(
    bsk: &[B],
) -> (RowMajorMatrix<Goldilocks>, usize) {
    let num_real_blocks = bsk.len();
    let num_blocks = num_real_blocks.next_power_of_two();
    let total_rows = num_blocks * N_POLY;

    let mut preprocessed = vec![Goldilocks::ZERO; total_rows * NUM_BR_PRE_COLS];

    for block_idx in 0..num_blocks {
        let block_start = block_idx * N_POLY;
        for j in 0..N_POLY {
            let pre_offset = (block_start + j) * NUM_BR_PRE_COLS;
            for l in 0..16 {
                preprocessed[pre_offset + l] = Goldilocks::new(bsk_a_ntt(bsk, block_idx, l, j).0);
                preprocessed[pre_offset + 16 + l] =
                    Goldilocks::new(bsk_b_ntt(bsk, block_idx, l, j).0);
            }
            preprocessed[pre_offset + 32] = if j == N_POLY - 1 {
                Goldilocks::ONE
            } else {
                Goldilocks::ZERO
            };
            preprocessed[pre_offset + 33] = Goldilocks::new(block_idx as u64);
            preprocessed[pre_offset + 34] = Goldilocks::new(j as u64);
            preprocessed[pre_offset + 35] = if block_idx == 0 {
                Goldilocks::ONE
            } else {
                Goldilocks::ZERO
            };
            preprocessed[pre_offset + 36] = if block_idx == num_blocks - 1 {
                Goldilocks::ONE
            } else {
                Goldilocks::ZERO
            };
            preprocessed[pre_offset + 37] = Goldilocks::new(((block_start + j) % 256) as u64);
        }
    }

    (
        RowMajorMatrix::new(preprocessed, NUM_BR_PRE_COLS),
        num_blocks,
    )
}
