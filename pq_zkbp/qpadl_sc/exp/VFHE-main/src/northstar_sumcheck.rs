//! Northstar sumcheck witness generation for VFHE (stacked approach).

use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{NorthstarProverData, NorthstarVerifierData};

use crate::config::{Challenge, PbsStarkConfig, Val};

/// Compute the Northstar prover data (R and Q_sc) using the stacked approach.
///
/// # Arguments
/// * `trace` - The full witness trace matrix
/// * `f_col_indices` - Column indices for coefficient-domain polynomials (decomp_a)
/// * `g_col_indices` - Column indices for NTT-domain polynomials (decomp_a_ntt)
/// * `alpha_sc` - Evaluation point challenge
/// * `eta` - Block-batching challenge
/// * `rho` - Level-batching challenge
/// * `log_block_size` - log2 of per-block NTT size (e.g., 10 for N=1024)
/// * `num_blocks` - number of blocks (k)
/// * `psi_block` - 2N-th root of unity for the per-block negacyclic NTT
pub fn compute_northstar_witness(
    trace: &RowMajorMatrix<Val>,
    f_col_indices: &[usize],
    g_col_indices: &[usize],
    alpha_sc: Challenge,
    eta: Challenge,
    rho: Challenge,
    log_block_size: usize,
    num_blocks: usize,
    psi_block: Val,
) -> NorthstarProverData<PbsStarkConfig> {
    assert_eq!(f_col_indices.len(), g_col_indices.len());
    let m = f_col_indices.len(); // number of decomposition levels
    let n_block = 1usize << log_block_size; // per-block size (N = 1024)
    let kn = num_blocks * n_block; // total trace height
    assert_eq!(trace.height(), kn);
    let log_kn = p3_util::log2_strict_usize(kn);

    let dft = Radix2DitParallel::<Val>::default();

    // Full trace domain generator
    let omega_kn = Val::two_adic_generator(log_kn);

    // Per-block N-th root: omega_N = omega_kn^num_blocks
    // (since omega_kn^kN = 1, (omega_kn^k)^N = 1)
    let omega_n = Val::two_adic_generator(log_block_size);

    // Pre-compute alpha powers (alpha^0, ..., alpha^{N-1}) — reused for all blocks
    let alpha_n = alpha_sc.exp_u64(n_block as u64);

    // Build sigma'_alpha and Lambda'_alpha evaluations on the trace domain H (size kN).
    // sigma'_alpha(omega_kn^{iN+j}) = eta^i * alpha^j
    // Lambda'_alpha(omega_kn^{iN+j}) = eta^i * L_{psi_block * omega_n^j}(alpha_sc)
    //
    // where L_{psi_block * omega_n^j}(alpha) = -(psi_block * omega_n^j) * (1 + alpha^N) / (N * (alpha - psi_block * omega_n^j))

    let n_field = Challenge::from(Val::from_u64(n_block as u64));
    let one_plus_alpha_n = Challenge::ONE + alpha_n;
    let psi_ext = Challenge::from(psi_block);

    // Pre-compute per-position-in-block values (j = 0..N-1)
    let mut alpha_powers: Vec<Challenge> = Vec::with_capacity(n_block);
    let mut lagrange_coset: Vec<Challenge> = Vec::with_capacity(n_block);
    {
        let mut alpha_pow = Challenge::ONE;
        let mut omega_n_pow = Val::ONE;
        for _j in 0..n_block {
            alpha_powers.push(alpha_pow);

            // L_{psi * omega_n^j}(alpha) = -(psi * omega_n^j) * (1 + alpha^N) / (N * (alpha - psi * omega_n^j))
            let psi_omega_j = Challenge::from(psi_block * omega_n_pow);
            let num = -psi_omega_j * one_plus_alpha_n;
            let denom = n_field * (alpha_sc - psi_omega_j);
            lagrange_coset.push(num * denom.inverse());

            alpha_pow *= alpha_sc;
            omega_n_pow *= omega_n;
        }
    }

    // Build full sigma' and Lambda' on H (size kN), then evaluate on doubled domain.
    // sigma'[iN+j] = eta^i * alpha^j
    // Lambda'[iN+j] = eta^i * lagrange_coset[j]
    let mut sigma_on_h: Vec<Challenge> = vec![Challenge::ZERO; kn];
    let mut lambda_on_h: Vec<Challenge> = vec![Challenge::ZERO; kn];
    {
        let mut eta_power = Challenge::ONE;
        for i in 0..num_blocks {
            for j in 0..n_block {
                sigma_on_h[i * n_block + j] = eta_power * alpha_powers[j];
                lambda_on_h[i * n_block + j] = eta_power * lagrange_coset[j];
            }
            eta_power *= eta;
        }
    }

    // Get sigma' and Lambda' as polynomials (iDFT from evaluations on H).
    // Then evaluate on doubled domain (size 2kN) for multiplication.
    let log_2kn = log_kn + 1;
    let two_kn = 1usize << log_2kn;

    let sigma_coeffs = idft_extension(&sigma_on_h, log_kn);
    let lambda_coeffs = idft_extension(&lambda_on_h, log_kn);

    // Zero-pad to 2kN and DFT to get evaluations on doubled domain
    let mut sigma_padded = sigma_coeffs;
    sigma_padded.resize(two_kn, Challenge::ZERO);
    let sigma_2kn = dft_extension(&sigma_padded, log_2kn);

    let mut lambda_padded = lambda_coeffs;
    lambda_padded.resize(two_kn, Challenge::ZERO);
    let lambda_2kn = dft_extension(&lambda_padded, log_2kn);

    // For each level l, evaluate f_l and g_l on the doubled domain (size 2kN)
    // Then compute P = sum_l rho^l * [f_l * sigma' - g_l * Lambda']
    let mut p_evals_2kn: Vec<Challenge> = vec![Challenge::ZERO; two_kn];
    let mut rho_power = Challenge::ONE;

    for l in 0..m {
        // Extract column values from trace (evaluations on H of size kN)
        let f_col: Vec<Val> = (0..kn).map(|row| trace.get(row, f_col_indices[l]).unwrap()).collect();
        let g_col: Vec<Val> = (0..kn).map(|row| trace.get(row, g_col_indices[l]).unwrap()).collect();

        // iDFT to coefficients, zero-pad to 2kN, DFT to doubled domain
        let f_coeff = dft.idft(f_col);
        let g_coeff = dft.idft(g_col);

        let mut f_padded = f_coeff;
        f_padded.resize(two_kn, Val::ZERO);
        let f_2kn = dft.dft(f_padded);

        let mut g_padded = g_coeff;
        g_padded.resize(two_kn, Val::ZERO);
        let g_2kn = dft.dft(g_padded);

        // P += rho^l * [f_l * sigma' - g_l * Lambda']
        // Note: f = decomp_a (coeff domain) goes with sigma' (which encodes alpha^j)
        //       g = decomp_a_ntt (NTT domain) goes with Lambda' (which encodes Lagrange of coset)
        for j in 0..two_kn {
            let f_ext = Challenge::from(f_2kn[j]);
            let g_ext = Challenge::from(g_2kn[j]);
            p_evals_2kn[j] += rho_power * (f_ext * sigma_2kn[j] - g_ext * lambda_2kn[j]);
        }
        rho_power *= rho;
    }

    // iDFT to get P coefficients (degree < 2kN - 1)
    let p_coeffs = idft_extension(&p_evals_2kn, log_2kn);

    // Aurora decomposition: P(X) = Q_sc(X) * (X^{kN} - 1) + X * R(X)
    // Polynomial long division of P by (X^{kN} - 1):
    //   q_i = p_{i+kN} for i < kN
    //   rem_i = p_i + q_i for i < kN
    //   rem(0) = 0 (zero-sum), so R(X) = rem(X) / X

    let mut q_sc_coeffs: Vec<Challenge> = vec![Challenge::ZERO; kn];
    for i in 0..kn {
        if i + kn < p_coeffs.len() {
            q_sc_coeffs[i] = p_coeffs[i + kn];
        }
    }

    let mut rem_coeffs: Vec<Challenge> = vec![Challenge::ZERO; kn];
    for i in 0..kn {
        let p_i = if i < p_coeffs.len() { p_coeffs[i] } else { Challenge::ZERO };
        rem_coeffs[i] = p_i + q_sc_coeffs[i];
    }

    // Verify rem(0) = 0
    debug_assert!(
        rem_coeffs[0] == Challenge::ZERO,
        "Northstar stacked: remainder constant term is non-zero: {:?}",
        rem_coeffs[0]
    );

    // R(X) = rem(X) / X: shift coefficients down
    let mut r_coeffs: Vec<Challenge> = vec![Challenge::ZERO; kn];
    for i in 0..kn - 1 {
        r_coeffs[i] = rem_coeffs[i + 1];
    }

    // Commit shifted copies as degree-bound witnesses. FRI proves all four
    // polynomials have degree < kN, while XR = X * R and XQ = X * Q force
    // the X^{kN-1} coefficients of R and Q to vanish.
    let mut xr_coeffs: Vec<Challenge> = vec![Challenge::ZERO; kn];
    let mut xq_sc_coeffs: Vec<Challenge> = vec![Challenge::ZERO; kn];
    for i in 0..kn - 1 {
        xr_coeffs[i + 1] = r_coeffs[i];
        xq_sc_coeffs[i + 1] = q_sc_coeffs[i];
    }

    // Convert R, Q_sc, XR, and XQ_sc to evaluations on H (for commitment)
    let r_evals = dft_extension(&r_coeffs, log_kn);
    let q_sc_evals = dft_extension(&q_sc_coeffs, log_kn);
    let xr_evals = dft_extension(&xr_coeffs, log_kn);
    let xq_sc_evals = dft_extension(&xq_sc_coeffs, log_kn);

    // Build the base-field matrix [R, Q_sc, XR, XQ_sc] on H.
    let dim = 2;
    let num_cols = 4 * dim;
    let mut rq_values: Vec<Val> = vec![Val::ZERO; kn * num_cols];
    for row in 0..kn {
        let r_bases = ext_to_bases(r_evals[row]);
        let q_bases = ext_to_bases(q_sc_evals[row]);
        let xr_bases = ext_to_bases(xr_evals[row]);
        let xq_bases = ext_to_bases(xq_sc_evals[row]);
        rq_values[row * num_cols] = r_bases[0];
        rq_values[row * num_cols + 1] = r_bases[1];
        rq_values[row * num_cols + 2] = q_bases[0];
        rq_values[row * num_cols + 3] = q_bases[1];
        rq_values[row * num_cols + 4] = xr_bases[0];
        rq_values[row * num_cols + 5] = xr_bases[1];
        rq_values[row * num_cols + 6] = xq_bases[0];
        rq_values[row * num_cols + 7] = xq_bases[1];
    }

    NorthstarProverData {
        rq_trace: RowMajorMatrix::new(rq_values, num_cols),
    }
}

/// Build the NorthstarVerifierData for the stacked approach.
pub fn make_northstar_verifier_data(
    f_col_indices: Vec<usize>,
    g_col_indices: Vec<usize>,
    log_block_size: usize,
    num_blocks: usize,
    psi_block: Val,
    omega_kn: Val,
) -> NorthstarVerifierData {
    NorthstarVerifierData {
        f_col_indices,
        g_col_indices,
        log_n: log_block_size,
        num_blocks,
        psi_raw: psi_block.as_canonical_u64(),
        omega_kn_raw: omega_kn.as_canonical_u64(),
    }
}

// --- Helper functions for extension-field DFT/iDFT ---

type Ext = BinomialExtensionField<Goldilocks, 2>;

fn ext_to_bases(e: Ext) -> [Val; 2] {
    let slice = e.as_basis_coefficients_slice();
    [slice[0], slice[1]]
}

fn bases_to_ext(a: Val, b: Val) -> Ext {
    Ext::from_basis_coefficients_fn(|i| if i == 0 { a } else { b })
}

/// DFT of extension-field coefficients using component-wise base-field DFT.
fn dft_extension(coeffs: &[Ext], log_n: usize) -> Vec<Ext> {
    let n = 1usize << log_n;
    let dft = Radix2DitParallel::<Val>::default();

    // Split into 2 base-field vectors
    let mut comp0: Vec<Val> = Vec::with_capacity(n);
    let mut comp1: Vec<Val> = Vec::with_capacity(n);
    for &c in coeffs.iter().take(n) {
        let bases = ext_to_bases(c);
        comp0.push(bases[0]);
        comp1.push(bases[1]);
    }
    // Pad if needed
    comp0.resize(n, Val::ZERO);
    comp1.resize(n, Val::ZERO);

    let eval0 = dft.dft(comp0);
    let eval1 = dft.dft(comp1);

    eval0
        .iter()
        .zip(eval1.iter())
        .map(|(&a, &b)| bases_to_ext(a, b))
        .collect()
}

/// iDFT of extension-field evaluations using component-wise base-field iDFT.
fn idft_extension(evals: &[Ext], log_n: usize) -> Vec<Ext> {
    let n = 1usize << log_n;
    let dft = Radix2DitParallel::<Val>::default();

    let mut comp0: Vec<Val> = Vec::with_capacity(n);
    let mut comp1: Vec<Val> = Vec::with_capacity(n);
    for &e in evals.iter().take(n) {
        let bases = ext_to_bases(e);
        comp0.push(bases[0]);
        comp1.push(bases[1]);
    }
    comp0.resize(n, Val::ZERO);
    comp1.resize(n, Val::ZERO);

    let coeff0 = dft.idft(comp0);
    let coeff1 = dft.idft(comp1);

    coeff0
        .iter()
        .zip(coeff1.iter())
        .map(|(&a, &b)| bases_to_ext(a, b))
        .collect()
}
