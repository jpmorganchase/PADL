use core::borrow::Borrow;
use std::borrow::Cow;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_lookup::{InteractionBuilder, Count};
use p3_matrix::dense::RowMajorMatrix;

use crate::br_columns::{BlindRotateCols, BlindRotatePreCols, NUM_BR_COLS, NUM_BR_PRE_COLS};
use crate::br_trace::br_periodic_columns_from_public_values;

/// Precomputed constants: ψ^{2^k} − 1 for k = 0..10.
fn psi_power_minus_one() -> [Goldilocks; 11] {
    use tfhe_goldilocks::ntt::NttContext;
    let ctx = NttContext::new();
    let psi = ctx.psi_powers[1];
    let mut result = [Goldilocks::ZERO; 11];
    let mut p = psi;
    for k in 0..11 {
        result[k] = Goldilocks::new(p.0) - Goldilocks::ONE;
        p = p * p;
    }
    result
}

/// Optimized AIR for blind rotation with LogUp range checks.
///
/// Range proofs use LogUp lookup against a preprocessed range table.
#[derive(Debug, Clone)]
pub struct BlindRotateAir {
    pub preprocessed: RowMajorMatrix<Goldilocks>,
    pub num_blocks: usize,
    pub public_values: Vec<Goldilocks>,
}

impl BaseAir<Goldilocks> for BlindRotateAir {
    fn width(&self) -> usize {
        NUM_BR_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_BR_PRE_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Goldilocks>> {
        Some(self.preprocessed.clone())
    }

    fn num_public_values(&self) -> usize {
        self.num_blocks + 3 * tfhe_goldilocks::params::N_POLY
    }

    fn num_periodic_columns(&self) -> usize {
        4
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Goldilocks>]> {
        Cow::Owned(br_periodic_columns_from_public_values(
            &self.public_values,
            self.num_blocks,
        ))
    }
}

impl<AB: AirBuilder<F = Goldilocks> + InteractionBuilder> Air<AB> for BlindRotateAir {
    fn eval(&self, builder: &mut AB) {
        // --- Extract preprocessed values ---
        let is_last: AB::Var;
        let bsk_a_ntt: [AB::Var; 16];
        let bsk_b_ntt: [AB::Var; 16];
        let range_table: AB::Var;
        {
            let prep = builder.preprocessed();
            let pre: &BlindRotatePreCols<AB::Var> = prep.current_slice().borrow();
            is_last = pre.is_last_in_block;
            bsk_a_ntt = pre.bsk_a_ntt;
            bsk_b_ntt = pre.bsk_b_ntt;
            range_table = pre.range_table;
        }

        // --- Main trace ---
        let main = builder.main();
        let local: &BlindRotateCols<AB::Var> = main.current_slice().borrow();
        let periodic = builder.periodic_values();
        let a_tilde: AB::Expr = periodic[0].into();
        let init_b_ntt: AB::Expr = periodic[1].into();
        let final_acc_a_ntt: AB::Expr = periodic[2].into();
        let final_acc_b_ntt: AB::Expr = periodic[3].into();

        let base = AB::F::from_u32(256);
        let psi_consts = psi_power_minus_one();

        // ========================================
        // Public input binding
        // sum(a_tilde_bits[k] * 2^k) = public a_tilde periodic value
        // ========================================
        {
            let mut recomp: AB::Expr = AB::Expr::ZERO;
            let mut pow2 = AB::F::ONE;
            for k in 0..11 {
                let bit: AB::Expr = local.a_tilde_bits[k].into();
                recomp = recomp + bit * pow2;
                pow2 = pow2 * AB::F::TWO;
            }
            builder.assert_zero(recomp - a_tilde.clone());
        }

        // ========================================
        // Binary exponentiation chain
        // ========================================
        for k in 0..11 {
            builder.assert_bool(local.a_tilde_bits[k]);
        }
        {
            let bit0: AB::Expr = local.a_tilde_bits[0].into();
            let expected_r1: AB::Expr = AB::Expr::ONE + bit0 * psi_consts[0];
            let r1: AB::Expr = local.exp_chain[0].into();
            builder.assert_zero(r1 - expected_r1);

            for k in 1..11 {
                let r_prev: AB::Expr = local.exp_chain[k - 1].into();
                let bit_k: AB::Expr = local.a_tilde_bits[k].into();
                let factor: AB::Expr = AB::Expr::ONE + bit_k * psi_consts[k];
                let expected: AB::Expr = r_prev * factor;
                let r_k: AB::Expr = local.exp_chain[k].into();
                builder.assert_zero(r_k - expected);
            }

            let r11: AB::Expr = local.exp_chain[10].into();
            let phi: AB::Expr = local.phi.into();
            builder.assert_zero(phi - r11);
        }

        // ========================================
        // rho = phi²
        // ========================================
        let phi: AB::Expr = local.phi.into();
        let rho: AB::Expr = local.rho.into();
        builder.assert_zero(rho.clone() - phi.clone() * phi.clone());

        // ========================================
        // Twiddle initial
        // ========================================
        let twiddle: AB::Expr = local.twiddle.into();
        builder.when_first_row().assert_zero(twiddle - phi.clone());

        // ========================================
        // Transition constraints
        // ========================================
        {
            let next_main = builder.main();
            let next: &BlindRotateCols<AB::Var> = next_main.next_slice().borrow();

            let is_last_expr: AB::Expr = is_last.into();
            let is_not_last: AB::Expr = AB::Expr::ONE - is_last_expr.clone();

            // Intra-block: twiddle geometric step
            let local_twiddle: AB::Expr = local.twiddle.into();
            let next_twiddle: AB::Expr = next.twiddle.into();
            builder.when_transition().assert_zero(
                is_not_last.clone() * (next_twiddle.clone() - local_twiddle * rho.clone()),
            );

            // Constancy: phi, rho
            let next_phi: AB::Expr = next.phi.into();
            let next_rho: AB::Expr = next.rho.into();
            builder.when_transition().assert_zero(is_not_last.clone() * (next_phi.clone() - phi.clone()));
            builder.when_transition().assert_zero(is_not_last.clone() * (next_rho - rho));

            // Constancy: a_tilde_bits
            for k in 0..11 {
                let local_bit: AB::Expr = local.a_tilde_bits[k].into();
                let next_bit: AB::Expr = next.a_tilde_bits[k].into();
                builder.when_transition().assert_zero(is_not_last.clone() * (next_bit - local_bit));
            }

            // Constancy: exp_chain
            for k in 0..11 {
                let local_r: AB::Expr = local.exp_chain[k].into();
                let next_r: AB::Expr = next.exp_chain[k].into();
                builder.when_transition().assert_zero(is_not_last.clone() * (next_r - local_r));
            }

            // Inter-block: twiddle reset
            builder.when_transition().assert_zero(is_last_expr * (next_twiddle - next_phi));
        }

        // ========================================
        // Rotation correctness
        // ========================================
        let local_twiddle: AB::Expr = local.twiddle.into();
        let acc_a: AB::Expr = local.acc_a_ntt.into();
        let acc_b: AB::Expr = local.acc_b_ntt.into();
        let rot_a: AB::Expr = local.acc_rot_a_ntt.into();
        let rot_b: AB::Expr = local.acc_rot_b_ntt.into();
        builder.assert_zero(rot_a - local_twiddle.clone() * acc_a.clone());
        builder.assert_zero(rot_b - local_twiddle * acc_b.clone());

        // ========================================
        // Delta binding (NTT domain)
        // Links decomposition to the actual rotation delta.
        // ========================================
        {
            let mut recomp_ntt: AB::Expr = AB::Expr::ZERO;
            let mut b_pow = AB::F::ONE;
            for l in 0..8 {
                let d_ntt: AB::Expr = local.decomp_a_ntt[l].into();
                recomp_ntt = recomp_ntt + d_ntt * b_pow.clone();
                b_pow = b_pow * base.clone();
            }
            let rot_a: AB::Expr = local.acc_rot_a_ntt.into();
            let acc_a: AB::Expr = local.acc_a_ntt.into();
            builder.assert_zero(recomp_ntt - (rot_a - acc_a));
        }
        {
            let mut recomp_ntt: AB::Expr = AB::Expr::ZERO;
            let mut b_pow = AB::F::ONE;
            for l in 0..8 {
                let d_ntt: AB::Expr = local.decomp_b_ntt[l].into();
                recomp_ntt = recomp_ntt + d_ntt * b_pow.clone();
                b_pow = b_pow * base.clone();
            }
            let rot_b: AB::Expr = local.acc_rot_b_ntt.into();
            let acc_b: AB::Expr = local.acc_b_ntt.into();
            builder.assert_zero(recomp_ntt - (rot_b - acc_b));
        }

        // ========================================
        // Recomposition (unsigned, no carry)
        // ========================================
        {
            let mut recomp: AB::Expr = AB::Expr::ZERO;
            let mut b_pow = AB::F::ONE;
            for l in 0..8 {
                let digit: AB::Expr = local.decomp_a[l].into();
                recomp = recomp + digit * b_pow.clone();
                b_pow = b_pow * base.clone();
            }
            let delta_a: AB::Expr = local.delta_a_coeff.into();
            builder.assert_zero(delta_a - recomp);
        }
        {
            let mut recomp: AB::Expr = AB::Expr::ZERO;
            let mut b_pow = AB::F::ONE;
            for l in 0..8 {
                let digit: AB::Expr = local.decomp_b[l].into();
                recomp = recomp + digit * b_pow.clone();
                b_pow = b_pow * base.clone();
            }
            let delta_b: AB::Expr = local.delta_b_coeff.into();
            builder.assert_zero(delta_b - recomp);
        }

        // ========================================
        // Digit range proof via LogUp
        // ========================================
        // Each unsigned digit d ∈ [0, 255] is looked up against range_table.
        for l in 0..8 {
            let digit: AB::Expr = local.decomp_a[l].into();
            let table_val: AB::Expr = range_table.into();
            let mult: AB::Expr = local.range_mult_a[l].into();
            builder.push_local_interaction(vec![
                (vec![digit], Count::bounded(AB::Expr::ONE, 1)),
                (vec![table_val], Count::provided(-mult)),
            ]);
        }
        for l in 0..8 {
            let digit: AB::Expr = local.decomp_b[l].into();
            let table_val: AB::Expr = range_table.into();
            let mult: AB::Expr = local.range_mult_b[l].into();
            builder.push_local_interaction(vec![
                (vec![digit], Count::bounded(AB::Expr::ONE, 1)),
                (vec![table_val], Count::provided(-mult)),
            ]);
        }

        // ========================================
        // Integer range check via is-zero gadget
        // ========================================
        // For Δ_a:
        {
            let d0: AB::Expr = local.decomp_a[0].into();
            let d1: AB::Expr = local.decomp_a[1].into();
            let d2: AB::Expr = local.decomp_a[2].into();
            let d3: AB::Expr = local.decomp_a[3].into();
            let d4: AB::Expr = local.decomp_a[4].into();
            let d5: AB::Expr = local.decomp_a[5].into();
            let d6: AB::Expr = local.decomp_a[6].into();
            let d7: AB::Expr = local.decomp_a[7].into();
            let sigma_top: AB::Expr =
                AB::Expr::ZERO + AB::F::from_u32(1020) - d4 - d5 - d6 - d7;
            let sigma_bot: AB::Expr = d0 + d1 + d2 + d3;
            let w: AB::Expr = local.inv_hint_a.into();
            let z: AB::Expr = AB::Expr::ONE - sigma_top.clone() * w;
            builder.assert_zero(sigma_top * z.clone());
            builder.assert_zero(z * sigma_bot);
        }
        // For Δ_b:
        {
            let d0: AB::Expr = local.decomp_b[0].into();
            let d1: AB::Expr = local.decomp_b[1].into();
            let d2: AB::Expr = local.decomp_b[2].into();
            let d3: AB::Expr = local.decomp_b[3].into();
            let d4: AB::Expr = local.decomp_b[4].into();
            let d5: AB::Expr = local.decomp_b[5].into();
            let d6: AB::Expr = local.decomp_b[6].into();
            let d7: AB::Expr = local.decomp_b[7].into();
            let sigma_top: AB::Expr =
                AB::Expr::ZERO + AB::F::from_u32(1020) - d4 - d5 - d6 - d7;
            let sigma_bot: AB::Expr = d0 + d1 + d2 + d3;
            let w: AB::Expr = local.inv_hint_b.into();
            let z: AB::Expr = AB::Expr::ONE - sigma_top.clone() * w;
            builder.assert_zero(sigma_top * z.clone());
            builder.assert_zero(z * sigma_bot);
        }

        // ========================================
        // External product (NTT domain)
        // ========================================
        {
            let mut sum_a: AB::Expr = AB::Expr::ZERO;
            for l in 0..8 {
                let d_a: AB::Expr = local.decomp_a_ntt[l].into();
                let b_a: AB::Expr = bsk_a_ntt[l].into();
                sum_a = sum_a + d_a * b_a;
            }
            for l in 0..8 {
                let d_b: AB::Expr = local.decomp_b_ntt[l].into();
                let b_a: AB::Expr = bsk_a_ntt[8 + l].into();
                sum_a = sum_a + d_b * b_a;
            }
            let ext_a: AB::Expr = local.ext_a_ntt.into();
            builder.assert_zero(ext_a - sum_a);
        }
        {
            let mut sum_b: AB::Expr = AB::Expr::ZERO;
            for l in 0..8 {
                let d_a: AB::Expr = local.decomp_a_ntt[l].into();
                let b_b: AB::Expr = bsk_b_ntt[l].into();
                sum_b = sum_b + d_a * b_b;
            }
            for l in 0..8 {
                let d_b: AB::Expr = local.decomp_b_ntt[l].into();
                let b_b: AB::Expr = bsk_b_ntt[8 + l].into();
                sum_b = sum_b + d_b * b_b;
            }
            let ext_b: AB::Expr = local.ext_b_ntt.into();
            builder.assert_zero(ext_b - sum_b);
        }

        // ========================================
        // CMUX addition
        // ========================================
        let ext_a: AB::Expr = local.ext_a_ntt.into();
        let ext_b: AB::Expr = local.ext_b_ntt.into();
        let next_a: AB::Expr = local.next_acc_a_ntt.into();
        let next_b: AB::Expr = local.next_acc_b_ntt.into();
        builder.assert_zero(next_a.clone() - (acc_a.clone() + ext_a));
        builder.assert_zero(next_b.clone() - (acc_b.clone() + ext_b));

        // Bind the final accumulator to the verifier-supplied output statement.
        {
            let prep = builder.preprocessed();
            let pre: &BlindRotatePreCols<AB::Var> = prep.current_slice().borrow();
            let is_last_block: AB::Expr = pre.is_last_block.into();
            builder.assert_zero(
                is_last_block.clone() * (next_a.clone() - final_acc_a_ntt),
            );
            builder.assert_zero(is_last_block * (next_b.clone() - final_acc_b_ntt));
        }

        // ========================================
        // Initial ACC boundary
        // ========================================
        {
            let prep = builder.preprocessed();
            let pre: &BlindRotatePreCols<AB::Var> = prep.current_slice().borrow();
            let is_first_block: AB::Expr = pre.is_first_block.into();
            // Mask must be zero at block 0
            builder.assert_zero(is_first_block.clone() * acc_a.clone());
            // Body must equal NTT(lut · X^{-b'}) at block 0
            builder.assert_zero(is_first_block * (acc_b.clone() - init_b_ntt));
        }

        // ========================================
        // ACC chaining via LogUp
        // ========================================
        {
            let prep = builder.preprocessed();
            let pre: &BlindRotatePreCols<AB::Var> = prep.current_slice().borrow();
            let block_id: AB::Expr = pre.block_id.into();
            let ntt_idx: AB::Expr = pre.ntt_idx.into();
            let is_first_block: AB::Expr = pre.is_first_block.into();
            let is_last_block: AB::Expr = pre.is_last_block.into();

            let send_mult: AB::Expr = AB::Expr::ONE - is_last_block;
            let recv_mult: AB::Expr = AB::Expr::ONE - is_first_block;

            builder.push_local_interaction(vec![
                (
                    vec![block_id.clone(), ntt_idx.clone(), next_a, next_b],
                    Count::bounded(send_mult, 1),
                ),
                (
                    vec![block_id - AB::Expr::ONE, ntt_idx, acc_a, acc_b],
                    Count::bounded(-recv_mult, 1),
                ),
            ]);
        }
    }
}
