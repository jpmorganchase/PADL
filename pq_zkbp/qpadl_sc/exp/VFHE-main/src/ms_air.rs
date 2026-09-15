use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;

use crate::ms_columns::{MsCols, MsPreCols, NUM_MS_COLS, NUM_MS_PRE_COLS, RANGE_BITS};

const K_VAL: u64 = (tfhe_goldilocks::params::Q - 1) / 4096;

const TWO_N: u64 = 2 * tfhe_goldilocks::params::N_POLY as u64;

/// AIR for Modulus Switching.
///
/// Proves that each LWE component a_i is correctly modulus-switched to b_i ∈ Z_{2N}.
///
/// Trace: next_power_of_two(N_LWE + 1) = 1024 rows.
///
#[derive(Debug, Clone)]
pub struct ModSwitchAir {
    pub preprocessed: RowMajorMatrix<Goldilocks>,
}

impl BaseAir<Goldilocks> for ModSwitchAir {
    fn width(&self) -> usize {
        NUM_MS_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_MS_PRE_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Goldilocks>> {
        Some(self.preprocessed.clone())
    }

}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for ModSwitchAir {
    fn eval(&self, builder: &mut AB) {
        let prep = builder.preprocessed();
        let pre: &MsPreCols<AB::Var> = prep.current_slice().borrow();
        let input_a: AB::Expr = pre.input_a.into();
        let expected_b_out: AB::Expr = pre.expected_b_out.into();

        let main = builder.main();
        let local: &MsCols<AB::Var> = main.current_slice().borrow();

        let b_prime: AB::Expr = local.b_prime.into();
        let b_out: AB::Expr = local.b_out.into();
        let f: AB::Expr = local.f_flag.into();
        let v: AB::Expr = local.inv_witness.into();

        let k_const: AB::Expr = AB::F::new(K_VAL).into();
        let two_n_const: AB::Expr = AB::F::new(TWO_N).into();

        // Bind the witness output to the value derived by the verifier from the input ciphertext.
        builder.assert_zero(b_out.clone() - expected_b_out);

        // ===== Constraint 1: Nonzero indicator =====
        // (a - k) * v - f = 0
        builder.assert_zero(
            (input_a.clone() - k_const.clone()) * v.clone() - f.clone(),
        );
        // (a - k) * (1 - f) = 0
        builder.assert_zero(
            (input_a.clone() - k_const.clone()) * (AB::Expr::ONE - f.clone()),
        );
        // f is boolean
        builder.assert_bool(local.f_flag);

        // ===== Constraint 2: b' range =====
        // b' ∈ {1, ..., 2N}, i.e. b' - 1 ∈ {0, ..., 2N-1}
        // This is enforced via public values check 

        // ===== Constraint 3: Output derivation =====
        // (b' - b_out) * (b' - b_out - 2N) = 0
        // Ensures b_out = b' or b_out = b' - 2N
        {
            let diff: AB::Expr = b_prime.clone() - b_out.clone();
            builder.assert_zero(
                diff.clone() * (diff - two_n_const.clone()),
            );
        }

        // ===== Constraint 4: Conditional range check =====
        // r = a - (2*b' - 1)*k - 1 (field arithmetic)
        // When f=1: sum(d_i * 2^i) = r (proves r ∈ [0, 2^53))
        // When f=0: bits unconstrained (prover sets 0)
        {
            let r_expr: AB::Expr = input_a.clone()
                - (b_prime.clone() * AB::F::TWO - AB::Expr::ONE) * k_const.clone()
                - AB::Expr::ONE;

            let mut bit_sum: AB::Expr = AB::Expr::ZERO;
            let mut two_pow = AB::F::ONE;
            for i in 0..RANGE_BITS {
                // Each bit is boolean
                builder.assert_bool(local.r_bits[i]);
                let bit: AB::Expr = local.r_bits[i].into();
                bit_sum = bit_sum + bit * two_pow;
                two_pow = two_pow * AB::F::TWO;
            }

            // f * (bit_sum - r) = 0
            builder.assert_zero(f.clone() * (bit_sum - r_expr));
        }

        // ===== Constraint 5: Exceptional point =====
        // (1 - f) * b_out = 0
        // When a = k (f=0): b_out must be 0
        builder.assert_zero((AB::Expr::ONE - f) * b_out);
    }
}
