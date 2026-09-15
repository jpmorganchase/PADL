use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;

use crate::haste_compat::{HASTE_LWE_DIMENSION, HASTE_RING_DIMENSION};
use crate::haste_ks_columns::{
    HasteKsCols, HasteKsPreCols, HASTE_KS_DIGIT_BITS, HASTE_KS_LEVELS, NUM_HASTE_KS_COLS,
    NUM_HASTE_KS_PRE_COLS,
};

#[derive(Debug, Clone)]
pub struct HasteKsAir {
    pub preprocessed: RowMajorMatrix<Goldilocks>,
}

impl BaseAir<Goldilocks> for HasteKsAir {
    fn width(&self) -> usize {
        NUM_HASTE_KS_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_HASTE_KS_PRE_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Goldilocks>> {
        Some(self.preprocessed.clone())
    }

    fn num_public_values(&self) -> usize {
        HASTE_RING_DIMENSION + 1 + HASTE_LWE_DIMENSION + 1
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for HasteKsAir {
    fn eval(&self, builder: &mut AB) {
        let (
            input_a_coeff,
            decomp,
            inv_hint,
            digit_bits,
            decomp_ntt,
            input_b0,
            out_a_ntt,
            out_b_ntt,
            out_a_coeff,
            out_b_coeff,
        ) = {
            let main = builder.main();
            let local: &HasteKsCols<AB::Var> = main.current_slice().borrow();
            (
                local.input_a_coeff,
                local.decomp,
                local.inv_hint,
                local.digit_bits,
                local.decomp_ntt,
                local.input_b0,
                local.out_a_ntt,
                local.out_b_ntt,
                local.out_a_coeff,
                local.out_b_coeff,
            )
        };
        let (
            ksk_a_ntt,
            ksk_b_ntt,
            expected_input_a,
            expected_input_b0,
            is_mask_output,
            expected_mask_output,
            is_first_row,
            expected_body_output,
        ) = {
            let prep = builder.preprocessed();
            let local: &HasteKsPreCols<AB::Var> = prep.current_slice().borrow();
            (
                local.ksk_a_ntt,
                local.ksk_b_ntt,
                local.input_a_coeff,
                local.input_b0,
                local.is_mask_output,
                local.expected_mask_output,
                local.is_first_row,
                local.expected_body_output,
            )
        };

        builder.assert_eq(input_a_coeff, expected_input_a);
        builder.assert_eq(input_b0, expected_input_b0);

        let base = AB::F::from_u32(32);
        let mut recomposed: AB::Expr = AB::Expr::ZERO;
        let mut base_power = AB::F::ONE;
        for level in 0..HASTE_KS_LEVELS {
            let digit: AB::Expr = decomp[level].into();
            recomposed = recomposed + digit.clone() * base_power;

            let mut bit_sum: AB::Expr = AB::Expr::ZERO;
            let mut bit_power = AB::F::ONE;
            for bit_index in 0..HASTE_KS_DIGIT_BITS {
                let bit = digit_bits[level * HASTE_KS_DIGIT_BITS + bit_index];
                builder.assert_bool(bit);
                bit_sum = bit_sum + AB::Expr::from(bit) * bit_power;
                bit_power = bit_power * AB::F::TWO;
            }
            builder.assert_zero(digit - bit_sum);
            base_power = base_power * base;
        }
        builder.assert_zero(AB::Expr::from(input_a_coeff) + recomposed);

        // Goldilocks Q = 0xffffffff00000001. A canonical 64-bit representative has
        // upper 32 bits below 0xffffffff, or upper bits all one and lower bits all zero.
        builder.assert_zero(digit_bits[64]);
        let mut sigma_top: AB::Expr = AB::Expr::ZERO;
        for bit in &digit_bits[32..64] {
            sigma_top = sigma_top + AB::Expr::ONE - *bit;
        }
        let mut sigma_bottom: AB::Expr = AB::Expr::ZERO;
        for bit in &digit_bits[..32] {
            sigma_bottom = sigma_bottom + *bit;
        }
        let zero_flag = AB::Expr::ONE - sigma_top.clone() * inv_hint;
        builder.assert_zero(sigma_top * zero_flag.clone());
        builder.assert_zero(zero_flag * sigma_bottom);

        let mut sum_a: AB::Expr = AB::Expr::ZERO;
        let mut sum_b: AB::Expr = AB::Expr::ZERO;
        for level in 0..HASTE_KS_LEVELS {
            let digit_ntt: AB::Expr = decomp_ntt[level].into();
            sum_a = sum_a + digit_ntt.clone() * ksk_a_ntt[level];
            sum_b = sum_b + digit_ntt * ksk_b_ntt[level];
        }
        builder.assert_eq(out_a_ntt, sum_a);
        builder.assert_zero(AB::Expr::from(out_b_ntt) - input_b0 - sum_b);

        builder.assert_bool(is_mask_output);
        builder.assert_zero(
            AB::Expr::from(is_mask_output) * (AB::Expr::from(out_a_coeff) - expected_mask_output),
        );
        builder.assert_zero(
            AB::Expr::from(is_first_row) * (AB::Expr::from(out_b_coeff) - expected_body_output),
        );
    }
}
