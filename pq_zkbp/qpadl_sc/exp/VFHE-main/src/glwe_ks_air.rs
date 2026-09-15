use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;

use tfhe_goldilocks::params::N_POLY;

use crate::glwe_ks_columns::{
    GlweKsCols, GlweKsPreCols, NUM_GLWE_KS_COLS, NUM_GLWE_KS_PRE_COLS,
};

/// AIR for GLWE Key Switching.
///
/// Proves correct GLWE-to-GLWE key switch operating on polynomials in NTT domain.
/// All constraints are row-local (no cross-row transitions needed).
///
/// Public values layout:
///   [input_a_coeffs: N_POLY] ++ [input_b_ntt: N_POLY] ++ [out_a_ntt: N_POLY] ++ [out_b_ntt: N_POLY]
#[derive(Debug, Clone)]
pub struct GlweKsAir {
    pub preprocessed: RowMajorMatrix<Goldilocks>,
}

impl BaseAir<Goldilocks> for GlweKsAir {
    fn width(&self) -> usize {
        NUM_GLWE_KS_COLS
    }

    fn preprocessed_width(&self) -> usize {
        NUM_GLWE_KS_PRE_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Goldilocks>> {
        Some(self.preprocessed.clone())
    }

    fn num_public_values(&self) -> usize {
        4 * N_POLY // input_a_coeffs + input_b_ntt + out_a_ntt + out_b_ntt
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for GlweKsAir {
    fn eval(&self, builder: &mut AB) {
        // Extract all variables first (AB::Var is Copy)
        let input_a_coeff: AB::Var;
        let decomp: [AB::Var; 8];
        let inv_hint: AB::Var;
        let digit_bits: [AB::Var; 64];
        let decomp_ntt: [AB::Var; 8];
        let input_b_ntt: AB::Var;
        let out_a_ntt: AB::Var;
        let out_b_ntt: AB::Var;
        {
            let main = builder.main();
            let local: &GlweKsCols<AB::Var> = main.current_slice().borrow();
            input_a_coeff = local.input_a_coeff;
            decomp = local.decomp;
            inv_hint = local.inv_hint;
            digit_bits = local.digit_bits;
            decomp_ntt = local.decomp_ntt;
            input_b_ntt = local.input_b_ntt;
            out_a_ntt = local.out_a_ntt;
            out_b_ntt = local.out_b_ntt;
        }

        let ksk_a_ntt: [AB::Var; 8];
        let ksk_b_ntt: [AB::Var; 8];
        let expected_input_a_coeff: AB::Var;
        let expected_input_b_ntt: AB::Var;
        let expected_out_a_ntt: AB::Var;
        let expected_out_b_ntt: AB::Var;
        {
            let prep = builder.preprocessed();
            let pre: &GlweKsPreCols<AB::Var> = prep.current_slice().borrow();
            ksk_a_ntt = pre.ksk_a_ntt;
            ksk_b_ntt = pre.ksk_b_ntt;
            expected_input_a_coeff = pre.input_a_coeff;
            expected_input_b_ntt = pre.input_b_ntt;
            expected_out_a_ntt = pre.out_a_ntt;
            expected_out_b_ntt = pre.out_b_ntt;
        }

        builder.assert_eq(input_a_coeff, expected_input_a_coeff);
        builder.assert_eq(input_b_ntt, expected_input_b_ntt);
        builder.assert_eq(out_a_ntt, expected_out_a_ntt);
        builder.assert_eq(out_b_ntt, expected_out_b_ntt);

        let base = AB::F::from_u32(256);

        // =============================================
        // C1: Coefficient-domain recomposition
        // input_a_coeff = Σ_{l=0}^{7} decomp[l] · 256^l
        // =============================================
        {
            let mut recomp: AB::Expr = AB::Expr::ZERO;
            let mut b_pow = AB::F::ONE;
            for l in 0..8 {
                let digit: AB::Expr = decomp[l].into();
                recomp = recomp + digit * b_pow;
                b_pow = b_pow * base;
            }
            let input_a: AB::Expr = input_a_coeff.into();
            builder.assert_zero(input_a - recomp);
        }

        // =============================================
        // C2: Digit range proof (binary decomposition)
        // ∀l: decomp[l] = Σ_{k=0}^{7} digit_bits[l*8+k] · 2^k
        // We uses binary here because Logup constant overhead is more expensive.
        // =============================================
        for l in 0..8 {
            let digit: AB::Expr = decomp[l].into();
            let mut bit_sum: AB::Expr = AB::Expr::ZERO;
            let mut two_pow = AB::F::ONE;
            for k in 0..8 {
                let bit_idx = l * 8 + k;
                builder.assert_bool(digit_bits[bit_idx]);
                let bit: AB::Expr = digit_bits[bit_idx].into();
                bit_sum = bit_sum + bit * two_pow;
                two_pow = two_pow * AB::F::TWO;
            }
            builder.assert_zero(digit - bit_sum);
        }

        // =============================================
        // C3: Is-zero gadget (integer range check: S < Q)
        // =============================================
        {
            let d0: AB::Expr = decomp[0].into();
            let d1: AB::Expr = decomp[1].into();
            let d2: AB::Expr = decomp[2].into();
            let d3: AB::Expr = decomp[3].into();
            let d4: AB::Expr = decomp[4].into();
            let d5: AB::Expr = decomp[5].into();
            let d6: AB::Expr = decomp[6].into();
            let d7: AB::Expr = decomp[7].into();
            let sigma_top: AB::Expr =
                AB::Expr::ZERO + AB::F::from_u32(1020) - d4 - d5 - d6 - d7;
            let sigma_bot: AB::Expr = d0 + d1 + d2 + d3;
            let w: AB::Expr = inv_hint.into();
            let z: AB::Expr = AB::Expr::ONE - sigma_top.clone() * w;
            builder.assert_zero(sigma_top * z.clone());
            builder.assert_zero(z * sigma_bot);
        }

        // NOTE: NTT <-> coefficient binding (C4) is verified OUTSIDE the STARK.
        // The verifier independently checks that decomp_ntt columns are the
        // correct NTT of the coefficient-domain digit polynomials, using OOD
        // evaluation: evaluate the committed trace polynomial for decomp[l]
        // at the NTT evaluation points and compare against decomp_ntt[l].

        // =============================================
        // C4: External product — output computation
        // out_a_ntt = Σ_l decomp_ntt[l]·256^l - Σ_l decomp_ntt[l] · ksk_a_ntt[l]
        //           = Σ_l decomp_ntt[l] · (256^l - ksk_a_ntt[l])
        // out_b_ntt = input_b_ntt - Σ_l decomp_ntt[l] · ksk_b_ntt[l]
        //
        // input_a_ntt is NOT a separate column — it equals Σ decomp_ntt[l]·B^l
        // (NTT correctness of decomp_ntt vs decomp is verified outside STARK).
        // =============================================
        {
            // input_a_ntt = Σ_l decomp_ntt[l] · 256^l (virtual, not committed)
            let mut input_a_ntt_expr: AB::Expr = AB::Expr::ZERO;
            let mut b_pow = AB::F::ONE;
            for l in 0..8 {
                let d_ntt: AB::Expr = decomp_ntt[l].into();
                input_a_ntt_expr = input_a_ntt_expr + d_ntt * b_pow;
                b_pow = b_pow * base;
            }

            let mut sum_a: AB::Expr = AB::Expr::ZERO;
            for l in 0..8 {
                let d_ntt: AB::Expr = decomp_ntt[l].into();
                let ksk_a: AB::Expr = ksk_a_ntt[l].into();
                sum_a = sum_a + d_ntt * ksk_a;
            }
            let out_a: AB::Expr = out_a_ntt.into();
            builder.assert_zero(out_a - (input_a_ntt_expr - sum_a));
        }
        {
            let b_ntt: AB::Expr = input_b_ntt.into();
            let mut sum_b: AB::Expr = AB::Expr::ZERO;
            for l in 0..8 {
                let d_ntt: AB::Expr = decomp_ntt[l].into();
                let ksk_b: AB::Expr = ksk_b_ntt[l].into();
                sum_b = sum_b + d_ntt * ksk_b;
            }
            let out_b: AB::Expr = out_b_ntt.into();
            builder.assert_zero(out_b - (b_ntt - sum_b));
        }

    }
}
