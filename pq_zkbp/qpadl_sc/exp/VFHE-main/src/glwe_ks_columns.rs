use core::borrow::Borrow;
use core::mem::size_of;

/// Witness columns for the GLWE Key Switching AIR.
///
/// Each row j = 0..N_POLY-1 corresponds to NTT evaluation point j.
/// All 8 digits of coefficient a_j are in the same row (row-local decomposition).
///
/// Total rows: N_POLY = 1024
#[repr(C)]
pub struct GlweKsCols<T> {
    /// Coefficient a_j of input mask polynomial a(X) (coefficient domain)
    pub input_a_coeff: T,

    /// 8 unsigned base-256 digits of a_j
    pub decomp: [T; 8],

    /// Is-zero gadget inverse hint
    pub inv_hint: T,

    /// Binary decomposition of digits: 8 digits × 8 bits = 64 bits
    pub digit_bits: [T; 64],

    /// NTT evaluations of digit polynomials at point j
    /// decomp_ntt[l] = NTT(d_l)[j] where d_l(X) = Σ_k decomp[l] at row k · X^k
    pub decomp_ntt: [T; 8],

    /// NTT of input b(X) at point j
    pub input_b_ntt: T,

    /// Output mask NTT: Σ_l decomp_ntt[l]·256^l - Σ_l decomp_ntt[l]·ksk_a_ntt[l]
    pub out_a_ntt: T,

    /// Output body NTT: input_b_ntt - Σ_l decomp_ntt[l] · ksk_b_ntt[l]
    pub out_b_ntt: T,
}

pub const NUM_GLWE_KS_COLS: usize = size_of::<GlweKsCols<u8>>();

/// Preprocessed columns for GLWE Key Switch.
///
/// The KSK is an RLev encryption: L=8 RLWE ciphertexts.
/// Each row provides the NTT evaluations of KSK polynomials at point j.
#[repr(C)]
pub struct GlweKsPreCols<T> {
    /// KSK mask NTT: ksk_a_ntt[l] = NTT(ksk_a_l(X))[j]
    pub ksk_a_ntt: [T; 8],

    /// KSK body NTT: ksk_b_ntt[l] = NTT(ksk_b_l(X))[j]
    pub ksk_b_ntt: [T; 8],

    /// Claimed Blind Rotation output mask coefficient at row j
    pub input_a_coeff: T,
    /// Claimed Blind Rotation output body NTT evaluation at row j
    pub input_b_ntt: T,
    /// Claimed final output mask NTT evaluation at row j
    pub out_a_ntt: T,
    /// Claimed final output body NTT evaluation at row j
    pub out_b_ntt: T,
}

pub const NUM_GLWE_KS_PRE_COLS: usize = size_of::<GlweKsPreCols<u8>>();

// --- Borrow impls ---

impl<T> Borrow<GlweKsCols<T>> for [T] {
    fn borrow(&self) -> &GlweKsCols<T> {
        debug_assert_eq!(self.len(), NUM_GLWE_KS_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<GlweKsCols<T>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> Borrow<GlweKsPreCols<T>> for [T] {
    fn borrow(&self) -> &GlweKsPreCols<T> {
        debug_assert_eq!(self.len(), NUM_GLWE_KS_PRE_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<GlweKsPreCols<T>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

// Compile-time check
const _: () = assert!(NUM_GLWE_KS_COLS == 1 + 8 + 1 + 64 + 8 + 1 + 1 + 1);
// = 85 columns
const _: () = assert!(NUM_GLWE_KS_PRE_COLS == 20);
