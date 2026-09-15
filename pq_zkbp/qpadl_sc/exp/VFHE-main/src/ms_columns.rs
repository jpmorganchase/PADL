use core::borrow::Borrow;
use core::mem::size_of;

use tfhe_goldilocks::params::N_LWE;

/// Number of bits in the range check: ceil(log2(2k)) where k = (Q-1)/(4*N_POLY).
pub const RANGE_BITS: usize = 53;

/// Number of LWE components to modulus-switch: N_LWE mask + 1 body = 729.
/// Padded to the next power of two (1024) for the AIR trace.
pub const NUM_MS_COMPONENTS: usize = N_LWE + 1;

/// Witness columns for the modulus-switch AIR.
///
/// Each row corresponds to one LWE component being modulus-switched
/// from Z_q to Z_{2N}.
///
/// The full nonzero-indicator approach (not hybrid):
/// - Flag f = 1{a ≠ k} via inverse witness
/// - Conditional bit decomposition of r = a - (2b'-1)·k - 1
/// - Exceptional point check: f=0 ⟹ b=0
#[repr(C)]
pub struct MsCols<T> {
    /// Prover witness: segment index b' ∈ {1, ..., 2N}
    pub b_prime: T,

    /// Output: b = b' mod 2N ∈ {0, ..., 2N-1}
    pub b_out: T,

    /// Nonzero indicator flag: f = 1{a ≠ k}
    pub f_flag: T,

    /// Inverse witness: (a - k)^{-1} when a ≠ k, else 0
    pub inv_witness: T,

    /// Bit decomposition of r = a - (2b'-1)·k - 1 (53 bits)
    pub r_bits: [T; RANGE_BITS],
}

pub const NUM_MS_COLS: usize = size_of::<MsCols<u8>>();

/// Preprocessed columns for modulus-switch AIR.
///
/// Each row provides the public input value and its expected switched output.
#[repr(C)]
pub struct MsPreCols<T> {
    /// The LWE component value a_i ∈ Z_q (public input)
    pub input_a: T,
    /// The verifier-derived modulus-switched value in Z_{2N}
    pub expected_b_out: T,
}

pub const NUM_MS_PRE_COLS: usize = size_of::<MsPreCols<u8>>();

// --- Borrow impls ---

impl<T> Borrow<MsCols<T>> for [T] {
    fn borrow(&self) -> &MsCols<T> {
        debug_assert_eq!(self.len(), NUM_MS_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<MsCols<T>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> Borrow<MsPreCols<T>> for [T] {
    fn borrow(&self) -> &MsPreCols<T> {
        debug_assert_eq!(self.len(), NUM_MS_PRE_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<MsPreCols<T>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

// Compile-time check: 1(b') + 1(b_out) + 1(f) + 1(inv) + 53(r_bits) = 57
const _: () = assert!(NUM_MS_COLS == 4 + RANGE_BITS);
const _: () = assert!(NUM_MS_PRE_COLS == 2);
