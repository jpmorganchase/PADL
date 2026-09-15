use core::borrow::Borrow;
use core::mem::size_of;

/// Optimized witness columns for the Blind Rotation AIR.
///
/// Uses LogUp range checks instead of 128 bit-decomposition columns.
/// Each row corresponds to one NTT evaluation point (index j).
/// Trace layout: num_blocks × 1024 rows.
///
#[repr(C)]
pub struct BlindRotateCols<T> {
    // === CMUX core columns (no digit_bits) ===
    // --- Accumulator (NTT domain) ---
    pub acc_a_ntt: T,
    pub acc_b_ntt: T,
    // --- Rotated ACC ---
    pub acc_rot_a_ntt: T,
    pub acc_rot_b_ntt: T,
    // --- Delta (coefficient domain) ---
    pub delta_a_coeff: T,
    pub delta_b_coeff: T,
    // --- Gadget decomposition digits ---
    pub decomp_a: [T; 8],
    pub decomp_b: [T; 8],
    // --- Is-zero gadget inverse hints ---
    pub inv_hint_a: T,
    pub inv_hint_b: T,
    // --- NTT of decomposition ---
    pub decomp_a_ntt: [T; 8],
    pub decomp_b_ntt: [T; 8],
    // --- External product ---
    pub ext_a_ntt: T,
    pub ext_b_ntt: T,
    // --- Output accumulator ---
    pub next_acc_a_ntt: T,
    pub next_acc_b_ntt: T,
    // --- Twiddle / rotation ---
    pub twiddle: T,
    pub phi: T,
    pub rho: T,

    // === LogUp range check: multiplicity columns ===
    // For each digit, the prover supplies the multiplicity at this row's range_table value.
    // range_mult_a[l] = count of how many rows have decomp_a[l]+128 == range_table[this_row]
    pub range_mult_a: [T; 8],
    pub range_mult_b: [T; 8],

    // === Blind rotation specific ===
    /// 11-bit decomposition of ã_i (constant within each block)
    pub a_tilde_bits: [T; 11],
    /// Binary exponentiation chain R_1..R_11 (constant within block)
    pub exp_chain: [T; 11],
}

pub const NUM_BR_COLS: usize = size_of::<BlindRotateCols<u8>>();

/// Preprocessed columns for blind rotation.
#[repr(C)]
pub struct BlindRotatePreCols<T> {
    /// NTT evaluations of BSK row l mask polynomial (l = 0..15)
    pub bsk_a_ntt: [T; 16],
    /// NTT evaluations of BSK row l body polynomial (l = 0..15)
    pub bsk_b_ntt: [T; 16],
    /// 1 on last row of each block (row 1023, 2047, ...), 0 elsewhere
    pub is_last_in_block: T,
    /// Block index (0-based), constant within each 1024-row block
    pub block_id: T,
    /// NTT evaluation index (0..1023), repeats per block
    pub ntt_idx: T,
    /// 1 on all rows of the first block, 0 elsewhere
    pub is_first_block: T,
    /// 1 on all rows of the last block, 0 elsewhere
    pub is_last_block: T,
    /// Range table value for LogUp range check: row_index % 256 (cycles 0..255)
    pub range_table: T,
}

pub const NUM_BR_PRE_COLS: usize = size_of::<BlindRotatePreCols<u8>>();

// --- Borrow impls ---

impl<T> Borrow<BlindRotateCols<T>> for [T] {
    fn borrow(&self) -> &BlindRotateCols<T> {
        debug_assert_eq!(self.len(), NUM_BR_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<BlindRotateCols<T>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> Borrow<BlindRotatePreCols<T>> for [T] {
    fn borrow(&self) -> &BlindRotatePreCols<T> {
        debug_assert_eq!(self.len(), NUM_BR_PRE_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<BlindRotatePreCols<T>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}
