use core::borrow::Borrow;
use core::mem::size_of;

pub const HASTE_KS_LEVELS: usize = 13;
pub const HASTE_KS_DIGIT_BITS: usize = 5;
pub const HASTE_KS_TOTAL_BITS: usize = HASTE_KS_LEVELS * HASTE_KS_DIGIT_BITS;

#[repr(C)]
pub struct HasteKsCols<T> {
    pub input_a_coeff: T,
    pub decomp: [T; HASTE_KS_LEVELS],
    pub inv_hint: T,
    pub digit_bits: [T; HASTE_KS_TOTAL_BITS],
    pub decomp_ntt: [T; HASTE_KS_LEVELS],
    pub input_b0: T,
    pub out_a_ntt: T,
    pub out_b_ntt: T,
    pub out_a_coeff: T,
    pub out_b_coeff: T,
}

pub const NUM_HASTE_KS_COLS: usize = size_of::<HasteKsCols<u8>>();

#[repr(C)]
pub struct HasteKsPreCols<T> {
    pub ksk_a_ntt: [T; HASTE_KS_LEVELS],
    pub ksk_b_ntt: [T; HASTE_KS_LEVELS],
    pub input_a_coeff: T,
    pub input_b0: T,
    pub is_mask_output: T,
    pub expected_mask_output: T,
    pub is_first_row: T,
    pub expected_body_output: T,
}

pub const NUM_HASTE_KS_PRE_COLS: usize = size_of::<HasteKsPreCols<u8>>();

pub const HASTE_KS_NORTHSTAR_F_COLS: [usize; HASTE_KS_LEVELS + 2] =
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 96, 97];
pub const HASTE_KS_NORTHSTAR_G_COLS: [usize; HASTE_KS_LEVELS + 2] =
    [80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 94, 95];

impl<T> Borrow<HasteKsCols<T>> for [T] {
    fn borrow(&self) -> &HasteKsCols<T> {
        debug_assert_eq!(self.len(), NUM_HASTE_KS_COLS);
        let (prefix, values, suffix) = unsafe { self.align_to::<HasteKsCols<T>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        &values[0]
    }
}

impl<T> Borrow<HasteKsPreCols<T>> for [T] {
    fn borrow(&self) -> &HasteKsPreCols<T> {
        debug_assert_eq!(self.len(), NUM_HASTE_KS_PRE_COLS);
        let (prefix, values, suffix) = unsafe { self.align_to::<HasteKsPreCols<T>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        &values[0]
    }
}

const _: () = assert!(NUM_HASTE_KS_COLS == 98);
const _: () = assert!(NUM_HASTE_KS_PRE_COLS == 32);
