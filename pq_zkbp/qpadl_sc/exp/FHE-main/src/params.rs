/// Goldilocks prime: Q = 2^64 - 2^32 + 1
pub const Q: u64 = 0xFFFFFFFF00000001;

/// LWE dimension
pub const N_LWE: usize = 728;

/// GLWE polynomial degree
pub const N_POLY: usize = 1024;

/// Gadget decomposition base for PBS
pub const B_PBS: u64 = 256; // 2^8

/// Number of decomposition levels for PBS
pub const L_PBS: usize = 8; // ceil(64/8)

/// Gadget decomposition base for key switching
pub const B_KS: u64 = 256; // 2^8

/// Number of decomposition levels for key switching
pub const L_KS: usize = 8;

/// GLWE dimension parameter (k=1 means RLWE)
pub const K_GLWE: usize = 1;

/// Plaintext modulus
pub const T_PLAIN: u64 = 4;

/// Scaling factor Δ = floor(Q / (2t))
pub const DELTA: u64 = Q / (2 * T_PLAIN);

/// Gaussian noise standard deviation
pub const SIGMA: f64 = 3.2;

/// log2(B_PBS) for bit-shift decomposition
pub const LOG_B_PBS: u32 = 8;

/// log2(B_KS) for bit-shift decomposition
pub const LOG_B_KS: u32 = 8;
