use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::Goldilocks;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;

// --- Type aliases for Goldilocks STARK config ---

pub type Val = Goldilocks;
pub type Challenge = BinomialExtensionField<Val, 2>;

// Poseidon2 permutation over Goldilocks (width 8)
pub type Perm = p3_goldilocks::Poseidon2Goldilocks<8>;

// Hash: absorb 8 field elements, squeeze 4, capacity 4
pub type MyHash = PaddingFreeSponge<Perm, 8, 4, 4>;

// Compression: truncate permutation output to 4 elements from 8
pub type MyCompress = TruncatedPermutation<Perm, 2, 4, 8>;

// Merkle tree MMCS over packed Goldilocks
pub type ValMmcs = MerkleTreeMmcs<
    <Val as Field>::Packing,
    <Val as Field>::Packing,
    MyHash,
    MyCompress,
    2,
    4,
>;

// Extension field MMCS for FRI challenges
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

// Fiat-Shamir challenger
pub type Challenger = DuplexChallenger<Val, Perm, 8, 4>;

// FFT engine
pub type Dft = Radix2DitParallel<Val>;

// Polynomial commitment scheme (FRI over two-adic field)
pub type MyPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

// Full STARK config
pub type PbsStarkConfig = StarkConfig<MyPcs, Challenge, Challenger>;

/// Create a STARK config suitable for testing (fast, low security).
pub fn make_test_config() -> PbsStarkConfig {
    let perm = p3_goldilocks::default_goldilocks_poseidon2_8();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = FriParameters::new_benchmark_high_arity(challenge_mmcs);
    let pcs = MyPcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    StarkConfig::new(pcs, challenger)
}
