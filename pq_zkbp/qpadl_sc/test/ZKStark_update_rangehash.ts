import { expect } from "chai";

import {
  P, G_PRIM,
  mod, fadd, fsub, fmul, fpow, finv, rootOfUnity,
  ntt, intt, polyEval,
  LdeCoset, buildLdeDomain, evalOnCoset, inttCoset,
  concatBytes, keccak, leafHashFromValues, leafHashFromValuesSalt,
  randomSalts, SALT_BYTES,
  BatchedMerkleTree,
  FiatShamirTranscript, trAppendHex32,
  layerCapHeight,
  tsVerifyBatch,
  cVecHash,
  packField16,
  packCVec,
  bytesToHex0x,
  bytesToHex,
  u64BE,
  leadingZeroBitsBytes,
  blindingBudget,
  cpBlindBudget,
  cpChunkWidth,
  negacyclicNTT,
  inttTwisted,
  sigmaAlphaCoeffs,
  lambdaAlphaCoeffs,
  blindWithNminus1,
  shiftUp,
  polyAddInto,
  polySub,
  polyAddScaled,
  polyMul,
  divByXNminus1,
  INV4,
  fold4Coset,
  friFoldArity4,
  detRng,
  ternaryRng,
  AOracleSetup,
  buildAOracleSetup,
  nttCoset,
} from "./stark-utils";

import {
  RESCUE_ALPHA,
  RESCUE_ALPHA_INV,
  RESCUE_ROUNDS,
  RESCUE_WIDTH,
  RESCUE_CAPACITY,
  RESCUE_RATE,
  RESCUE_M,
  RESCUE_MINV,
  RESCUE_ARC1,
  RESCUE_ARC2,
} from "./rescue-params";

import { ethers } from "ethers";
import hre from "hardhat";


// Native prover (also provides the lattice commitment keygen used below).
const nativeProver = require("../stark-prover-native");

// Lattice commitment keys: A_sis is shared (LATTICE_SIS_SEED); each recipient
// derives its own B, B' rows from a per-recipient seed. Used when M matches the
// decryptable layout (κ_sis SIS rows + 2 message rows).
export const LATTICE_SIS_SEED = 777;
export const LATTICE_DEFAULT_RECIPIENT = 1000;
export const LATTICE_KAPPA_SIS = 4;

// =============================================================================
// Shared STARK parameters
// =============================================================================

const BLOWUP = 16;
const NUM_QUERIES = 23;
const CAP_HEIGHT = 6;
const FRI_ARITY = 4;
const FINAL_POLY_BOUND = 16;
const GRINDING_BITS = 23;

// LogUp: 8-byte decomposition of 64-bit values
const NUM_BYTES = 8;
const TABLE_SIZE = 256;

// Hash parameters
const HASH_STATE_WIDTH = RESCUE_WIDTH;       // 12
const HASH_RATE = RESCUE_RATE;               // 8
const HASH_CAPACITY = RESCUE_CAPACITY;       // 4
const HASH_ROUNDS = RESCUE_ROUNDS;           // 8
const HASH_OUTPUT_LANES = 2;                 // τ = 2 output lanes
const NUM_HASHES = 3;                        // m, m_sender, m_original

// Powers of 256 for recomposition
const POW256: bigint[] = Array.from({ length: NUM_BYTES }, (_, j) => 1n << BigInt(8 * j));

// =============================================================================
// 1. Rescue-Prime Permutation (forward computation)
// =============================================================================

/** MDS matrix-vector multiply: out = M · v (mod P) */
function mdsMultiply(v: bigint[]): bigint[] {
  const out = new Array<bigint>(HASH_STATE_WIDTH).fill(0n);
  for (let i = 0; i < HASH_STATE_WIDTH; i++) {
    let acc = 0n;
    for (let j = 0; j < HASH_STATE_WIDTH; j++) {
      acc = fadd(acc, fmul(RESCUE_M[i][j], v[j]));
    }
    out[i] = acc;
  }
  return out;
}

/** Inverse MDS: out = M^{-1} · v */
function mdsInvMultiply(v: bigint[]): bigint[] {
  const out = new Array<bigint>(HASH_STATE_WIDTH).fill(0n);
  for (let i = 0; i < HASH_STATE_WIDTH; i++) {
    let acc = 0n;
    for (let j = 0; j < HASH_STATE_WIDTH; j++) {
      acc = fadd(acc, fmul(RESCUE_MINV[i][j], v[j]));
    }
    out[i] = acc;
  }
  return out;
}

/** S-box: x^α (α = 3) elementwise */
function sboxForward(v: bigint[]): bigint[] {
  return v.map((x) => fmul(fmul(x, x), x)); // x^3
}

/** Inverse S-box: x^{α_inv} elementwise */
function sboxInverse(v: bigint[]): bigint[] {
  return v.map((x) => fpow(x, RESCUE_ALPHA_INV));
}

/**
 * One full Rescue-Prime round.
 * Given post-injection state σ̂, compute next state:
 *   mid = M · σ̂^{⊙3} + arc1[r]
 *   s_next = M · mid^{⊙(1/3)} + arc2[r]
 */
function rescueRound(sigmaHat: bigint[], roundIdx: number): bigint[] {
  // Forward half: cube, MDS, add arc1
  const cubed = sboxForward(sigmaHat);
  const afterMds1 = mdsMultiply(cubed);
  const mid = afterMds1.map((v, i) => fadd(v, RESCUE_ARC1[roundIdx][i]));

  // Inverse half: inv-sbox, MDS, add arc2
  const invCubed = sboxInverse(mid);
  const afterMds2 = mdsMultiply(invCubed);
  const sNext = afterMds2.map((v, i) => fadd(v, RESCUE_ARC2[roundIdx][i]));
  return sNext;
}

/**
 * Full Rescue-Prime sponge hash.
 * Input: coefficients (length N, must be multiple of HASH_RATE).
 * Output: first HASH_OUTPUT_LANES elements of final state.
 *
 * The last HASH_RATE coefficients (block N/8 - 1) serve as randomness.
 */
function rescueSpongeHash(coeffs: bigint[]): bigint[] {
  const N = coeffs.length;
  if (N % HASH_RATE !== 0) throw new Error(`rescueSpongeHash: N=${N} not multiple of rate=${HASH_RATE}`);
  const numBlocks = N / HASH_RATE;

  // Initial state = IV = all zeros
  let state = new Array<bigint>(HASH_STATE_WIDTH).fill(0n);

  for (let blk = 0; blk < numBlocks; blk++) {
    // Absorb: inject HASH_RATE coefficients into rate lanes
    for (let j = 0; j < HASH_RATE; j++) {
      state[j] = fadd(state[j], coeffs[blk * HASH_RATE + j]);
    }
    // Permutation: HASH_ROUNDS rounds
    const roundsToApply = (blk < numBlocks - 1) ? HASH_ROUNDS : HASH_ROUNDS - 1;
    for (let r = 0; r < roundsToApply; r++) {
      state = rescueRound(state, r);
    }
  }

  return state.slice(0, HASH_OUTPUT_LANES);
}

// =============================================================================
// 2. Hash State Trace Builder
// =============================================================================

/**
 * Build the full Rescue hash state trace (N rows × 12 state columns).
 * Also returns the σ helper trace (N rows × 8 columns).
 *
 * Row layout within block k (rows 8k..8k+7):
 *   Row 8k: state before permutation of block k (post-absorb of block k-1,
 *           or IV for k=0)
 *   Rows 8k+1..8k+7: state after rounds 0..6 of block k
 *   The transition from row 8k+7 to row 8(k+1) is round 7 of block k.
 *
 * σ_j(ω^t) = s_j(ω^t) + f_abs(ω^t) · message[t + j - (t mod 8)]
 *   but we store it more carefully: at absorb rows (t≡0 mod 8),
 *   σ_j = s_j + coeffs[t + j]; at non-absorb rows, σ_j = s_j.
 */
function buildHashTrace(coeffs: bigint[]): {
  stateTrace: bigint[][];  // [HASH_STATE_WIDTH][N]
  sigmaTrace: bigint[][];  // [HASH_RATE][N]
} {
  const N = coeffs.length;
  if (N % HASH_RATE !== 0) throw new Error("buildHashTrace: N not multiple of rate");
  const numBlocks = N / HASH_RATE;

  const stateTrace: bigint[][] = Array.from({ length: HASH_STATE_WIDTH }, () => new Array(N));
  const sigmaTrace: bigint[][] = Array.from({ length: HASH_RATE }, () => new Array(N));

  // Initial state = IV = all zeros
  let state = new Array<bigint>(HASH_STATE_WIDTH).fill(0n);

  for (let blk = 0; blk < numBlocks; blk++) {
    const baseRow = blk * HASH_ROUNDS;
    // Row baseRow: state at start of block (before absorption of this block)
    // Store state
    for (let i = 0; i < HASH_STATE_WIDTH; i++) stateTrace[i][baseRow] = state[i];

    // Absorb: inject message into rate lanes for σ
    const sigmaHat = state.slice();
    for (let j = 0; j < HASH_RATE; j++) {
      sigmaHat[j] = fadd(state[j], coeffs[blk * HASH_RATE + j]);
    }

    // σ at absorb row
    for (let j = 0; j < HASH_RATE; j++) sigmaTrace[j][baseRow] = sigmaHat[j];

    // Apply rounds within this block
    let cur = sigmaHat;
    const roundsInBlock = (blk < numBlocks - 1) ? HASH_ROUNDS : HASH_ROUNDS - 1;
    for (let r = 0; r < roundsInBlock; r++) {
      const next = rescueRound(cur, r % HASH_ROUNDS);
      const nextRow = baseRow + r + 1;
      if (nextRow < N) {
        for (let i = 0; i < HASH_STATE_WIDTH; i++) stateTrace[i][nextRow] = next[i];
        // σ at non-absorb rows: σ_j = s_j (no injection)
        for (let j = 0; j < HASH_RATE; j++) sigmaTrace[j][nextRow] = next[j];
      }
      cur = next;
    }
    state = cur;
  }

  return { stateTrace, sigmaTrace };
}

// =============================================================================
// 3. Absorb Selector and Periodic Polynomial Helpers
// =============================================================================

/**
 * Compute absorb selector values on H:
 * f_abs(ω^t) = 1 if t ≡ 0 mod 8, else 0
 */
function buildAbsorbSelectorValues(N: number): bigint[] {
  const vals = new Array<bigint>(N).fill(0n);
  for (let t = 0; t < N; t += HASH_ROUNDS) vals[t] = 1n;
  return vals;
}

/**
 * Build periodic round constant values on H for a given component.
 * arc[t] = arcTable[t mod 8][comp]
 */
function buildPeriodicArcValues(N: number, arcTable: bigint[][], comp: number): bigint[] {
  const vals = new Array<bigint>(N);
  for (let t = 0; t < N; t++) vals[t] = arcTable[t % HASH_ROUNDS][comp];
  return vals;
}

/**
 * Evaluate a periodic polynomial (period 8) at an arbitrary point z.
 * Given values v[0..7] with period 8 over H (ω^N = 1):
 *   p(z) = (z^N - 1)/8 · Σ_{r=0}^{7} v[r] / (z^{N/8} · ω^{-rN/8} - 1)
 *
 * If z^N = 1 (shouldn't happen for OOD z), this formula is singular.
 */
function evalPeriodicAtZ(values8: bigint[], z: bigint, N: number, omega: bigint): bigint {
  const Nbig = BigInt(N);
  const zN = fpow(z, Nbig);
  const zNm1 = fsub(zN, 1n); // z^N - 1
  if (zNm1 === 0n) throw new Error("evalPeriodicAtZ: z is N-th root of unity");

  const period = HASH_ROUNDS; // 8
  const inv8 = finv(BigInt(period));
  const zN8 = fpow(z, Nbig / BigInt(period)); // z^{N/8}
  // ω^{N/8} is a primitive 8th root of unity
  const omegaN8 = fpow(omega, Nbig / BigInt(period));

  let sum = 0n;
  let omegaN8_negR = 1n; // ω^{-rN/8} starts at 1 for r=0
  const omegaN8_inv = finv(omegaN8);
  for (let r = 0; r < period; r++) {
    const denom = fsub(fmul(zN8, omegaN8_negR), 1n);
    if (denom === 0n) throw new Error(`evalPeriodicAtZ: singular at r=${r}`);
    sum = fadd(sum, fmul(values8[r], finv(denom)));
    omegaN8_negR = fmul(omegaN8_negR, omegaN8_inv);
  }
  return fmul(fmul(zNm1, inv8), sum);
}

/**
 * Evaluate f_abs(z) = (1/8) · (z^N - 1) / (z^{N/8} - 1)
 * Simplified since f_abs has period-8 values [1,0,0,0,0,0,0,0].
 */
function evalAbsorbSelectorAtZ(z: bigint, N: number): bigint {
  const Nbig = BigInt(N);
  const zN = fpow(z, Nbig);
  const zN8 = fpow(z, Nbig / 8n);
  const numer = fsub(zN, 1n);
  const denom = fmul(8n, fsub(zN8, 1n));
  if (denom === 0n) throw new Error("evalAbsorbSelectorAtZ: z^{N/8} = 1");
  return fmul(numer, finv(denom));
}

/**
 * Evaluate the boundary vanishing factor for C1b divisor:
 * Z_H(x) / (x - ω^{N-1}) evaluated at z.
 * = (z^N - 1) / (z - ω^{N-1})
 */
function evalC1bDivisorAtZ(z: bigint, N: number, omega: bigint): bigint {
  const Nbig = BigInt(N);
  const zN = fpow(z, Nbig);
  const omegaNm1 = fpow(omega, Nbig - 1n);
  const numer = fsub(zN, 1n);
  const denom = fsub(z, omegaNm1);
  if (denom === 0n) throw new Error("evalC1bDivisorAtZ: z = ω^{N-1}");
  return fmul(numer, finv(denom));
}

// =============================================================================
// LogUp Helpers 
// =============================================================================

function decomposeBytes64(value: bigint): bigint[] {
  const v = mod(value);
  if (v >= (1n << 64n)) throw new Error(`decomposeBytes64: value ${v} >= 2^64`);
  const bytes = new Array<bigint>(NUM_BYTES);
  let x = v;
  for (let j = 0; j < NUM_BYTES; j++) {
    bytes[j] = x & 0xFFn;
    x >>= 8n;
  }
  return bytes;
}

// Little-endian 2-byte split of a value in [0, 2^16). Used for the r-range check.
function decomposeBytes16(value: bigint): bigint[] {
  const v = mod(value);
  if (v >= (1n << 16n)) throw new Error(`decomposeBytes16: value ${v} >= 2^16`);
  return [v & 0xFFn, (v >> 8n) & 0xFFn];
}

function buildTableValues(N: number): bigint[] {
  if (N < TABLE_SIZE) throw new Error(`N=${N} too small for table`);
  const tVals = new Array<bigint>(N).fill(0n);
  for (let i = 0; i < TABLE_SIZE; i++) tVals[i] = BigInt(i);
  return tVals;
}

function computeMultiplicity(N: number, dmBytes: bigint[][], dsBytes: bigint[][], extra: bigint[][]): bigint[] {
  const mu = new Array<bigint>(N).fill(0n);
  for (let j = 0; j < NUM_BYTES; j++) {
    for (let i = 0; i < N; i++) {
      mu[Number(dmBytes[j][i])] += 1n;
      mu[Number(dsBytes[j][i])] += 1n;
    }
  }
  for (const col of extra) {
    for (let i = 0; i < N; i++) mu[Number(col[i])] += 1n;
  }
  return mu;
}

function computeHelperInverse(beta: bigint, values: bigint[]): bigint[] {
  return values.map((v, i) => {
    const denom = fsub(beta, v);
    if (denom === 0n) throw new Error(`helper inverse: β = value at index ${i}`);
    return finv(denom);
  });
}

function computeZLup(
  N: number, pmCols: bigint[][], psCols: bigint[][], prCols: bigint[][], muCol: bigint[], qCol: bigint[],
): bigint[] {
  const zLup = new Array<bigint>(N).fill(0n);
  for (let i = 0; i < N - 1; i++) {
    let contrib = 0n;
    for (let j = 0; j < NUM_BYTES; j++) {
      contrib = fadd(contrib, pmCols[j][i]);
      contrib = fadd(contrib, psCols[j][i]);
    }
    for (const col of prCols) contrib = fadd(contrib, col[i]);
    contrib = fsub(contrib, fmul(muCol[i], qCol[i]));
    zLup[i + 1] = fadd(zLup[i], contrib);
  }
  let lastContrib = 0n;
  for (let j = 0; j < NUM_BYTES; j++) {
    lastContrib = fadd(lastContrib, pmCols[j][N - 1]);
    lastContrib = fadd(lastContrib, psCols[j][N - 1]);
  }
  for (const col of prCols) lastContrib = fadd(lastContrib, col[N - 1]);
  lastContrib = fsub(lastContrib, fmul(muCol[N - 1], qCol[N - 1]));
  const closing = fadd(zLup[N - 1], lastContrib);
  if (closing !== 0n) throw new Error(`LogUp accumulator does not close: final=${closing}`);
  return zLup;
}

// =============================================================================
//Column Layout Constants
// =============================================================================

// ── Blinding budgets ──────────────────────────────────────────────────────────
/** Source columns (m, m_s, m_o) need b >= Q+8 (7 extra OOD shift reads) */
function blindingBudgetSource(numQueries: number): number { return numQueries + 8; }
/** Hash state columns: b_s >= Q+2 (opened at z and ωz) */
function blindingBudgetState(numQueries: number): number { return numQueries + 2; }
/** Hash helper σ columns: b_σ >= Q+1 */
function blindingBudgetSigma(numQueries: number): number { return numQueries + 1; }

/** D_max = 2N + 3*b_s + 1 (from Rescue C1b cube constraint) */
function dMax(N: number, bS: number): number { return 2 * N + 3 * bS + 1; }

/** CP chunks for hash version: d = ceil(D_max / N) = 3 for typical params */
function cpNumChunksHash(N: number, bS: number): number {
  return Math.ceil(dMax(N, bS) / N);
}

// ── Round 0 trace column count: 4K + 21 + 60 (hash) = 4K + 81 ────────────────
// Layout per leaf:
//   [b̃Ntt(K), ĝ(K), b̃Sq(K), m, m_orig, m_sender,
//    d^(m)(8), d^(s)(8), μ, rAur,
//    s^(m)_0..11, σ^(m)_0..7,           ← hash of m (20 cols)
//    s^(s)_0..11, σ^(s)_0..7,           ← hash of m_sender (20 cols)
//    s^(o)_0..11, σ^(o)_0..7]           ← hash of m_original (20 cols)
function traceColCount(K: number): number { return 4 * K + 21 + 60; }

// Base offsets
function traceOffBNtt(K: number): number { return 0; }
function traceOffGHat(K: number): number { return K; }
function traceOffGlo(K: number): number { return 2 * K; }
function traceOffGhi(K: number): number { return 3 * K; }
function traceOffM(K: number): number { return 4 * K; }
function traceOffMOrig(K: number): number { return 4 * K + 1; }
function traceOffMSender(K: number): number { return 4 * K + 2; }
function traceOffDm(K: number): number { return 4 * K + 3; }
function traceOffDs(K: number): number { return 4 * K + 11; }
function traceOffMu(K: number): number { return 4 * K + 19; }
function traceOffRAur(K: number): number { return 4 * K + 20; }

// Hash columns start at offset 4K + 21
// Each hash occupies 20 columns: 12 state + 8 sigma
function traceOffHashState(K: number, hashIdx: number): number {
  return 4 * K + 21 + hashIdx * 20;
}
function traceOffHashSigma(K: number, hashIdx: number): number {
  return 4 * K + 21 + hashIdx * 20 + HASH_STATE_WIDTH;
}

// Range-check shift (η = 2^15): b ∈ [−2^15, 2^15) ⇒ b + 2^15 ∈ [0, 2^16) = 2 bytes.
const R_SHIFT = 1n << 15n;
// Interaction columns (Round 0.5): pm[8], ps[8], pr[2K], qcol, zlup.
function interColCount(K: number): number { return 18 + 2 * K; }
function interOffPm(): number { return 0; }
function interOffPs(): number { return 8; }
function interOffPr(): number { return 16; }
function interOffQcol(K: number): number { return 16 + 2 * K; }
function interOffZlup(K: number): number { return 17 + 2 * K; }

// Number of α-slots: 3K + 22 (range) + 102 (hash) = 3K + 124
function numAlphaSlots(K: number): number { return 3 * K + 124; }

// Hash α-slot offsets (start after 3K+22 range slots):
function alphaOffC1a(K: number): number { return 3 * K + 22; }
function alphaOffC1b(K: number): number { return 3 * K + 46; }
function alphaOffC2(K: number): number { return 3 * K + 82; }
function alphaOffC3(K: number): number { return 3 * K + 118; }

// =============================================================================
// Extended A-Oracle Setup 
// =============================================================================

interface AOracleSetupRangeHash extends AOracleSetup {
  tPoly: bigint[];
  tNtt: bigint[];
  tLde: bigint[];
}

function buildAOracleSetupRangeHash(
  aMat: bigint[][][], blowup: number, capHeight: number,
): AOracleSetupRangeHash {
  const M = aMat.length;
  if (M === 0) throw new Error("empty M");
  const K = aMat[0].length;
  if (K === 0) throw new Error("empty K");
  const d = aMat[0][0].length;
  if (d < TABLE_SIZE) throw new Error(`d=${d} < ${TABLE_SIZE}`);
  if (d % HASH_RATE !== 0) throw new Error(`d=${d} not multiple of HASH_RATE=${HASH_RATE}`);
  const omega = rootOfUnity(BigInt(d));
  const aPolys: bigint[][][] = aMat.map((row) =>
    row.map((a) => intt(a.map((v) => mod(v)), omega)),
  );
  const lde = buildLdeDomain(d, blowup);
  const aLde: bigint[][][] = [];
  for (let m = 0; m < M; m++) {
    const row: bigint[][] = [];
    for (let k = 0; k < K; k++) row.push(evalOnCoset(aPolys[m][k], lde));
    aLde.push(row);
  }
  const tNtt = buildTableValues(d);
  const tPoly = intt(tNtt, omega);
  const tLde = evalOnCoset(tPoly, lde);

  const leaves: Uint8Array[] = [];
  for (let i = 0; i < lde.ldeSize; i++) {
    const vals: bigint[] = new Array(M * K + 1);
    for (let m = 0; m < M; m++)
      for (let k = 0; k < K; k++) vals[m * K + k] = aLde[m][k][i];
    vals[M * K] = tLde[i];
    leaves.push(leafHashFromValues(vals));
  }
  const cap = layerCapHeight(capHeight, lde.ldeSize);
  const aTree = new BatchedMerkleTree(leaves, cap);
  const aCap = aTree.cap();
  const aOracleHash = ethers.keccak256(concatBytes(...aCap));
  return {
    M, K, d, blowup, capHeight, aPolys, aLde, aTree, aCap, aOracleHash, lde,
    tPoly, tNtt, tLde,
  };
}

// =============================================================================
// Proof Interface
// =============================================================================

interface ZKStarkUpdateRangeHashProof {
  traceLength: number;
  numColumns: number;    // K
  blowup: number;
  capHeight: number;
  blindB: number;        // standard blinding (other witness cols)
  blindBSource: number;  // blinding for m, m_s, m_o (Q+8)
  blindBState: number;   // blinding for hash state (Q+2)
  blindBSigma: number;   // blinding for hash helper (Q+1)
  cpBlindH: number;
  numChunks: number;     // 3
  cpChunkWidth: number;
  betaAur: bigint;

  // Public hash tokens (3 hashes × 2 output lanes = 6 field elements)
  tokenM: bigint[];      // [2]
  tokenS: bigint[];      // [2]
  tokenO: bigint[];      // [2]

  // Round 0: trace (4K + 81 columns, salted)
  traceCap: Uint8Array[];
  tracePositions: number[];
  traceColValues: bigint[][];
  traceSalts: Uint8Array[];
  traceBatchProof: Uint8Array[];

  // Round 0.5: interaction (18 columns)
  interCap: Uint8Array[];
  interColValues: bigint[][];
  interSalts: Uint8Array[];
  interBatchProof: Uint8Array[];

  // Aurora auxiliaries R, Q0, Q1
  auxCap: Uint8Array[];
  auxColValues: bigint[][];
  auxSalts: Uint8Array[];
  auxBatchProof: Uint8Array[];

  // CP chunks (d=3 columns)
  cpChunkCap: Uint8Array[];
  cpChunkColValues: bigint[][];
  cpChunkSalts: Uint8Array[];
  cpChunkBatchProof: Uint8Array[];

  // Mask R_deep
  maskCap: Uint8Array[];
  maskValues: bigint[];
  maskSalts: Uint8Array[];
  maskBatchProof: Uint8Array[];

  // Split g0, g1
  splitCap: Uint8Array[];
  splitColValues: bigint[][];
  splitSalts: Uint8Array[];
  splitBatchProof: Uint8Array[];

  // A oracle (M*K + 1 columns)
  aCap: Uint8Array[];
  aColValues: bigint[][];
  aBatchProof: Uint8Array[];

  // OOD openings at z
  oodBNttZ: bigint[];      // K
  oodGHatZ: bigint[];      // K
  oodGloZ: bigint[];       // K   low byte of (ĝ_k + 2^15)
  oodGhiZ: bigint[];       // K   high byte
  oodAZ: bigint[];         // M*K
  oodTZ: bigint;
  oodMZ: bigint;
  oodMOrigZ: bigint;
  oodMSenderZ: bigint;
  oodDmZ: bigint[];        // 8
  oodDsZ: bigint[];        // 8
  oodPmZ: bigint[];        // 8
  oodPsZ: bigint[];        // 8
  oodPrZ: bigint[];        // 2K
  oodQcolZ: bigint;
  oodMuZ: bigint;
  oodZlupZ: bigint;
  oodZlupOmegaZ: bigint;
  oodRAurZ: bigint;
  oodRZ: bigint;
  oodQZ: bigint;
  oodQ1Z: bigint;
  oodCpChunkZ: bigint[];   // d=3

  // Hash OOD at z: state s^(v)_i(z) for 3 hashes × 12 = 36
  oodHashStateZ: bigint[][]; // [3][12]
  // Hash OOD at ωz: state s^(v)_i(ωz) for 3 hashes × 12 = 36
  oodHashStateOmegaZ: bigint[][]; // [3][12]
  // Hash OOD at z: sigma σ^(v)_j(z) for 3 hashes × 8 = 24
  oodHashSigmaZ: bigint[][]; // [3][8]
  // Source OOD at ω^j z (j=1..7) for 3 source columns = 3×7 = 21
  oodSourceShifts: bigint[][]; // [3][7] — m(ω^j z), m_s(ω^j z), m_o(ω^j z)

  // FRI
  friCaps: Uint8Array[][];
  friLayerPositions: number[][];
  friLayerValues: bigint[][];
  friLayerSalts: Uint8Array[][];
  friLayerProofs: Uint8Array[][];
  friFinalPoly: bigint[];
  grindingNonce: bigint;
  queryIndices: number[];
}

// =============================================================================
// Prover Inputs Interface
// =============================================================================

interface RangeHashProveInputs {
  setup: AOracleSetupRangeHash;
  sqrtQ: bigint;
  cNtts: bigint[][];       // M × N NTT outputs c_m
  bCoeffs: bigint[][];     // K × N ternary coefficients
  mNtt: bigint[];          // N — message (transfer amount) values on H
  mOrigNtt: bigint[];      // N — sender's original balance on H
  mSenderNtt: bigint[];    // N — sender's remaining balance on H
  tokenM: bigint[];        // [2] — public hash of m
  tokenS: bigint[];        // [2] — public hash of m_sender
  tokenO: bigint[];        // [2] — public hash of m_original
}

// =============================================================================
// Prover
// =============================================================================

class ZKStarkUpdateProverRangeHash {
  blowup: number;
  numQueries: number;
  capHeight: number;
  constructor(blowup = BLOWUP, numQueries = NUM_QUERIES, capHeight = CAP_HEIGHT) {
    this.blowup = blowup;
    this.numQueries = numQueries;
    this.capHeight = capHeight;
  }

  prove(inputs: RangeHashProveInputs): ZKStarkUpdateRangeHashProof {
    const { setup, sqrtQ, cNtts, bCoeffs, mNtt, mOrigNtt, mSenderNtt, tokenM, tokenS, tokenO } = inputs;
    const { M, K, d, aPolys, aLde, aTree, aCap, aOracleHash, lde, tPoly, tNtt, tLde } = setup;
    if (setup.blowup !== this.blowup) throw new Error("prover/setup blowup mismatch");
    if (setup.capHeight !== this.capHeight) throw new Error("prover/setup capHeight mismatch");
    if (M < 2) throw new Error("requires M >= 2");
    if (cNtts.length !== M) throw new Error("c_vec length != M");
    if (bCoeffs.length !== K) throw new Error("bCoeffs length != K");
    if (mNtt.length !== d) throw new Error("mNtt length != d");
    if (mOrigNtt.length !== d) throw new Error("mOrigNtt length != d");
    if (mSenderNtt.length !== d) throw new Error("mSenderNtt length != d");
    if (d < TABLE_SIZE) throw new Error(`d=${d} < ${TABLE_SIZE}`);
    if (d % HASH_RATE !== 0) throw new Error(`d not multiple of HASH_RATE`);
    if (tokenM.length !== HASH_OUTPUT_LANES) throw new Error("tokenM length");
    if (tokenS.length !== HASH_OUTPUT_LANES) throw new Error("tokenS length");
    if (tokenO.length !== HASH_OUTPUT_LANES) throw new Error("tokenO length");
    for (const cm of cNtts) if (cm.length !== d) throw new Error("c_m length != d");
    for (const bc of bCoeffs) if (bc.length !== d) throw new Error("bCoeff_k length != d");

    const sqrtQn = mod(sqrtQ);
    if (sqrtQn === 0n) throw new Error("sqrtQ must be non-zero mod P");

    const N = d;
    const Nbig = BigInt(N);
    const omega = rootOfUnity(Nbig);
    const psi = rootOfUnity(2n * Nbig);

    // Blinding budgets
    const b = blindingBudget(N, this.numQueries);         // standard (bNtt, gHat, bSq, etc.)
    const bSource = blindingBudgetSource(this.numQueries); // m, m_s, m_o
    const bS = blindingBudgetState(this.numQueries);       // hash state
    const bSigma = blindingBudgetSigma(this.numQueries);   // hash helper σ
    const h = cpBlindBudget(this.numQueries);
    const w = cpChunkWidth(N);
    const dChunks = cpNumChunksHash(N, bS);

    const rng = (): bigint => mod(BigInt("0x" + ethers.hexlify(ethers.randomBytes(16)).slice(2)));
    const randPoly = (len: number): bigint[] =>
      Array.from({ length: len }, () => rng());

    // ── 1. Bare coefficient polynomials for b̃Ntt, ĝ, b̃Sq ─────────────
    const bCoeffNorm: bigint[][] = bCoeffs.map((row) => row.map((v) => mod(v)));
    // r-range: split (b + 2^15) ∈ [0,2^16) into low/high byte columns per k
    const gloCols: bigint[][] = bCoeffNorm.map((row) => row.map((v) => decomposeBytes16(fadd(v, R_SHIFT))[0]));
    const ghiCols: bigint[][] = bCoeffNorm.map((row) => row.map((v) => decomposeBytes16(fadd(v, R_SHIFT))[1]));
    const rByteCols: bigint[][] = [...gloCols, ...ghiCols];

    const fPolysBare: bigint[][] = bCoeffNorm.map((c) => {
      let psij = 1n;
      return c.map((v) => { const r = fmul(v, psij); psij = fmul(psij, psi); return r; });
    });
    const gPolysBare: bigint[][] = bCoeffNorm.map((c) => intt(c, omega));
    const gloPolysBare: bigint[][] = gloCols.map((c) => intt(c, omega));
    const ghiPolysBare: bigint[][] = ghiCols.map((c) => intt(c, omega));

    // ── 2. m, m_original, m_sender bare polynomials ─────────────────────
    const mVals = mNtt.map((v) => mod(v));
    const mOrigVals = mOrigNtt.map((v) => mod(v));
    const mSenderVals = mSenderNtt.map((v) => mod(v));
    const mPolyBare: bigint[] = intt(mVals, omega);
    const mOrigPolyBare: bigint[] = intt(mOrigVals, omega);
    const mSenderPolyBare: bigint[] = intt(mSenderVals, omega);

    // Verify balance: m_original = m + m_sender on H
    for (let i = 0; i < N; i++) {
      if (mOrigVals[i] !== fadd(mVals[i], mSenderVals[i]))
        throw new Error(`balance violated at row ${i}`);
    }

    // ── 3. Byte decomposition columns d^(m)_j, d^(s)_j ─────────────────
    const dmByteCols: bigint[][] = Array.from({ length: NUM_BYTES }, () => new Array(N));
    const dsByteCols: bigint[][] = Array.from({ length: NUM_BYTES }, () => new Array(N));
    for (let i = 0; i < N; i++) {
      const mBytes = decomposeBytes64(mVals[i]);
      const sBytes = decomposeBytes64(mSenderVals[i]);
      for (let j = 0; j < NUM_BYTES; j++) {
        dmByteCols[j][i] = mBytes[j];
        dsByteCols[j][i] = sBytes[j];
      }
    }
    const dmPolysBare: bigint[][] = dmByteCols.map((col) => intt(col, omega));
    const dsPolysBare: bigint[][] = dsByteCols.map((col) => intt(col, omega));

    // ── 4. Multiplicity column μ ─────────────────────────────────────────
    const muVals = computeMultiplicity(N, dmByteCols, dsByteCols, rByteCols);
    const muPolyBare: bigint[] = intt(muVals, omega);

    // ── 5. Hash state & σ traces for 3 hashes ───────────────────────────
    // Source values: m, m_sender, m_original (values on H = the coefficients
    // stored in the respective committed columns)
    const sourceVals: bigint[][] = [mVals, mSenderVals, mOrigVals];
    const hashTraces: { stateTrace: bigint[][]; sigmaTrace: bigint[][] }[] = [];
    for (let hi = 0; hi < NUM_HASHES; hi++) {
      hashTraces.push(buildHashTrace(sourceVals[hi]));
    }

    // Verify hash outputs match public tokens
    const tokens = [tokenM, tokenS, tokenO];
    for (let hi = 0; hi < NUM_HASHES; hi++) {
      for (let lane = 0; lane < HASH_OUTPUT_LANES; lane++) {
        const actual = hashTraces[hi].stateTrace[lane][N - 1];
        if (actual !== mod(tokens[hi][lane]))
          throw new Error(`hash ${hi} lane ${lane} mismatch: ${actual} != ${mod(tokens[hi][lane])}`);
      }
    }

    // Interpolate hash state and σ traces
    const hashStatePolysBare: bigint[][][] = []; // [3][12][N] polynomials
    const hashSigmaPolysBare: bigint[][][] = []; // [3][8][N] polynomials
    for (let hi = 0; hi < NUM_HASHES; hi++) {
      const sp: bigint[][] = [];
      for (let i = 0; i < HASH_STATE_WIDTH; i++) {
        sp.push(intt(hashTraces[hi].stateTrace[i], omega));
      }
      hashStatePolysBare.push(sp);
      const sigP: bigint[][] = [];
      for (let j = 0; j < HASH_RATE; j++) {
        sigP.push(intt(hashTraces[hi].sigmaTrace[j], omega));
      }
      hashSigmaPolysBare.push(sigP);
    }

    // ── 6. Aurora blinding polynomial r(X): fully random, deg N+b-1 ─────
    const rAurPoly: bigint[] = randPoly(N + b);

    // ── 7. Mask all Round 0 columns ─────────────────────────────────────
    const rNttPolys: bigint[][] = Array.from({ length: K }, () => randPoly(b));
    const rgPolys: bigint[][] = Array.from({ length: K }, () => randPoly(b));
    const rgloPolys: bigint[][] = Array.from({ length: K }, () => randPoly(b));
    const rghiPolys: bigint[][] = Array.from({ length: K }, () => randPoly(b));
    const rmPoly: bigint[] = randPoly(bSource);
    const rmOrigPoly: bigint[] = randPoly(bSource);
    const rmSenderPoly: bigint[] = randPoly(bSource);
    const rdmPolys: bigint[][] = Array.from({ length: NUM_BYTES }, () => randPoly(b));
    const rdsPolys: bigint[][] = Array.from({ length: NUM_BYTES }, () => randPoly(b));
    const rmuPoly: bigint[] = randPoly(b);

    // Hash masking polynomials
    const rHashStatePolys: bigint[][][] = []; // [3][12]
    const rHashSigmaPolys: bigint[][][] = []; // [3][8]
    for (let hi = 0; hi < NUM_HASHES; hi++) {
      const rs: bigint[][] = [];
      for (let i = 0; i < HASH_STATE_WIDTH; i++) rs.push(randPoly(bS));
      rHashStatePolys.push(rs);
      const rsig: bigint[][] = [];
      for (let j = 0; j < HASH_RATE; j++) rsig.push(randPoly(bSigma));
      rHashSigmaPolys.push(rsig);
    }

    // Apply blindWithNminus1 masking
    const bNttPolys: bigint[][] = fPolysBare.map((p, k) => blindWithNminus1(p, rNttPolys[k], N));
    const gHatPolys: bigint[][] = gPolysBare.map((p, k) => blindWithNminus1(p, rgPolys[k], N));
    const gloPolys: bigint[][] = gloPolysBare.map((p, k) => blindWithNminus1(p, rgloPolys[k], N));
    const ghiPolys: bigint[][] = ghiPolysBare.map((p, k) => blindWithNminus1(p, rghiPolys[k], N));
    const mPoly: bigint[] = blindWithNminus1(mPolyBare, rmPoly, N);
    const mOrigPoly: bigint[] = blindWithNminus1(mOrigPolyBare, rmOrigPoly, N);
    const mSenderPoly: bigint[] = blindWithNminus1(mSenderPolyBare, rmSenderPoly, N);
    const dmPolys: bigint[][] = dmPolysBare.map((p, j) => blindWithNminus1(p, rdmPolys[j], N));
    const dsPolys: bigint[][] = dsPolysBare.map((p, j) => blindWithNminus1(p, rdsPolys[j], N));
    const muPoly: bigint[] = blindWithNminus1(muPolyBare, rmuPoly, N);

    // Masked hash columns
    const hashStatePolys: bigint[][][] = []; // [3][12]
    const hashSigmaPolys: bigint[][][] = []; // [3][8]
    for (let hi = 0; hi < NUM_HASHES; hi++) {
      const sp: bigint[][] = [];
      for (let i = 0; i < HASH_STATE_WIDTH; i++) {
        sp.push(blindWithNminus1(hashStatePolysBare[hi][i], rHashStatePolys[hi][i], N));
      }
      hashStatePolys.push(sp);
      const sigP: bigint[][] = [];
      for (let j = 0; j < HASH_RATE; j++) {
        sigP.push(blindWithNminus1(hashSigmaPolysBare[hi][j], rHashSigmaPolys[hi][j], N));
      }
      hashSigmaPolys.push(sigP);
    }

    // ── 8. LDE all Round 0 columns ──────────────────────────────────────
    const bNttLde: bigint[][] = bNttPolys.map((p) => evalOnCoset(p, lde));
    const gHatLde: bigint[][] = gHatPolys.map((p) => evalOnCoset(p, lde));
    const gloLde: bigint[][] = gloPolys.map((p) => evalOnCoset(p, lde));
    const ghiLde: bigint[][] = ghiPolys.map((p) => evalOnCoset(p, lde));
    const mLde: bigint[] = evalOnCoset(mPoly, lde);
    const mOrigLde: bigint[] = evalOnCoset(mOrigPoly, lde);
    const mSenderLde: bigint[] = evalOnCoset(mSenderPoly, lde);
    const dmLde: bigint[][] = dmPolys.map((p) => evalOnCoset(p, lde));
    const dsLde: bigint[][] = dsPolys.map((p) => evalOnCoset(p, lde));
    const muLde: bigint[] = evalOnCoset(muPoly, lde);
    const rAurLde: bigint[] = evalOnCoset(rAurPoly, lde);

    // Hash columns LDE
    const hashStateLde: bigint[][][] = []; // [3][12][ldeSize]
    const hashSigmaLde: bigint[][][] = []; // [3][8][ldeSize]
    for (let hi = 0; hi < NUM_HASHES; hi++) {
      const sl: bigint[][] = [];
      for (let i = 0; i < HASH_STATE_WIDTH; i++) sl.push(evalOnCoset(hashStatePolys[hi][i], lde));
      hashStateLde.push(sl);
      const sigl: bigint[][] = [];
      for (let j = 0; j < HASH_RATE; j++) sigl.push(evalOnCoset(hashSigmaPolys[hi][j], lde));
      hashSigmaLde.push(sigl);
    }

    // ── 9. Round 0 Merkle commit (4K + 81 trace cols) ────────────────────
    const traceCols = traceColCount(K);
    const traceSaltsAll: Uint8Array[] = randomSalts(lde.ldeSize);
    const traceLeafHashes: Uint8Array[] = [];
    for (let i = 0; i < lde.ldeSize; i++) {
      const row: bigint[] = new Array(traceCols);
      for (let k = 0; k < K; k++) {
        row[traceOffBNtt(K) + k] = bNttLde[k][i];
        row[traceOffGHat(K) + k] = gHatLde[k][i];
        row[traceOffGlo(K) + k] = gloLde[k][i];
        row[traceOffGhi(K) + k] = ghiLde[k][i];
      }
      row[traceOffM(K)] = mLde[i];
      row[traceOffMOrig(K)] = mOrigLde[i];
      row[traceOffMSender(K)] = mSenderLde[i];
      for (let j = 0; j < NUM_BYTES; j++) {
        row[traceOffDm(K) + j] = dmLde[j][i];
        row[traceOffDs(K) + j] = dsLde[j][i];
      }
      row[traceOffMu(K)] = muLde[i];
      row[traceOffRAur(K)] = rAurLde[i];
      // Hash columns
      for (let hi = 0; hi < NUM_HASHES; hi++) {
        for (let ci = 0; ci < HASH_STATE_WIDTH; ci++)
          row[traceOffHashState(K, hi) + ci] = hashStateLde[hi][ci][i];
        for (let cj = 0; cj < HASH_RATE; cj++)
          row[traceOffHashSigma(K, hi) + cj] = hashSigmaLde[hi][cj][i];
      }
      traceLeafHashes.push(leafHashFromValuesSalt(row, traceSaltsAll[i]));
    }
    const capR0 = layerCapHeight(this.capHeight, lde.ldeSize);
    const traceTree = new BatchedMerkleTree(traceLeafHashes, capR0);
    const traceCap = traceTree.cap();

    // ── 10. c polys for matmul ───────────────────────────────────────────
    const cPolys: bigint[][] = cNtts.map((cm) => intt(cm.map((v) => mod(v)), omega));
    const cLde: bigint[][] = cPolys.map((p) => evalOnCoset(p, lde));

    // ── 11. Transcript prefix + squeeze challenges ───────────────────────
    const tr = new FiatShamirTranscript();
    tr.appendU64(M);
    tr.appendU64(N);
    tr.appendU64(K);
    tr.appendU64(this.blowup);
    tr.appendU64(this.capHeight);
    tr.appendU64(b);
    tr.appendU64(bSource);
    tr.appendU64(bS);
    tr.appendU64(bSigma);
    tr.appendU64(h);
    tr.appendU64(w);
    trAppendHex32(tr, aOracleHash);
    tr.appendField(sqrtQn);
    trAppendHex32(tr, cVecHash(cNtts));
    // Public hash tokens
    for (const t of tokenM) tr.appendField(mod(t));
    for (const t of tokenS) tr.appendField(mod(t));
    for (const t of tokenO) tr.appendField(mod(t));
    for (const hc of traceCap) tr.append(hc);

    // Squeeze: ρ (rows/msg), α (sumcheck), λ_k (batch), β_lup (LogUp)
    const rho0 = tr.challenge(P);
    const rhos: bigint[] = new Array(M);
    { let acc = rho0; for (let m = 0; m < M; m++) { rhos[m] = acc; acc = fmul(acc, rho0); } }
    const rhoMsg = fadd(rhos[M - 2], fmul(rhos[M - 1], sqrtQn));

    const alpha = tr.challenge(P);
    const nQuotients = numAlphaSlots(K);
    const alphaPows: bigint[] = new Array(nQuotients);
    alphaPows[0] = alpha;
    for (let i = 1; i < nQuotients; i++) alphaPows[i] = fmul(alphaPows[i - 1], alpha);

    const lamK: bigint[] = new Array(K);
    for (let k = 0; k < K; k++) lamK[k] = tr.challenge(P);

    const betaLup = tr.challenge(P);

    // ── 12. Compute interaction columns using β_lup ──────────────────────
    const pmValsCols: bigint[][] = dmByteCols.map((col) => computeHelperInverse(betaLup, col));
    const psValsCols: bigint[][] = dsByteCols.map((col) => computeHelperInverse(betaLup, col));
    const qColVals: bigint[] = computeHelperInverse(betaLup, tNtt);
    const prValsCols: bigint[][] = rByteCols.map((col) => computeHelperInverse(betaLup, col));
    const zLupVals: bigint[] = computeZLup(N, pmValsCols, psValsCols, prValsCols, muVals, qColVals);

    const pmPolysBare: bigint[][] = pmValsCols.map((col) => intt(col, omega));
    const psPolysBare: bigint[][] = psValsCols.map((col) => intt(col, omega));
    const prPolysBare: bigint[][] = prValsCols.map((col) => intt(col, omega));
    const qColPolyBare: bigint[] = intt(qColVals, omega);
    const zLupPolyBare: bigint[] = intt(zLupVals, omega);

    // ── 13. Mask interaction columns ─────────────────────────────────────
    const rpmPolys: bigint[][] = Array.from({ length: NUM_BYTES }, () => randPoly(b));
    const rpsPolys: bigint[][] = Array.from({ length: NUM_BYTES }, () => randPoly(b));
    const rprPolys: bigint[][] = Array.from({ length: 2 * K }, () => randPoly(b));
    const rqColPoly: bigint[] = randPoly(b);
    const rzLupPoly: bigint[] = randPoly(b);

    const pmPolys: bigint[][] = pmPolysBare.map((p, j) => blindWithNminus1(p, rpmPolys[j], N));
    const psPolys: bigint[][] = psPolysBare.map((p, j) => blindWithNminus1(p, rpsPolys[j], N));
    const prPolys: bigint[][] = prPolysBare.map((p, j) => blindWithNminus1(p, rprPolys[j], N));
    const qColPoly: bigint[] = blindWithNminus1(qColPolyBare, rqColPoly, N);
    const zLupPoly: bigint[] = blindWithNminus1(zLupPolyBare, rzLupPoly, N);

    // ── 14. LDE interaction columns ──────────────────────────────────────
    const pmLde: bigint[][] = pmPolys.map((p) => evalOnCoset(p, lde));
    const psLde: bigint[][] = psPolys.map((p) => evalOnCoset(p, lde));
    const prLde: bigint[][] = prPolys.map((p) => evalOnCoset(p, lde));
    const qColLde: bigint[] = evalOnCoset(qColPoly, lde);
    const zLupLde: bigint[] = evalOnCoset(zLupPoly, lde);

    // ── 15. Round 0.5 Merkle commit (18 interaction cols) ────────────────
    const interSaltsAll: Uint8Array[] = randomSalts(lde.ldeSize);
    const interLeafHashes: Uint8Array[] = [];
    for (let i = 0; i < lde.ldeSize; i++) {
      const row: bigint[] = new Array(interColCount(K));
      for (let j = 0; j < NUM_BYTES; j++) {
        row[interOffPm() + j] = pmLde[j][i];
        row[interOffPs() + j] = psLde[j][i];
      }
      for (let j = 0; j < 2 * K; j++) row[interOffPr() + j] = prLde[j][i];
      row[interOffQcol(K)] = qColLde[i];
      row[interOffZlup(K)] = zLupLde[i];
      interLeafHashes.push(leafHashFromValuesSalt(row, interSaltsAll[i]));
    }
    const interTree = new BatchedMerkleTree(interLeafHashes, capR0);
    const interCap = interTree.cap();
    for (const hc of interCap) tr.append(hc);

    // ── 16. Aurora blinding: β claim and ρ_aurora ────────────────────────
    const betaAur = fadd(mod(rAurPoly[0]), mod(rAurPoly[N]));
    tr.appendField(betaAur);
    const rhoAurora = tr.challenge(P);

    // ── 17. σ_α, Λ'_α, and Aurora auxiliaries R, Q ──────────────────────
    const sigmaAlpha = sigmaAlphaCoeffs(alpha, N, omega);
    const lambdaAlpha = lambdaAlphaCoeffs(alpha, N, omega, psi);
    const alphaN = fpow(alpha, Nbig);
    const alphaNplus1 = fadd(alphaN, 1n);

    let gBatch: bigint[] = [];
    let fBatch: bigint[] = [];
    for (let k = 0; k < K; k++) {
      gBatch = polyAddScaled(gBatch, gHatPolys[k], lamK[k]);
      fBatch = polyAddScaled(fBatch, bNttPolys[k], lamK[k]);
    }
    const term1 = polyMul(gBatch, sigmaAlpha);
    const term2 = polyMul(fBatch, lambdaAlpha);
    const pZeroTarget = polySub(term1, term2);
    let pBlinded: bigint[] = new Array(pZeroTarget.length).fill(0n);
    for (let j = 0; j < pZeroTarget.length; j++) {
      pBlinded[j] = fmul(rhoAurora, pZeroTarget[j]);
    }
    pBlinded = polyAddInto(pBlinded, rAurPoly);
    pBlinded[0] = fsub(pBlinded[0], betaAur);
    const { quot: Qpoly, rem: remN } = divByXNminus1(pBlinded, N);
    if (mod(remN[0] ?? 0n) !== 0n)
      throw new Error(`Aurora remainder not divisible by X (const=${remN[0]})`);
    const Rpoly = remN.slice(1);

    const RcolPoly = Rpoly;
    const Q0colPoly = Qpoly.slice(0, N);
    const Q1colPoly = Qpoly.slice(N);
    if (Q1colPoly.length > b - 1) throw new Error(`Aurora Q1 degree overflow`);
    const auxRLde = evalOnCoset(RcolPoly, lde);
    const auxQ0Lde = evalOnCoset(Q0colPoly, lde);
    const auxQ1Lde = evalOnCoset(Q1colPoly, lde);
    const auxSaltsAll: Uint8Array[] = randomSalts(lde.ldeSize);
    const auxLeafHashes: Uint8Array[] = auxRLde.map((rv, i) =>
      leafHashFromValuesSalt([rv, auxQ0Lde[i], auxQ1Lde[i]], auxSaltsAll[i]),
    );
    const auxTree = new BatchedMerkleTree(auxLeafHashes, capR0);
    const auxCap = auxTree.cap();
    for (const hc of auxCap) tr.append(hc);

    // ── 18. Precompute hash constraint LDE helpers ─────────────────────
    const omegaShift = this.blowup; // ω = ldeOmega^blowup

    // f_abs polynomial (absorb selector) LDE
    const fAbsVals = buildAbsorbSelectorValues(N);
    const fAbsPoly = intt(fAbsVals, omega);
    const fAbsLde: bigint[] = evalOnCoset(fAbsPoly, lde);

    // arc1, arc2 periodic polynomials LDE (12 components each)
    const arc1Lde: bigint[][] = [];
    const arc2Lde: bigint[][] = [];
    for (let comp = 0; comp < HASH_STATE_WIDTH; comp++) {
      const a1Vals = buildPeriodicArcValues(N, RESCUE_ARC1, comp);
      arc1Lde.push(evalOnCoset(intt(a1Vals, omega), lde));
      const a2Vals = buildPeriodicArcValues(N, RESCUE_ARC2, comp);
      arc2Lde.push(evalOnCoset(intt(a2Vals, omega), lde));
    }

    // Source column LDEs (already have mLde, mOrigLde, mSenderLde)
    const sourceLdes: bigint[][] = [mLde, mSenderLde, mOrigLde];

    // ω^{N-1} for C1b/C3 divisor
    const omegaNm1 = fpow(omega, Nbig - 1n);

    // Precompute per-LDE-point divisors
    const zDInv: bigint[] = new Array(lde.ldeSize);
    const invXminus1: bigint[] = new Array(lde.ldeSize);
    const invXminusOmNm1: bigint[] = new Array(lde.ldeSize);
    const xMinusOmNm1: bigint[] = new Array(lde.ldeSize);
    for (let i = 0; i < lde.ldeSize; i++) {
      const x = lde.domain[i];
      const xN = fpow(x, Nbig);
      zDInv[i] = finv(fsub(xN, 1n));
      invXminus1[i] = finv(fsub(x, 1n));
      const diff = fsub(x, omegaNm1);
      xMinusOmNm1[i] = diff;
      invXminusOmNm1[i] = finv(diff);
    }

    // ── 19. Build CP on LDE (all 2K+124 α-slots) ────────────────────────
    const cpLde: bigint[] = new Array(lde.ldeSize);
    for (let i = 0; i < lde.ldeSize; i++) {
      // --- Slots 0..2K+21: same as range version ---
      // Slot 0: matmul + msg
      let matmul = 0n;
      for (let m = 0; m < M; m++) {
        let inner = 0n;
        for (let k = 0; k < K; k++) inner = fadd(inner, fmul(aLde[m][k][i], bNttLde[k][i]));
        matmul = fadd(matmul, fmul(rhos[m], fsub(inner, cLde[m][i])));
      }
      matmul = fadd(matmul, fmul(rhoMsg, mLde[i]));
      let cp = fmul(alphaPows[0], fmul(matmul, zDInv[i]));

      // Slots 1..K: range recompose (ĝ + 2^15) − (gLo + 256·gHi)
      for (let k = 0; k < K; k++) {
        const rc = fsub(fadd(gHatLde[k][i], R_SHIFT), fadd(gloLde[k][i], fmul(256n, ghiLde[k][i])));
        cp = fadd(cp, fmul(alphaPows[1 + k], fmul(rc, zDInv[i])));
      }

      // Slot K+1: Balance
      const bal = fsub(mOrigLde[i], fadd(mSenderLde[i], mLde[i]));
      cp = fadd(cp, fmul(alphaPows[K + 1], fmul(bal, zDInv[i])));

      // Slot K+2: Recompose m
      let recompM = mLde[i];
      for (let j = 0; j < NUM_BYTES; j++) recompM = fsub(recompM, fmul(POW256[j], dmLde[j][i]));
      cp = fadd(cp, fmul(alphaPows[K + 2], fmul(recompM, zDInv[i])));

      // Slot K+3: Recompose m_sender
      let recompS = mSenderLde[i];
      for (let j = 0; j < NUM_BYTES; j++) recompS = fsub(recompS, fmul(POW256[j], dsLde[j][i]));
      cp = fadd(cp, fmul(alphaPows[K + 3], fmul(recompS, zDInv[i])));

      // Slot K+4: LogUp accumulator transition (includes Σpr)
      const iNext = (i + omegaShift) % lde.ldeSize;
      let accTrans = fsub(zLupLde[iNext], zLupLde[i]);
      for (let j = 0; j < NUM_BYTES; j++) { accTrans = fsub(accTrans, pmLde[j][i]); accTrans = fsub(accTrans, psLde[j][i]); }
      for (let j = 0; j < 2 * K; j++) accTrans = fsub(accTrans, prLde[j][i]);
      accTrans = fadd(accTrans, fmul(muLde[i], qColLde[i]));
      cp = fadd(cp, fmul(alphaPows[K + 4], fmul(accTrans, zDInv[i])));

      // Slots K+5..K+12: Inverse correctness p^(m)
      for (let j = 0; j < NUM_BYTES; j++) {
        const inv_m = fsub(fmul(pmLde[j][i], fsub(betaLup, dmLde[j][i])), 1n);
        cp = fadd(cp, fmul(alphaPows[K + 5 + j], fmul(inv_m, zDInv[i])));
      }
      // Slots K+13..K+20: Inverse correctness p^(s)
      for (let j = 0; j < NUM_BYTES; j++) {
        const inv_s = fsub(fmul(psLde[j][i], fsub(betaLup, dsLde[j][i])), 1n);
        cp = fadd(cp, fmul(alphaPows[K + 13 + j], fmul(inv_s, zDInv[i])));
      }
      // Slots K+21..K+20+2K: Inverse correctness p^(r) (r-byte lookups)
      for (let j = 0; j < 2 * K; j++) {
        const rbv = j < K ? gloLde[j][i] : ghiLde[j - K][i];
        const inv_r = fsub(fmul(prLde[j][i], fsub(betaLup, rbv)), 1n);
        cp = fadd(cp, fmul(alphaPows[K + 21 + j], fmul(inv_r, zDInv[i])));
      }
      // Slot K+21+2K: Inverse correctness q
      const inv_t = fsub(fmul(qColLde[i], fsub(betaLup, tLde[i])), 1n);
      cp = fadd(cp, fmul(alphaPows[K + 21 + 2 * K], fmul(inv_t, zDInv[i])));

      // --- Slots 3K+22..3K+123: Hash constraints ---
      const baseC1a = alphaOffC1a(K);
      const baseC1b = alphaOffC1b(K);
      const baseC2 = alphaOffC2(K);
      const baseC3 = alphaOffC3(K);

      for (let hi = 0; hi < NUM_HASHES; hi++) {
        // ── C1a: σ_j - s_j - f_abs · source(ω^j x) = 0 (8 per hash) ──
        for (let j = 0; j < HASH_RATE; j++) {
          const shiftIdx = (i + j * omegaShift) % lde.ldeSize;
          const srcShifted = sourceLdes[hi][shiftIdx];
          const c1aNum = fsub(hashSigmaLde[hi][j][i], fadd(hashStateLde[hi][j][i], fmul(fAbsLde[i], srcShifted)));
          const slotIdx = baseC1a + hi * HASH_RATE + j;
          cp = fadd(cp, fmul(alphaPows[slotIdx], fmul(c1aNum, zDInv[i])));
        }

        // ── C1b: (M^{-1}(s(ωx)-arc2))^3 - (M·σ̂^3 + arc1) = 0 (12 per hash) ──
        // Get s(ωx) for all 12 components
        const sNext: bigint[] = new Array(HASH_STATE_WIDTH);
        const iOmega = (i + omegaShift) % lde.ldeSize;
        for (let ci = 0; ci < HASH_STATE_WIDTH; ci++)
          sNext[ci] = hashStateLde[hi][ci][iOmega];

        // LHS: M^{-1}(s_next - arc2), then cube
        const sMinusArc2: bigint[] = new Array(HASH_STATE_WIDTH);
        for (let ci = 0; ci < HASH_STATE_WIDTH; ci++)
          sMinusArc2[ci] = fsub(sNext[ci], arc2Lde[ci][i]);
        // M^{-1} multiply
        const mInvApplied: bigint[] = new Array(HASH_STATE_WIDTH).fill(0n);
        for (let ci = 0; ci < HASH_STATE_WIDTH; ci++)
          for (let cj = 0; cj < HASH_STATE_WIDTH; cj++)
            mInvApplied[ci] = fadd(mInvApplied[ci], fmul(RESCUE_MINV[ci][cj], sMinusArc2[cj]));
        // Cube each component
        const lhsCubed: bigint[] = mInvApplied.map((v) => fmul(fmul(v, v), v));

        // RHS: σ̂ = (σ_0..7, s_8..11), cube, M·, + arc1
        const sigmaHat: bigint[] = new Array(HASH_STATE_WIDTH);
        for (let cj = 0; cj < HASH_RATE; cj++) sigmaHat[cj] = hashSigmaLde[hi][cj][i];
        for (let cj = HASH_RATE; cj < HASH_STATE_WIDTH; cj++) sigmaHat[cj] = hashStateLde[hi][cj][i];
        const sigCubed: bigint[] = sigmaHat.map((v) => fmul(fmul(v, v), v));
        // M · sigCubed
        const mApplied: bigint[] = new Array(HASH_STATE_WIDTH).fill(0n);
        for (let ci = 0; ci < HASH_STATE_WIDTH; ci++)
          for (let cj = 0; cj < HASH_STATE_WIDTH; cj++)
            mApplied[ci] = fadd(mApplied[ci], fmul(RESCUE_M[ci][cj], sigCubed[cj]));
        // + arc1
        const rhs: bigint[] = new Array(HASH_STATE_WIDTH);
        for (let ci = 0; ci < HASH_STATE_WIDTH; ci++) rhs[ci] = fadd(mApplied[ci], arc1Lde[ci][i]);

        // C1b numerator = LHS - RHS, quotient by Z_H/(x-ω^{N-1})
        // = num * (x - ω^{N-1}) / (x^N - 1) = num * xMinusOmNm1 * zDInv
        for (let ci = 0; ci < HASH_STATE_WIDTH; ci++) {
          const c1bNum = fsub(lhsCubed[ci], rhs[ci]);
          const slotIdx = baseC1b + hi * HASH_STATE_WIDTH + ci;
          cp = fadd(cp, fmul(alphaPows[slotIdx], fmul(fmul(c1bNum, xMinusOmNm1[i]), zDInv[i])));
        }

        // ── C2: s(1) - IV = 0 (12 per hash), quotient by 1/(x-1) ──
        for (let ci = 0; ci < HASH_STATE_WIDTH; ci++) {
          const c2Num = hashStateLde[hi][ci][i]; // IV = 0, so just s_i(x)
          const slotIdx = baseC2 + hi * HASH_STATE_WIDTH + ci;
          cp = fadd(cp, fmul(alphaPows[slotIdx], fmul(c2Num, invXminus1[i])));
        }

        // ── C3: s(ω^{N-1}) - token = 0 (τ=2 per hash), quotient by 1/(x-ω^{N-1}) ──
        for (let lane = 0; lane < HASH_OUTPUT_LANES; lane++) {
          const c3Num = fsub(hashStateLde[hi][lane][i], mod(tokens[hi][lane]));
          const slotIdx = baseC3 + hi * HASH_OUTPUT_LANES + lane;
          cp = fadd(cp, fmul(alphaPows[slotIdx], fmul(c3Num, invXminusOmNm1[i])));
        }
      }

      cpLde[i] = cp;
    }

    // ── 20. Chunk CP + telescoping-blind ─────────────────────────────────
    const cpCoeffs = inttCoset(cpLde, lde);
    for (let j = dChunks * w; j < cpCoeffs.length; j++) {
      if (mod(cpCoeffs[j]) !== 0n) throw new Error(`CP degree overflow at coeff ${j}`);
    }
    const cpChunks: bigint[][] = [];
    for (let j = 0; j < dChunks; j++) {
      const chunk = new Array<bigint>(w).fill(0n);
      for (let t = 0; t < w; t++) {
        const idx = j * w + t;
        chunk[t] = idx < cpCoeffs.length ? mod(cpCoeffs[idx]) : 0n;
      }
      cpChunks.push(chunk);
    }
    const tBlind: bigint[][] = new Array(dChunks + 1);
    tBlind[0] = [];
    tBlind[dChunks] = [];
    for (let j = 1; j < dChunks; j++) tBlind[j] = randPoly(h);
    const cpChunkPolys: bigint[][] = [];
    for (let j = 0; j < dChunks; j++) {
      let cj = cpChunks[j].slice();
      cj = polyAddInto(cj, shiftUp(tBlind[j + 1], w));
      cj = polySub(cj, tBlind[j]);
      cpChunkPolys.push(cj);
    }
    const cpChunkLde: bigint[][] = cpChunkPolys.map((p) => evalOnCoset(p, lde));

    const cpChunkSaltsAll: Uint8Array[] = randomSalts(lde.ldeSize);
    const cpChunkLeafHashes: Uint8Array[] = [];
    for (let i = 0; i < lde.ldeSize; i++) {
      const row: bigint[] = new Array(dChunks);
      for (let j = 0; j < dChunks; j++) row[j] = cpChunkLde[j][i];
      cpChunkLeafHashes.push(leafHashFromValuesSalt(row, cpChunkSaltsAll[i]));
    }
    const cpChunkTree = new BatchedMerkleTree(cpChunkLeafHashes, capR0);
    const cpChunkCap = cpChunkTree.cap();
    for (const hc of cpChunkCap) tr.append(hc);

    // ── 21. OOD point z ──────────────────────────────────────────────────
    const z = tr.challenge(P);
    const omegaZ = fmul(omega, z);

    // ── 22. OOD openings ─────────────────────────────────────────────────
    const oodBNttZ: bigint[] = bNttPolys.map((p) => polyEval(p, z));
    const oodGHatZ: bigint[] = gHatPolys.map((p) => polyEval(p, z));
    const oodGloZ: bigint[] = gloPolys.map((p) => polyEval(p, z));
    const oodGhiZ: bigint[] = ghiPolys.map((p) => polyEval(p, z));
    const oodAZ: bigint[] = new Array(M * K);
    for (let m = 0; m < M; m++)
      for (let k = 0; k < K; k++) oodAZ[m * K + k] = polyEval(aPolys[m][k], z);
    const oodTZ = polyEval(tPoly, z);
    const oodMZ = polyEval(mPoly, z);
    const oodMOrigZ = polyEval(mOrigPoly, z);
    const oodMSenderZ = polyEval(mSenderPoly, z);
    const oodDmZ: bigint[] = dmPolys.map((p) => polyEval(p, z));
    const oodDsZ: bigint[] = dsPolys.map((p) => polyEval(p, z));
    const oodPmZ: bigint[] = pmPolys.map((p) => polyEval(p, z));
    const oodPsZ: bigint[] = psPolys.map((p) => polyEval(p, z));
    const oodPrZ: bigint[] = prPolys.map((p) => polyEval(p, z));
    const oodQcolZ = polyEval(qColPoly, z);
    const oodMuZ = polyEval(muPoly, z);
    const oodZlupZ = polyEval(zLupPoly, z);
    const oodZlupOmegaZ = polyEval(zLupPoly, omegaZ);
    const oodRAurZ = polyEval(rAurPoly, z);
    const oodRZ = polyEval(RcolPoly, z);
    const oodQZ = polyEval(Q0colPoly, z);
    const oodQ1Z = polyEval(Q1colPoly, z);
    const oodCpChunkZ: bigint[] = cpChunkPolys.map((p) => polyEval(p, z));

    // Hash OOD: state at z, state at ωz, sigma at z
    const oodHashStateZ: bigint[][] = [];
    const oodHashStateOmegaZ: bigint[][] = [];
    const oodHashSigmaZ: bigint[][] = [];
    for (let hi = 0; hi < NUM_HASHES; hi++) {
      oodHashStateZ.push(hashStatePolys[hi].map((p) => polyEval(p, z)));
      oodHashStateOmegaZ.push(hashStatePolys[hi].map((p) => polyEval(p, omegaZ)));
      oodHashSigmaZ.push(hashSigmaPolys[hi].map((p) => polyEval(p, z)));
    }

    // Source shifted OOD: source(ω^j z) for j=1..7, 3 sources
    const sourcePolys: bigint[][] = [mPoly, mSenderPoly, mOrigPoly];
    const oodSourceShifts: bigint[][] = [];
    for (let hi = 0; hi < NUM_HASHES; hi++) {
      const shifts: bigint[] = [];
      for (let j = 1; j <= 7; j++) {
        const omegaJz = fmul(fpow(omega, BigInt(j)), z);
        shifts.push(polyEval(sourcePolys[hi], omegaJz));
      }
      oodSourceShifts.push(shifts);
    }

    // Absorb OOD values into transcript
    for (const v of oodBNttZ) tr.appendField(v);
    for (const v of oodGHatZ) tr.appendField(v);
    for (const v of oodGloZ) tr.appendField(v);
    for (const v of oodGhiZ) tr.appendField(v);
    for (const v of oodAZ) tr.appendField(v);
    tr.appendField(oodTZ);
    tr.appendField(oodMZ);
    tr.appendField(oodMOrigZ);
    tr.appendField(oodMSenderZ);
    for (const v of oodDmZ) tr.appendField(v);
    for (const v of oodDsZ) tr.appendField(v);
    for (const v of oodPmZ) tr.appendField(v);
    for (const v of oodPsZ) tr.appendField(v);
    for (const v of oodPrZ) tr.appendField(v);
    tr.appendField(oodQcolZ);
    tr.appendField(oodMuZ);
    tr.appendField(oodZlupZ);
    tr.appendField(oodZlupOmegaZ);
    tr.appendField(oodRAurZ);
    tr.appendField(oodRZ);
    tr.appendField(oodQZ);
    tr.appendField(oodQ1Z);
    for (const v of oodCpChunkZ) tr.appendField(v);
    for (let hi = 0; hi < NUM_HASHES; hi++) for (const v of oodHashStateZ[hi]) tr.appendField(v);
    for (let hi = 0; hi < NUM_HASHES; hi++) for (const v of oodHashStateOmegaZ[hi]) tr.appendField(v);
    for (let hi = 0; hi < NUM_HASHES; hi++) for (const v of oodHashSigmaZ[hi]) tr.appendField(v);
    for (let hi = 0; hi < NUM_HASHES; hi++) for (const v of oodSourceShifts[hi]) tr.appendField(v);

    // ── 23. Prover-side OOD sanity checks ────────────────────────────────
    {
      const zN = fpow(z, Nbig);
      const zDInvZ = finv(fsub(zN, 1n));
      // (a) CP consistency for range slots
      let matmulZ = 0n;
      for (let m = 0; m < M; m++) {
        let inner = 0n;
        for (let k = 0; k < K; k++) inner = fadd(inner, fmul(oodAZ[m * K + k], oodBNttZ[k]));
        const cAtZ = polyEval(cPolys[m], z);
        matmulZ = fadd(matmulZ, fmul(rhos[m], fsub(inner, cAtZ)));
      }
      matmulZ = fadd(matmulZ, fmul(rhoMsg, oodMZ));
      let cpExpected = fmul(alphaPows[0], fmul(matmulZ, zDInvZ));
      for (let k = 0; k < K; k++) {
        const rc = fsub(fadd(oodGHatZ[k], R_SHIFT), fadd(oodGloZ[k], fmul(256n, oodGhiZ[k])));
        cpExpected = fadd(cpExpected, fmul(alphaPows[1 + k], fmul(rc, zDInvZ)));
      }
      cpExpected = fadd(cpExpected, fmul(alphaPows[K+1], fmul(fsub(oodMOrigZ, fadd(oodMSenderZ, oodMZ)), zDInvZ)));
      let rmZ = oodMZ; for (let j = 0; j < NUM_BYTES; j++) rmZ = fsub(rmZ, fmul(POW256[j], oodDmZ[j]));
      cpExpected = fadd(cpExpected, fmul(alphaPows[K+2], fmul(rmZ, zDInvZ)));
      let rsZ = oodMSenderZ; for (let j = 0; j < NUM_BYTES; j++) rsZ = fsub(rsZ, fmul(POW256[j], oodDsZ[j]));
      cpExpected = fadd(cpExpected, fmul(alphaPows[K+3], fmul(rsZ, zDInvZ)));
      let accZ = fsub(oodZlupOmegaZ, oodZlupZ);
      for (let j = 0; j < NUM_BYTES; j++) { accZ = fsub(accZ, oodPmZ[j]); accZ = fsub(accZ, oodPsZ[j]); }
      for (let j = 0; j < 2 * K; j++) accZ = fsub(accZ, oodPrZ[j]);
      accZ = fadd(accZ, fmul(oodMuZ, oodQcolZ));
      cpExpected = fadd(cpExpected, fmul(alphaPows[K+4], fmul(accZ, zDInvZ)));
      for (let j = 0; j < NUM_BYTES; j++) {
        cpExpected = fadd(cpExpected, fmul(alphaPows[K+5+j], fmul(fsub(fmul(oodPmZ[j], fsub(betaLup, oodDmZ[j])), 1n), zDInvZ)));
      }
      for (let j = 0; j < NUM_BYTES; j++) {
        cpExpected = fadd(cpExpected, fmul(alphaPows[K+13+j], fmul(fsub(fmul(oodPsZ[j], fsub(betaLup, oodDsZ[j])), 1n), zDInvZ)));
      }
      for (let j = 0; j < 2 * K; j++) {
        const rbv = j < K ? oodGloZ[j] : oodGhiZ[j - K];
        cpExpected = fadd(cpExpected, fmul(alphaPows[K+21+j], fmul(fsub(fmul(oodPrZ[j], fsub(betaLup, rbv)), 1n), zDInvZ)));
      }
      cpExpected = fadd(cpExpected, fmul(alphaPows[K+21+2*K], fmul(fsub(fmul(oodQcolZ, fsub(betaLup, oodTZ)), 1n), zDInvZ)));

      // Hash constraints at z
      const fAbsZ = evalAbsorbSelectorAtZ(z, N);
      const zMinusOmNm1 = fsub(z, omegaNm1);
      const invZminus1 = finv(fsub(z, 1n));
      const invZminusOmNm1 = finv(zMinusOmNm1);

      for (let hi = 0; hi < NUM_HASHES; hi++) {
        // C1a at z
        for (let j = 0; j < HASH_RATE; j++) {
          const omJz = fmul(fpow(omega, BigInt(j)), z);
          const srcAtOmJz = (j === 0) ? polyEval(sourcePolys[hi], z) : oodSourceShifts[hi][j - 1];
          const c1a = fsub(oodHashSigmaZ[hi][j], fadd(oodHashStateZ[hi][j], fmul(fAbsZ, srcAtOmJz)));
          cpExpected = fadd(cpExpected, fmul(alphaPows[alphaOffC1a(K) + hi * HASH_RATE + j], fmul(c1a, zDInvZ)));
        }
        // C1b at z
        const sNextZ: bigint[] = oodHashStateOmegaZ[hi];
        const arc2AtZ: bigint[] = new Array(HASH_STATE_WIDTH);
        const arc1AtZ: bigint[] = new Array(HASH_STATE_WIDTH);
        for (let ci = 0; ci < HASH_STATE_WIDTH; ci++) {
          const a2vals = RESCUE_ARC2.map((row) => row[ci]);
          arc2AtZ[ci] = evalPeriodicAtZ(a2vals, z, N, omega);
          const a1vals = RESCUE_ARC1.map((row) => row[ci]);
          arc1AtZ[ci] = evalPeriodicAtZ(a1vals, z, N, omega);
        }
        const smA2: bigint[] = sNextZ.map((v, ci) => fsub(v, arc2AtZ[ci]));
        const mInvZ: bigint[] = new Array(HASH_STATE_WIDTH).fill(0n);
        for (let ci = 0; ci < HASH_STATE_WIDTH; ci++)
          for (let cj = 0; cj < HASH_STATE_WIDTH; cj++)
            mInvZ[ci] = fadd(mInvZ[ci], fmul(RESCUE_MINV[ci][cj], smA2[cj]));
        const lhsC: bigint[] = mInvZ.map((v) => fmul(fmul(v, v), v));

        const sigHatZ: bigint[] = new Array(HASH_STATE_WIDTH);
        for (let cj = 0; cj < HASH_RATE; cj++) sigHatZ[cj] = oodHashSigmaZ[hi][cj];
        for (let cj = HASH_RATE; cj < HASH_STATE_WIDTH; cj++) sigHatZ[cj] = oodHashStateZ[hi][cj];
        const scZ: bigint[] = sigHatZ.map((v) => fmul(fmul(v, v), v));
        const mAppZ: bigint[] = new Array(HASH_STATE_WIDTH).fill(0n);
        for (let ci = 0; ci < HASH_STATE_WIDTH; ci++)
          for (let cj = 0; cj < HASH_STATE_WIDTH; cj++)
            mAppZ[ci] = fadd(mAppZ[ci], fmul(RESCUE_M[ci][cj], scZ[cj]));
        const rhsC: bigint[] = mAppZ.map((v, ci) => fadd(v, arc1AtZ[ci]));

        for (let ci = 0; ci < HASH_STATE_WIDTH; ci++) {
          const c1bNum = fsub(lhsC[ci], rhsC[ci]);
          cpExpected = fadd(cpExpected, fmul(alphaPows[alphaOffC1b(K) + hi * HASH_STATE_WIDTH + ci],
            fmul(fmul(c1bNum, zMinusOmNm1), zDInvZ)));
        }
        // C2 at z
        for (let ci = 0; ci < HASH_STATE_WIDTH; ci++) {
          cpExpected = fadd(cpExpected, fmul(alphaPows[alphaOffC2(K) + hi * HASH_STATE_WIDTH + ci],
            fmul(oodHashStateZ[hi][ci], invZminus1)));
        }
        // C3 at z
        for (let lane = 0; lane < HASH_OUTPUT_LANES; lane++) {
          const c3n = fsub(oodHashStateZ[hi][lane], mod(tokens[hi][lane]));
          cpExpected = fadd(cpExpected, fmul(alphaPows[alphaOffC3(K) + hi * HASH_OUTPUT_LANES + lane],
            fmul(c3n, invZminusOmNm1)));
        }
      }

      let cpAtZ = 0n;
      let zPow = 1n; const zW = fpow(z, BigInt(w));
      for (let j = 0; j < dChunks; j++) { cpAtZ = fadd(cpAtZ, fmul(zPow, oodCpChunkZ[j])); zPow = fmul(zPow, zW); }
      if (cpAtZ !== cpExpected) throw new Error(`prover OOD CP self-check failed`);

      // (b) Aurora zero-target
      const sigmaAtZ = polyEval(sigmaAlpha, z);
      const lambdaAtZ = fmul(
        fsub(fmul(alpha, fsub(1n, zN)), fmul(fmul(psi, z), alphaNplus1)),
        finv(fmul(Nbig, fsub(alpha, fmul(psi, z)))),
      );
      let gBatchZ = 0n, fBatchZ = 0n;
      for (let k = 0; k < K; k++) {
        gBatchZ = fadd(gBatchZ, fmul(lamK[k], oodGHatZ[k]));
        fBatchZ = fadd(fBatchZ, fmul(lamK[k], oodBNttZ[k]));
      }
      const lhsAur = fadd(fmul(rhoAurora, fsub(fmul(gBatchZ, sigmaAtZ), fmul(fBatchZ, lambdaAtZ))), oodRAurZ);
      const qAtZ = fadd(oodQZ, fmul(zN, oodQ1Z));
      const rhsAur = fadd(betaAur, fadd(fmul(z, oodRZ), fmul(qAtZ, fsub(zN, 1n))));
      if (lhsAur !== rhsAur) throw new Error(`prover Aurora self-check failed`);
    }

    // ── 24. Mask polynomial R_deep ───────────────────────────────────────
    const bDeep = bSource; // max blinding budget drives DEEP quotient degree
    const maskPoly: bigint[] = randPoly(N + bDeep);
    const maskLde: bigint[] = evalOnCoset(maskPoly, lde);
    const maskSaltsAll: Uint8Array[] = randomSalts(lde.ldeSize);
    const maskLeafHashes = maskLde.map((v, i) => leafHashFromValuesSalt([v], maskSaltsAll[i]));
    const maskTree = new BatchedMerkleTree(maskLeafHashes, capR0);
    const maskCap = maskTree.cap();
    for (const hc of maskCap) tr.append(hc);

    // ── 25. DEEP combiners γ ─────────────────────────────────────────────
    const gam = (n: number): bigint[] => { const o: bigint[] = []; for (let i = 0; i < n; i++) o.push(tr.challenge(P)); return o; };
    const gBNttZ = gam(K);
    const gGHatZ = gam(K);
    const gGloZ = gam(K);
    const gGhiZ = gam(K);
    const gAZ = gam(M * K);
    const gTZ = tr.challenge(P);
    const gM = tr.challenge(P);
    const gMOrig = tr.challenge(P);
    const gMSender = tr.challenge(P);
    const gDmZ = gam(NUM_BYTES);
    const gDsZ = gam(NUM_BYTES);
    const gPmZ = gam(NUM_BYTES);
    const gPsZ = gam(NUM_BYTES);
    const gPrZ = gam(2 * K);
    const gQcol = tr.challenge(P);
    const gMu = tr.challenge(P);
    const gZlup = tr.challenge(P);
    const gZlupOmega = tr.challenge(P);
    const gRAur = tr.challenge(P);
    const gR = tr.challenge(P);
    const gQ = tr.challenge(P);
    const gCpChunk = gam(dChunks);
    // Hash DEEP combiners: state@z, state@ωz, sigma@z
    const gHashStateZ: bigint[][] = [];
    const gHashStateOmegaZ: bigint[][] = [];
    const gHashSigmaZ: bigint[][] = [];
    for (let hi = 0; hi < NUM_HASHES; hi++) {
      gHashStateZ.push(gam(HASH_STATE_WIDTH));
      gHashStateOmegaZ.push(gam(HASH_STATE_WIDTH));
      gHashSigmaZ.push(gam(HASH_RATE));
    }
    // Source shifts: source@ω^j z, j=1..7, 3 sources
    const gSourceShifts: bigint[][] = [];
    for (let hi = 0; hi < NUM_HASHES; hi++) gSourceShifts.push(gam(7));

    // ── 26. Masked DEEP polynomial h(x) ──────────────────────────────────
    const hLde: bigint[] = new Array(lde.ldeSize);
    for (let i = 0; i < lde.ldeSize; i++) {
      const ell = lde.domain[i];
      const invEllZ = finv(fsub(ell, z));
      const invEllOmegaZ = finv(fsub(ell, omegaZ));

      let val = 0n;
      // Standard columns @ z
      for (let k = 0; k < K; k++) val = fadd(val, fmul(gBNttZ[k], fmul(fsub(bNttLde[k][i], oodBNttZ[k]), invEllZ)));
      for (let k = 0; k < K; k++) val = fadd(val, fmul(gGHatZ[k], fmul(fsub(gHatLde[k][i], oodGHatZ[k]), invEllZ)));
      for (let k = 0; k < K; k++) val = fadd(val, fmul(gGloZ[k], fmul(fsub(gloLde[k][i], oodGloZ[k]), invEllZ)));
      for (let k = 0; k < K; k++) val = fadd(val, fmul(gGhiZ[k], fmul(fsub(ghiLde[k][i], oodGhiZ[k]), invEllZ)));
      for (let m = 0; m < M; m++)
        for (let k = 0; k < K; k++) val = fadd(val, fmul(gAZ[m*K+k], fmul(fsub(aLde[m][k][i], oodAZ[m*K+k]), invEllZ)));
      val = fadd(val, fmul(gTZ, fmul(fsub(tLde[i], oodTZ), invEllZ)));
      val = fadd(val, fmul(gM, fmul(fsub(mLde[i], oodMZ), invEllZ)));
      val = fadd(val, fmul(gMOrig, fmul(fsub(mOrigLde[i], oodMOrigZ), invEllZ)));
      val = fadd(val, fmul(gMSender, fmul(fsub(mSenderLde[i], oodMSenderZ), invEllZ)));
      for (let j = 0; j < NUM_BYTES; j++) val = fadd(val, fmul(gDmZ[j], fmul(fsub(dmLde[j][i], oodDmZ[j]), invEllZ)));
      for (let j = 0; j < NUM_BYTES; j++) val = fadd(val, fmul(gDsZ[j], fmul(fsub(dsLde[j][i], oodDsZ[j]), invEllZ)));
      for (let j = 0; j < NUM_BYTES; j++) val = fadd(val, fmul(gPmZ[j], fmul(fsub(pmLde[j][i], oodPmZ[j]), invEllZ)));
      for (let j = 0; j < NUM_BYTES; j++) val = fadd(val, fmul(gPsZ[j], fmul(fsub(psLde[j][i], oodPsZ[j]), invEllZ)));
      for (let j = 0; j < 2 * K; j++) val = fadd(val, fmul(gPrZ[j], fmul(fsub(prLde[j][i], oodPrZ[j]), invEllZ)));
      val = fadd(val, fmul(gQcol, fmul(fsub(qColLde[i], oodQcolZ), invEllZ)));
      val = fadd(val, fmul(gMu, fmul(fsub(muLde[i], oodMuZ), invEllZ)));
      val = fadd(val, fmul(gZlup, fmul(fsub(zLupLde[i], oodZlupZ), invEllZ)));
      val = fadd(val, fmul(gZlupOmega, fmul(fsub(zLupLde[i], oodZlupOmegaZ), invEllOmegaZ)));
      val = fadd(val, fmul(gRAur, fmul(fsub(rAurLde[i], oodRAurZ), invEllZ)));
      val = fadd(val, fmul(gR, fmul(fsub(auxRLde[i], oodRZ), invEllZ)));
      val = fadd(val, fmul(gQ, fmul(fsub(auxQ0Lde[i], oodQZ), invEllZ)));
      val = fadd(val, fmul(fadd(gQ, 1n), fmul(fsub(auxQ1Lde[i], oodQ1Z), invEllZ)));
      for (let j = 0; j < dChunks; j++) val = fadd(val, fmul(gCpChunk[j], fmul(fsub(cpChunkLde[j][i], oodCpChunkZ[j]), invEllZ)));

      // Hash columns: state @ z, state @ ωz, sigma @ z
      for (let hi = 0; hi < NUM_HASHES; hi++) {
        for (let ci = 0; ci < HASH_STATE_WIDTH; ci++) {
          val = fadd(val, fmul(gHashStateZ[hi][ci], fmul(fsub(hashStateLde[hi][ci][i], oodHashStateZ[hi][ci]), invEllZ)));
          val = fadd(val, fmul(gHashStateOmegaZ[hi][ci], fmul(fsub(hashStateLde[hi][ci][i], oodHashStateOmegaZ[hi][ci]), invEllOmegaZ)));
        }
        for (let cj = 0; cj < HASH_RATE; cj++)
          val = fadd(val, fmul(gHashSigmaZ[hi][cj], fmul(fsub(hashSigmaLde[hi][cj][i], oodHashSigmaZ[hi][cj]), invEllZ)));
      }

      // Source shifts: source(ω^j z), j=1..7
      for (let hi = 0; hi < NUM_HASHES; hi++) {
        for (let j = 1; j <= 7; j++) {
          const omJz = fmul(fpow(omega, BigInt(j)), z);
          const invEllOmJz = finv(fsub(ell, omJz));
          val = fadd(val, fmul(gSourceShifts[hi][j - 1], fmul(fsub(sourceLdes[hi][i], oodSourceShifts[hi][j - 1]), invEllOmJz)));
        }
      }

      val = fadd(val, maskLde[i]);
      hLde[i] = val;
    }

    // ── 27. Split h = g0 + x^N·g1 ───────────────────────────────────────
    const hCoeffs = inttCoset(hLde, lde);
    for (let j = N + bDeep; j < hCoeffs.length; j++) {
      if (mod(hCoeffs[j]) !== 0n) throw new Error(`h degree overflow at ${j}`);
    }
    const g0Coeffs = hCoeffs.slice(0, N);
    const g1Coeffs = hCoeffs.slice(N, N + bDeep);
    const g0Lde = evalOnCoset(g0Coeffs, lde);
    const g1Lde = evalOnCoset(g1Coeffs, lde);

    const splitSaltsAll: Uint8Array[] = randomSalts(lde.ldeSize);
    const splitLeafHashes = g0Lde.map((v, i) => leafHashFromValuesSalt([v, g1Lde[i]], splitSaltsAll[i]));
    const splitTree = new BatchedMerkleTree(splitLeafHashes, capR0);
    const splitCap = splitTree.cap();
    for (const hc of splitCap) tr.append(hc);

    // ── 28. Batch challenge λ and FRI ────────────────────────────────────
    const lambda = tr.challenge(P);
    const lambda2 = fmul(lambda, lambda);
    const lambda3 = fmul(lambda2, lambda);
    const lambda4 = fmul(lambda3, lambda);
    const hBatchEvals: bigint[] = new Array(lde.ldeSize);
    for (let i = 0; i < lde.ldeSize; i++) {
      const x = lde.domain[i];
      hBatchEvals[i] = fadd(
        fadd(g0Lde[i], fmul(lambda, g1Lde[i])),
        fadd(fmul(lambda2, fmul(x, auxRLde[i])), fadd(
          fmul(lambda3, auxQ0Lde[i]),
          fmul(lambda4, fmul(fpow(x, BigInt(N - b + 1)), auxQ1Lde[i])),
        )),
      );
    }

    // ── 29. ARITY-4 FRI commit phase ────────────────────────────────────
    const mu4 = fpow(lde.ldeOmega, BigInt(lde.ldeSize / FRI_ARITY));
    const friLayers: { evals: bigint[]; domain: bigint[] }[] = [
      { evals: hBatchEvals.slice(), domain: lde.domain.slice() },
    ];
    const friTrees: BatchedMerkleTree[] = [];
    const friCaps: Uint8Array[][] = [];
    const friBetas: bigint[] = [];
    const friSaltsAll: Uint8Array[][] = [];
    const friLayer0Salts = randomSalts(lde.ldeSize);
    friSaltsAll.push(friLayer0Salts);
    const tree0 = new BatchedMerkleTree(
      hBatchEvals.map((v, i) => leafHashFromValuesSalt([v], friLayer0Salts[i])), capR0,
    );
    friTrees.push(tree0);
    friCaps.push(tree0.cap());
    for (const hc of tree0.cap()) tr.append(hc);

    let curEvals = hBatchEvals.slice();
    let curDomain = lde.domain.slice();
    let curBound = N;
    let friFinalPoly: bigint[] = [];
    while (true) {
      const beta = tr.challenge(P);
      friBetas.push(beta);
      const folded = friFoldArity4(curEvals, curDomain, beta, mu4);
      curEvals = folded.newEvals;
      curDomain = folded.newDomain;
      curBound = curBound / FRI_ARITY;
      if (curBound > FINAL_POLY_BOUND) {
        friLayers.push({ evals: curEvals.slice(), domain: curDomain.slice() });
        const cap = layerCapHeight(this.capHeight, curEvals.length);
        const layerSalts = randomSalts(curEvals.length);
        friSaltsAll.push(layerSalts);
        const tree = new BatchedMerkleTree(
          curEvals.map((v, i) => leafHashFromValuesSalt([v], layerSalts[i])), cap,
        );
        friTrees.push(tree);
        friCaps.push(tree.cap());
        for (const hc of tree.cap()) tr.append(hc);
      } else {
        const finalLde: LdeCoset = {
          ldeOmega: fmul(curDomain[1], finv(curDomain[0])),
          cosetGen: curDomain[0],
          ldeSize: curEvals.length,
          domain: curDomain.slice(),
        };
        const finalCoeffs = inttCoset(curEvals, finalLde);
        for (let j = curBound; j < finalCoeffs.length; j++) {
          if (finalCoeffs[j] !== 0n) throw new Error(`FRI final poly degree overflow at coeff ${j}`);
        }
        friFinalPoly = finalCoeffs.slice(0, curBound);
        break;
      }
    }
    for (const c of friFinalPoly) tr.appendField(c);

    // ── 30. Grinding ─────────────────────────────────────────────────────
    let grindingNonce = 0n;
    { const savedState = tr.state;
      while (true) {
        const cand = keccak(concatBytes(savedState, u64BE(grindingNonce)));
        if (leadingZeroBitsBytes(cand) >= GRINDING_BITS) { tr.state = cand; break; }
        grindingNonce++;
      }
    }

    // ── 31. Query indices ────────────────────────────────────────────────
    const queryIndices: number[] = [];
    for (let i = 0; i < this.numQueries; i++) queryIndices.push(tr.challengeIndex(lde.ldeSize / FRI_ARITY));

    // ── 32. Openings at query positions ──────────────────────────────────
    const posSet = new Set<number>();
    for (const q of queryIndices) posSet.add(q);
    const positions = Array.from(posSet).sort((a, b2) => a - b2);

    const traceColValues = positions.map((p) => {
      const row: bigint[] = new Array(traceCols);
      for (let k = 0; k < K; k++) {
        row[traceOffBNtt(K)+k] = bNttLde[k][p];
        row[traceOffGHat(K)+k] = gHatLde[k][p];
        row[traceOffGlo(K)+k] = gloLde[k][p];
        row[traceOffGhi(K)+k] = ghiLde[k][p];
      }
      row[traceOffM(K)] = mLde[p];
      row[traceOffMOrig(K)] = mOrigLde[p];
      row[traceOffMSender(K)] = mSenderLde[p];
      for (let j = 0; j < NUM_BYTES; j++) { row[traceOffDm(K)+j] = dmLde[j][p]; row[traceOffDs(K)+j] = dsLde[j][p]; }
      row[traceOffMu(K)] = muLde[p];
      row[traceOffRAur(K)] = rAurLde[p];
      for (let hi = 0; hi < NUM_HASHES; hi++) {
        for (let ci = 0; ci < HASH_STATE_WIDTH; ci++) row[traceOffHashState(K,hi)+ci] = hashStateLde[hi][ci][p];
        for (let cj = 0; cj < HASH_RATE; cj++) row[traceOffHashSigma(K,hi)+cj] = hashSigmaLde[hi][cj][p];
      }
      return row;
    });
    const traceSalts = positions.map((p) => traceSaltsAll[p]);
    const traceBatchProof = traceTree.openBatch(positions);

    const interColValues = positions.map((p) => {
      const row: bigint[] = new Array(interColCount(K));
      for (let j = 0; j < NUM_BYTES; j++) { row[interOffPm()+j] = pmLde[j][p]; row[interOffPs()+j] = psLde[j][p]; }
      for (let j = 0; j < 2 * K; j++) row[interOffPr()+j] = prLde[j][p];
      row[interOffQcol(K)] = qColLde[p];
      row[interOffZlup(K)] = zLupLde[p];
      return row;
    });
    const interSalts = positions.map((p) => interSaltsAll[p]);
    const interBatchProof = interTree.openBatch(positions);

    const auxColValues = positions.map((p) => [auxRLde[p], auxQ0Lde[p], auxQ1Lde[p]]);
    const auxSalts = positions.map((p) => auxSaltsAll[p]);
    const auxBatchProof = auxTree.openBatch(positions);

    const cpChunkColValues = positions.map((p) => {
      const row: bigint[] = new Array(dChunks);
      for (let j = 0; j < dChunks; j++) row[j] = cpChunkLde[j][p];
      return row;
    });
    const cpChunkSalts = positions.map((p) => cpChunkSaltsAll[p]);
    const cpChunkBatchProof = cpChunkTree.openBatch(positions);

    const maskValues = positions.map((p) => maskLde[p]);
    const maskSalts = positions.map((p) => maskSaltsAll[p]);
    const maskBatchProof = maskTree.openBatch(positions);

    const splitColValues = positions.map((p) => [g0Lde[p], g1Lde[p]]);
    const splitSalts = positions.map((p) => splitSaltsAll[p]);
    const splitBatchProof = splitTree.openBatch(positions);

    const aColValues = positions.map((p) => {
      const row: bigint[] = new Array(M * K + 1);
      for (let m = 0; m < M; m++)
        for (let k = 0; k < K; k++) row[m*K+k] = aLde[m][k][p];
      row[M * K] = tLde[p];
      return row;
    });
    const aBatchProof = aTree.openBatch(positions);

    // FRI layer openings
    const friLayerPositions: number[][] = [];
    const friLayerValues: bigint[][] = [];
    const friLayerSalts: Uint8Array[][] = [];
    const friLayerProofs: Uint8Array[][] = [];
    for (let r = 0; r < friTrees.length; r++) {
      const evalsR = friLayers[r].evals;
      const nR = evalsR.length;
      const quarterR = nR / FRI_ARITY;
      const set = new Set<number>();
      for (const q of queryIndices) {
        const iR = q % quarterR;
        set.add(iR); set.add(iR + quarterR); set.add(iR + 2 * quarterR); set.add(iR + 3 * quarterR);
      }
      const pos = Array.from(set).sort((a, b2) => a - b2);
      friLayerPositions.push(pos);
      friLayerValues.push(pos.map((p) => evalsR[p]));
      friLayerSalts.push(pos.map((p) => friSaltsAll[r][p]));
      friLayerProofs.push(friTrees[r].openBatch(pos));
    }

    return {
      traceLength: N, numColumns: K, blowup: this.blowup, capHeight: this.capHeight,
      blindB: b, blindBSource: bSource, blindBState: bS, blindBSigma: bSigma,
      cpBlindH: h, numChunks: dChunks, cpChunkWidth: w,
      betaAur,
      tokenM, tokenS, tokenO,
      traceCap, tracePositions: positions, traceColValues, traceSalts, traceBatchProof,
      interCap, interColValues, interSalts, interBatchProof,
      auxCap, auxColValues, auxSalts, auxBatchProof,
      cpChunkCap, cpChunkColValues, cpChunkSalts, cpChunkBatchProof,
      maskCap, maskValues, maskSalts, maskBatchProof,
      splitCap, splitColValues, splitSalts, splitBatchProof,
      aCap, aColValues, aBatchProof,
      oodBNttZ, oodGHatZ, oodGloZ, oodGhiZ, oodAZ, oodTZ,
      oodMZ, oodMOrigZ, oodMSenderZ,
      oodDmZ, oodDsZ, oodPmZ, oodPsZ, oodPrZ, oodQcolZ, oodMuZ,
      oodZlupZ, oodZlupOmegaZ, oodRAurZ, oodRZ, oodQZ, oodQ1Z, oodCpChunkZ,
      oodHashStateZ, oodHashStateOmegaZ, oodHashSigmaZ, oodSourceShifts,
      friCaps, friLayerPositions, friLayerValues, friLayerSalts, friLayerProofs,
      friFinalPoly, grindingNonce, queryIndices,
    };
  }
}


// =============================================================================
// Test: prover runs up to commitment phase
// =============================================================================

function buildInputsRangeHash(
  d: number, M: number, K: number, sqrtQ: bigint,
  recipientSeed: number = LATTICE_DEFAULT_RECIPIENT,
): {
  aMat: bigint[][][]; bCoeffs: bigint[][]; mNtt: bigint[];
  mOrigNtt: bigint[]; mSenderNtt: bigint[]; cNtts: bigint[][];
  tokenM: bigint[]; tokenS: bigint[]; tokenO: bigint[];
} {
  if (M < 2) throw new Error("requires M >= 2");
  if (d < TABLE_SIZE) throw new Error(`d < ${TABLE_SIZE}`);
  if (d % HASH_RATE !== 0) throw new Error(`d not multiple of HASH_RATE`);
  const rndA = detRng(0xA1B2C3D4 ^ ((d * 31 + M) * 17 + K));
  const rndBRaw = detRng(0xCAFEBABE ^ ((d * 13 + M) * 7 + K));
  // r bounded-uniform in [−2^15, 2^15) for the STARK range check
  const rndB = (): bigint => mod((rndBRaw() % (1n << 16n)) - R_SHIFT);
  const rndM = detRng(0xBEEF1234 ^ ((d * 41 + M) * 11 + K));
  const rndOrig = detRng(0xDEAD5678 ^ ((d * 23 + M) * 5 + K));
  const psi = rootOfUnity(2n * BigInt(d));
  const sqrtQn = mod(sqrtQ);

  const aMat: bigint[][][] = [];
  if (M === LATTICE_KAPPA_SIS + 2) {
    // Per-recipient commitment matrix A_R = [A_sis ; B_R ; B'_R]: shared A_sis
    // (LATTICE_SIS_SEED) + the recipient's B rows (recipientSeed). Generated in
    // Rust so it matches the key regenerated for decryption.
    const flat: string[] = nativeProver.latticeKeygenRecipient(
      d, K, LATTICE_SIS_SEED, recipientSeed,
    );
    for (let m = 0; m < M; m++) {
      const row: bigint[][] = [];
      for (let k = 0; k < K; k++) {
        const base = (m * K + k) * d;
        row.push(flat.slice(base, base + d).map((s: string) => BigInt(s)));
      }
      aMat.push(row);
    }
  } else {
    for (let m = 0; m < M; m++) {
      const row: bigint[][] = [];
      for (let k = 0; k < K; k++) row.push(Array.from({ length: d }, () => rndA()));
      aMat.push(row);
    }
  }
  const bCoeffs: bigint[][] = [];
  for (let k = 0; k < K; k++) bCoeffs.push(Array.from({ length: d }, () => rndB()));

  // Generate m values that fit in 64 bits
  const mNtt: bigint[] = Array.from({ length: d }, () => mod(rndM() % (1n << 63n)));
  const mSenderNtt: bigint[] = Array.from({ length: d }, () => mod(rndOrig() % (1n << 63n)));
  const mOrigNtt: bigint[] = mNtt.map((mv, i) => fadd(mv, mSenderNtt[i]));

  // Verify all fit in 64 bits
  for (let i = 0; i < d; i++) {
    if (mNtt[i] >= (1n << 64n)) throw new Error(`mNtt[${i}] >= 2^64`);
    if (mSenderNtt[i] >= (1n << 64n)) throw new Error(`mSenderNtt[${i}] >= 2^64`);
    if (mOrigNtt[i] >= (1n << 64n)) throw new Error(`mOrigNtt[${i}] >= 2^64`);
  }

  // NTT view of b̃Ntt_k on ψH
  const bNtts: bigint[][] = bCoeffs.map((c) => negacyclicNTT(c, psi));

  const cNtts: bigint[][] = [];
  for (let m = 0; m < M; m++) {
    const cm = new Array<bigint>(d).fill(0n);
    for (let i = 0; i < d; i++) {
      let acc = 0n;
      for (let k = 0; k < K; k++) acc = fadd(acc, fmul(aMat[m][k][i], bNtts[k][i]));
      cm[i] = acc;
    }
    cNtts.push(cm);
  }
  // Embed message into last two rows
  for (let i = 0; i < d; i++) {
    cNtts[M - 2][i] = fadd(cNtts[M - 2][i], mNtt[i]);
    cNtts[M - 1][i] = fadd(cNtts[M - 1][i], fmul(sqrtQn, mNtt[i]));
  }

  // Compute hash tokens
  const tokenM = rescueSpongeHash(mNtt);
  const tokenS = rescueSpongeHash(mSenderNtt);
  const tokenO = rescueSpongeHash(mOrigNtt);

  return { aMat, bCoeffs, mNtt, mOrigNtt, mSenderNtt, cNtts, tokenM, tokenS, tokenO };
}


// =============================================================================
// Verifier (Main)
// =============================================================================

function zkVerifyUpdateRangeHash(
  proof: ZKStarkUpdateRangeHashProof,
  setup: AOracleSetupRangeHash,
  sqrtQ: bigint,
  cNtts: bigint[][],
): { ok: boolean; reason: string } {
  const { M, K, d, blowup, capHeight, aOracleHash, tPoly } = setup;
  const N = proof.traceLength;
  if (N !== d) return { ok: false, reason: `traceLength ${N} != d ${d}` };
  if (N < TABLE_SIZE) return { ok: false, reason: `N < ${TABLE_SIZE}` };
  if (N % HASH_RATE !== 0) return { ok: false, reason: `N % HASH_RATE != 0` };
  if (proof.numColumns !== K) return { ok: false, reason: `numColumns mismatch` };
  if (proof.blowup !== blowup) return { ok: false, reason: `blowup mismatch` };
  if (proof.capHeight !== capHeight) return { ok: false, reason: `capHeight mismatch` };
  if (proof.oodBNttZ.length !== K) return { ok: false, reason: `oodBNttZ != K` };
  if (proof.oodGHatZ.length !== K) return { ok: false, reason: `oodGHatZ != K` };
  if (proof.oodGloZ.length !== K) return { ok: false, reason: `oodGloZ != K` };
  if (proof.oodGhiZ.length !== K) return { ok: false, reason: `oodGhiZ != K` };
  if (proof.oodAZ.length !== M * K) return { ok: false, reason: `oodAZ != M*K` };
  if (proof.oodDmZ.length !== NUM_BYTES) return { ok: false, reason: `oodDmZ len` };
  if (proof.oodDsZ.length !== NUM_BYTES) return { ok: false, reason: `oodDsZ len` };
  if (proof.oodPmZ.length !== NUM_BYTES) return { ok: false, reason: `oodPmZ len` };
  if (proof.oodPsZ.length !== NUM_BYTES) return { ok: false, reason: `oodPsZ len` };
  if (proof.oodHashStateZ.length !== NUM_HASHES) return { ok: false, reason: `oodHashStateZ len` };
  if (proof.oodHashStateOmegaZ.length !== NUM_HASHES) return { ok: false, reason: `oodHashStateOmZ len` };
  if (proof.oodHashSigmaZ.length !== NUM_HASHES) return { ok: false, reason: `oodHashSigmaZ len` };
  if (proof.oodSourceShifts.length !== NUM_HASHES) return { ok: false, reason: `oodSourceShifts len` };
  for (let hi = 0; hi < NUM_HASHES; hi++) {
    if (proof.oodHashStateZ[hi].length !== HASH_STATE_WIDTH) return { ok: false, reason: `oodHashStateZ[${hi}] len` };
    if (proof.oodHashStateOmegaZ[hi].length !== HASH_STATE_WIDTH) return { ok: false, reason: `oodHashStateOmZ[${hi}] len` };
    if (proof.oodHashSigmaZ[hi].length !== HASH_RATE) return { ok: false, reason: `oodHashSigmaZ[${hi}] len` };
    if (proof.oodSourceShifts[hi].length !== 7) return { ok: false, reason: `oodSourceShifts[${hi}] len` };
  }
  if (cNtts.length !== M) return { ok: false, reason: `c_vec != M` };
  for (let m = 0; m < M; m++)
    if (cNtts[m].length !== d) return { ok: false, reason: `c_m length != d` };
  if (M < 2) return { ok: false, reason: `M < 2` };
  if (proof.tokenM.length !== HASH_OUTPUT_LANES) return { ok: false, reason: `tokenM len` };
  if (proof.tokenS.length !== HASH_OUTPUT_LANES) return { ok: false, reason: `tokenS len` };
  if (proof.tokenO.length !== HASH_OUTPUT_LANES) return { ok: false, reason: `tokenO len` };
  const sqrtQn = mod(sqrtQ);
  if (sqrtQn === 0n) return { ok: false, reason: `sqrtQ zero mod P` };

  const b = blindingBudget(N, proof.queryIndices.length);
  const bSource = blindingBudgetSource(proof.queryIndices.length);
  const bS = blindingBudgetState(proof.queryIndices.length);
  const bSigma = blindingBudgetSigma(proof.queryIndices.length);
  const bDeep = bSource; // max blinding budget
  const h = cpBlindBudget(proof.queryIndices.length);
  const w = cpChunkWidth(N);
  const dChunks = cpNumChunksHash(N, bS);
  if (proof.blindB !== b) return { ok: false, reason: `blindB mismatch` };
  if (proof.blindBSource !== bSource) return { ok: false, reason: `blindBSource mismatch` };
  if (proof.blindBState !== bS) return { ok: false, reason: `blindBState mismatch` };
  if (proof.blindBSigma !== bSigma) return { ok: false, reason: `blindBSigma mismatch` };
  if (proof.cpBlindH !== h) return { ok: false, reason: `cpBlindH mismatch` };
  if (proof.cpChunkWidth !== w) return { ok: false, reason: `cpChunkWidth mismatch` };
  if (proof.numChunks !== dChunks) return { ok: false, reason: `numChunks mismatch` };
  if (proof.oodCpChunkZ.length !== dChunks) return { ok: false, reason: `oodCpChunkZ len` };

  const Nbig = BigInt(N);
  const ldeSize = N * blowup;
  const numFriLayers = proof.friCaps.length;
  const omega = fpow(G_PRIM, (P - 1n) / Nbig);
  const psi = fpow(G_PRIM, (P - 1n) / (2n * Nbig));
  const ldeOmega = fpow(G_PRIM, (P - 1n) / BigInt(ldeSize));
  const cosetGen = fpow(G_PRIM, (P - 1n) / BigInt(2 * ldeSize));

  // Bind aCap to admin commitment
  {
    const got = ethers.keccak256(concatBytes(...proof.aCap));
    if (got.toLowerCase() !== aOracleHash.toLowerCase())
      return { ok: false, reason: `aOracleHash mismatch` };
  }

  // c_m polys
  const cPolys: bigint[][] = cNtts.map((cm) => intt(cm.map((v) => mod(v)), omega));

  // ── Rebuild transcript ─────────────────────────────────────────────
  const tr = new FiatShamirTranscript();
  tr.appendU64(M);
  tr.appendU64(N);
  tr.appendU64(K);
  tr.appendU64(blowup);
  tr.appendU64(capHeight);
  tr.appendU64(b);
  tr.appendU64(bSource);
  tr.appendU64(bS);
  tr.appendU64(bSigma);
  tr.appendU64(h);
  tr.appendU64(w);
  trAppendHex32(tr, aOracleHash);
  tr.appendField(sqrtQn);
  trAppendHex32(tr, cVecHash(cNtts));
  // Public hash tokens
  for (const t of proof.tokenM) tr.appendField(mod(t));
  for (const t of proof.tokenS) tr.appendField(mod(t));
  for (const t of proof.tokenO) tr.appendField(mod(t));
  for (const hc of proof.traceCap) tr.append(hc);

  const rho0 = tr.challenge(P);
  const rhos: bigint[] = new Array(M);
  { let acc = rho0; for (let m = 0; m < M; m++) { rhos[m] = acc; acc = fmul(acc, rho0); } }
  const rhoMsg = fadd(rhos[M - 2], fmul(rhos[M - 1], sqrtQn));

  const alpha = tr.challenge(P);
  const nQuotients = numAlphaSlots(K);
  const alphaPows: bigint[] = new Array(nQuotients);
  alphaPows[0] = alpha;
  for (let i = 1; i < nQuotients; i++) alphaPows[i] = fmul(alphaPows[i - 1], alpha);

  const lamK: bigint[] = new Array(K);
  for (let k = 0; k < K; k++) lamK[k] = tr.challenge(P);

  const betaLup = tr.challenge(P);

  // Absorb interaction cap
  for (const hc of proof.interCap) tr.append(hc);

  // Aurora blinding
  tr.appendField(mod(proof.betaAur));
  const rhoAurora = tr.challenge(P);

  const sigmaAlpha = sigmaAlphaCoeffs(alpha, N, omega);
  const alphaN = fpow(alpha, Nbig);
  const alphaNplus1 = fadd(alphaN, 1n);

  for (const hc of proof.auxCap) tr.append(hc);
  for (const hc of proof.cpChunkCap) tr.append(hc);

  const z = tr.challenge(P);
  const omegaZ = fmul(omega, z);
  const omegaNm1 = fpow(omega, Nbig - 1n);

  // Absorb OOD openings (must match prover order exactly)
  for (const v of proof.oodBNttZ) tr.appendField(v);
  for (const v of proof.oodGHatZ) tr.appendField(v);
  for (const v of proof.oodGloZ) tr.appendField(v);
  for (const v of proof.oodGhiZ) tr.appendField(v);
  for (const v of proof.oodAZ) tr.appendField(v);
  tr.appendField(proof.oodTZ);
  tr.appendField(proof.oodMZ);
  tr.appendField(proof.oodMOrigZ);
  tr.appendField(proof.oodMSenderZ);
  for (const v of proof.oodDmZ) tr.appendField(v);
  for (const v of proof.oodDsZ) tr.appendField(v);
  for (const v of proof.oodPmZ) tr.appendField(v);
  for (const v of proof.oodPsZ) tr.appendField(v);
  for (const v of proof.oodPrZ) tr.appendField(v);
  tr.appendField(proof.oodQcolZ);
  tr.appendField(proof.oodMuZ);
  tr.appendField(proof.oodZlupZ);
  tr.appendField(proof.oodZlupOmegaZ);
  tr.appendField(proof.oodRAurZ);
  tr.appendField(proof.oodRZ);
  tr.appendField(proof.oodQZ);
  tr.appendField(proof.oodQ1Z);
  for (const v of proof.oodCpChunkZ) tr.appendField(v);
  for (let hi = 0; hi < NUM_HASHES; hi++) for (const v of proof.oodHashStateZ[hi]) tr.appendField(v);
  for (let hi = 0; hi < NUM_HASHES; hi++) for (const v of proof.oodHashStateOmegaZ[hi]) tr.appendField(v);
  for (let hi = 0; hi < NUM_HASHES; hi++) for (const v of proof.oodHashSigmaZ[hi]) tr.appendField(v);
  for (let hi = 0; hi < NUM_HASHES; hi++) for (const v of proof.oodSourceShifts[hi]) tr.appendField(v);

  // ── OOD check (a): CP at z (all 2K+124 constraints) ───────────────
  const zN = fpow(z, Nbig);
  const zD = fsub(zN, 1n);
  if (zD === 0n) return { ok: false, reason: `z is N-th root of unity` };
  const zDInvZ = finv(zD);

  // Tokens lookup
  const tokens: bigint[][] = [proof.tokenM, proof.tokenS, proof.tokenO];
  // Source OOD at z: source[0]=m, source[1]=m_sender, source[2]=m_orig
  const sourceOodZ: bigint[] = [
    mod(proof.oodMZ), mod(proof.oodMSenderZ), mod(proof.oodMOrigZ),
  ];

  // Slot 0: matmul + msg
  let matmulZ = 0n;
  for (let m = 0; m < M; m++) {
    let inner = 0n;
    const base = m * K;
    for (let k = 0; k < K; k++) inner = fadd(inner, fmul(mod(proof.oodAZ[base + k]), mod(proof.oodBNttZ[k])));
    const cAtZ = polyEval(cPolys[m], z);
    matmulZ = fadd(matmulZ, fmul(rhos[m], fsub(inner, cAtZ)));
  }
  matmulZ = fadd(matmulZ, fmul(rhoMsg, mod(proof.oodMZ)));
  let cpExpected = fmul(alphaPows[0], fmul(matmulZ, zDInvZ));

  // Slots 1..K: range recompose (ĝ + 2^15) − (gLo + 256·gHi)
  for (let k = 0; k < K; k++) {
    const rc = fsub(fadd(mod(proof.oodGHatZ[k]), R_SHIFT), fadd(mod(proof.oodGloZ[k]), fmul(256n, mod(proof.oodGhiZ[k]))));
    cpExpected = fadd(cpExpected, fmul(alphaPows[1 + k], fmul(rc, zDInvZ)));
  }

  // Slot K+1: Balance
  const balZ = fsub(mod(proof.oodMOrigZ), fadd(mod(proof.oodMSenderZ), mod(proof.oodMZ)));
  cpExpected = fadd(cpExpected, fmul(alphaPows[K + 1], fmul(balZ, zDInvZ)));

  // Slot K+2: Recompose m
  let rmZ = mod(proof.oodMZ);
  for (let j = 0; j < NUM_BYTES; j++) rmZ = fsub(rmZ, fmul(POW256[j], mod(proof.oodDmZ[j])));
  cpExpected = fadd(cpExpected, fmul(alphaPows[K + 2], fmul(rmZ, zDInvZ)));

  // Slot K+3: Recompose m_sender
  let rsZ = mod(proof.oodMSenderZ);
  for (let j = 0; j < NUM_BYTES; j++) rsZ = fsub(rsZ, fmul(POW256[j], mod(proof.oodDsZ[j])));
  cpExpected = fadd(cpExpected, fmul(alphaPows[K + 3], fmul(rsZ, zDInvZ)));

  // Slot K+4: LogUp accumulator transition (includes Σpr)
  let accZ = fsub(mod(proof.oodZlupOmegaZ), mod(proof.oodZlupZ));
  for (let j = 0; j < NUM_BYTES; j++) { accZ = fsub(accZ, mod(proof.oodPmZ[j])); accZ = fsub(accZ, mod(proof.oodPsZ[j])); }
  for (let j = 0; j < 2 * K; j++) accZ = fsub(accZ, mod(proof.oodPrZ[j]));
  accZ = fadd(accZ, fmul(mod(proof.oodMuZ), mod(proof.oodQcolZ)));
  cpExpected = fadd(cpExpected, fmul(alphaPows[K + 4], fmul(accZ, zDInvZ)));

  // Slots K+5..K+12: Inverse correctness p^(m)
  for (let j = 0; j < NUM_BYTES; j++) {
    const ic = fsub(fmul(mod(proof.oodPmZ[j]), fsub(betaLup, mod(proof.oodDmZ[j]))), 1n);
    cpExpected = fadd(cpExpected, fmul(alphaPows[K + 5 + j], fmul(ic, zDInvZ)));
  }
  // Slots K+13..K+20: Inverse correctness p^(s)
  for (let j = 0; j < NUM_BYTES; j++) {
    const ic = fsub(fmul(mod(proof.oodPsZ[j]), fsub(betaLup, mod(proof.oodDsZ[j]))), 1n);
    cpExpected = fadd(cpExpected, fmul(alphaPows[K + 13 + j], fmul(ic, zDInvZ)));
  }
  // Slots K+21..K+20+2K: Inverse correctness p^(r) (r-byte lookups)
  for (let j = 0; j < 2 * K; j++) {
    const rbv = j < K ? mod(proof.oodGloZ[j]) : mod(proof.oodGhiZ[j - K]);
    const ic = fsub(fmul(mod(proof.oodPrZ[j]), fsub(betaLup, rbv)), 1n);
    cpExpected = fadd(cpExpected, fmul(alphaPows[K + 21 + j], fmul(ic, zDInvZ)));
  }
  // Slot K+21+2K: Inverse correctness q
  const icT = fsub(fmul(mod(proof.oodQcolZ), fsub(betaLup, mod(proof.oodTZ))), 1n);
  cpExpected = fadd(cpExpected, fmul(alphaPows[K + 21 + 2 * K], fmul(icT, zDInvZ)));

  // ── Hash constraints C1a, C1b, C2, C3 at z ────────────────────────
  const fAbsZ = evalAbsorbSelectorAtZ(z, N);
  const zMinusOmNm1 = fsub(z, omegaNm1);
  const invZminus1 = finv(fsub(z, 1n));
  const invZminusOmNm1 = finv(zMinusOmNm1);

  for (let hi = 0; hi < NUM_HASHES; hi++) {
    // C1a at z (8 per hash)
    for (let j = 0; j < HASH_RATE; j++) {
      // source(ω^j z): j=0 → source at z, j≥1 → oodSourceShifts[hi][j-1]
      const srcAtOmJz = (j === 0) ? sourceOodZ[hi] : mod(proof.oodSourceShifts[hi][j - 1]);
      const c1a = fsub(mod(proof.oodHashSigmaZ[hi][j]),
        fadd(mod(proof.oodHashStateZ[hi][j]), fmul(fAbsZ, srcAtOmJz)));
      cpExpected = fadd(cpExpected,
        fmul(alphaPows[alphaOffC1a(K) + hi * HASH_RATE + j], fmul(c1a, zDInvZ)));
    }

    // C1b at z (12 per hash): (M^{-1}(s(ωz)-arc2))^3 - (M·σ̂^3 + arc1)
    const sNextZ: bigint[] = proof.oodHashStateOmegaZ[hi];
    const arc2AtZ: bigint[] = new Array(HASH_STATE_WIDTH);
    const arc1AtZ: bigint[] = new Array(HASH_STATE_WIDTH);
    for (let ci = 0; ci < HASH_STATE_WIDTH; ci++) {
      arc2AtZ[ci] = evalPeriodicAtZ(RESCUE_ARC2.map((row) => row[ci]), z, N, omega);
      arc1AtZ[ci] = evalPeriodicAtZ(RESCUE_ARC1.map((row) => row[ci]), z, N, omega);
    }
    const smA2: bigint[] = sNextZ.map((v, ci) => fsub(mod(v), arc2AtZ[ci]));
    const mInvZ: bigint[] = new Array(HASH_STATE_WIDTH).fill(0n);
    for (let ci = 0; ci < HASH_STATE_WIDTH; ci++)
      for (let cj = 0; cj < HASH_STATE_WIDTH; cj++)
        mInvZ[ci] = fadd(mInvZ[ci], fmul(RESCUE_MINV[ci][cj], smA2[cj]));
    const lhsC: bigint[] = mInvZ.map((v) => fmul(fmul(v, v), v));

    const sigHatZ: bigint[] = new Array(HASH_STATE_WIDTH);
    for (let cj = 0; cj < HASH_RATE; cj++) sigHatZ[cj] = mod(proof.oodHashSigmaZ[hi][cj]);
    for (let cj = HASH_RATE; cj < HASH_STATE_WIDTH; cj++) sigHatZ[cj] = mod(proof.oodHashStateZ[hi][cj]);
    const scZ: bigint[] = sigHatZ.map((v) => fmul(fmul(v, v), v));
    const mAppZ: bigint[] = new Array(HASH_STATE_WIDTH).fill(0n);
    for (let ci = 0; ci < HASH_STATE_WIDTH; ci++)
      for (let cj = 0; cj < HASH_STATE_WIDTH; cj++)
        mAppZ[ci] = fadd(mAppZ[ci], fmul(RESCUE_M[ci][cj], scZ[cj]));
    const rhsC: bigint[] = mAppZ.map((v, ci) => fadd(v, arc1AtZ[ci]));

    for (let ci = 0; ci < HASH_STATE_WIDTH; ci++) {
      const c1bNum = fsub(lhsC[ci], rhsC[ci]);
      cpExpected = fadd(cpExpected, fmul(alphaPows[alphaOffC1b(K) + hi * HASH_STATE_WIDTH + ci],
        fmul(fmul(c1bNum, zMinusOmNm1), zDInvZ)));
    }

    // C2 at z (12 per hash): s(1) = IV = 0 → quotient by 1/(x-1)
    for (let ci = 0; ci < HASH_STATE_WIDTH; ci++) {
      cpExpected = fadd(cpExpected, fmul(alphaPows[alphaOffC2(K) + hi * HASH_STATE_WIDTH + ci],
        fmul(mod(proof.oodHashStateZ[hi][ci]), invZminus1)));
    }

    // C3 at z (τ=2 per hash): s(ω^{N-1}) = token → quotient by 1/(x-ω^{N-1})
    for (let lane = 0; lane < HASH_OUTPUT_LANES; lane++) {
      const c3n = fsub(mod(proof.oodHashStateZ[hi][lane]), mod(tokens[hi][lane]));
      cpExpected = fadd(cpExpected, fmul(alphaPows[alphaOffC3(K) + hi * HASH_OUTPUT_LANES + lane],
        fmul(c3n, invZminusOmNm1)));
    }
  }

  // CP reassembly from chunks
  let cpAtZ = 0n;
  {
    let zPow = 1n;
    const zW = fpow(z, BigInt(w));
    for (let j = 0; j < dChunks; j++) {
      cpAtZ = fadd(cpAtZ, fmul(zPow, mod(proof.oodCpChunkZ[j])));
      zPow = fmul(zPow, zW);
    }
  }
  if (cpAtZ !== cpExpected) {
    return { ok: false, reason: `OOD CP mismatch` };
  }

  // ── OOD check (b): Blinded Aurora zero-target at z ─────────────────
  {
    const sigmaAtZ = polyEval(sigmaAlpha, z);
    const lambdaAtZ = fmul(
      fsub(fmul(alpha, fsub(1n, zN)), fmul(fmul(psi, z), alphaNplus1)),
      finv(fmul(Nbig, fsub(alpha, fmul(psi, z)))),
    );
    let gBatchZ = 0n, fBatchZ = 0n;
    for (let k = 0; k < K; k++) {
      gBatchZ = fadd(gBatchZ, fmul(lamK[k], mod(proof.oodGHatZ[k])));
      fBatchZ = fadd(fBatchZ, fmul(lamK[k], mod(proof.oodBNttZ[k])));
    }
    const lhs = fadd(
      fmul(rhoAurora, fsub(fmul(gBatchZ, sigmaAtZ), fmul(fBatchZ, lambdaAtZ))),
      mod(proof.oodRAurZ),
    );
    const qAtZ = fadd(mod(proof.oodQZ), fmul(zN, mod(proof.oodQ1Z)));
    const rhs = fadd(mod(proof.betaAur), fadd(fmul(z, mod(proof.oodRZ)), fmul(qAtZ, zD)));
    if (lhs !== rhs)
      return { ok: false, reason: `Aurora OOD mismatch` };
  }

  // ── Absorb mask/split, squeeze γ and λ ─────────────────────────────
  for (const hc of proof.maskCap) tr.append(hc);

  const gam = (n: number): bigint[] => {
    const out: bigint[] = [];
    for (let i = 0; i < n; i++) out.push(tr.challenge(P));
    return out;
  };
  const gBNttZ = gam(K);
  const gGHatZ = gam(K);
  const gGloZ = gam(K);
  const gGhiZ = gam(K);
  const gAZ = gam(M * K);
  const gTZ = tr.challenge(P);
  const gM = tr.challenge(P);
  const gMOrig = tr.challenge(P);
  const gMSender = tr.challenge(P);
  const gDmZ = gam(NUM_BYTES);
  const gDsZ = gam(NUM_BYTES);
  const gPmZ = gam(NUM_BYTES);
  const gPsZ = gam(NUM_BYTES);
  const gPrZ = gam(2 * K);
  const gQcol = tr.challenge(P);
  const gMu = tr.challenge(P);
  const gZlup = tr.challenge(P);
  const gZlupOmega = tr.challenge(P);
  const gRAur = tr.challenge(P);
  const gR = tr.challenge(P);
  const gQ = tr.challenge(P);
  const gCpChunk = gam(dChunks);
  // Hash DEEP combiners
  const gHashStateZ: bigint[][] = [];
  const gHashStateOmegaZ: bigint[][] = [];
  const gHashSigmaZ: bigint[][] = [];
  for (let hi = 0; hi < NUM_HASHES; hi++) {
    gHashStateZ.push(gam(HASH_STATE_WIDTH));
    gHashStateOmegaZ.push(gam(HASH_STATE_WIDTH));
    gHashSigmaZ.push(gam(HASH_RATE));
  }
  const gSourceShifts: bigint[][] = [];
  for (let hi = 0; hi < NUM_HASHES; hi++) gSourceShifts.push(gam(7));

  for (const hc of proof.splitCap) tr.append(hc);
  const lambda = tr.challenge(P);

  // ── FRI transcript ─────────────────────────────────────────────────
  if (numFriLayers === 0) return { ok: false, reason: `no FRI layers` };
  const expectedFinalBound = N / 4 ** numFriLayers;
  if (!Number.isInteger(expectedFinalBound) || expectedFinalBound < 1)
    return { ok: false, reason: `bad FRI layer count` };
  if (proof.friFinalPoly.length !== expectedFinalBound)
    return { ok: false, reason: `friFinalPoly length mismatch` };
  if (expectedFinalBound > FINAL_POLY_BOUND)
    return { ok: false, reason: `final poly bound exceeded` };

  for (const hc of proof.friCaps[0]) tr.append(hc);
  const friBetas: bigint[] = [];
  for (let r = 0; r < numFriLayers; r++) {
    friBetas.push(tr.challenge(P));
    if (r + 1 < numFriLayers) for (const hc of proof.friCaps[r + 1]) tr.append(hc);
  }
  for (const c of proof.friFinalPoly) tr.appendField(c);

  // Grinding
  if (proof.grindingNonce < 0n || proof.grindingNonce > 0xffffffffffffffffn)
    return { ok: false, reason: `grindingNonce out of range` };
  {
    const cand = keccak(concatBytes(tr.state, u64BE(proof.grindingNonce)));
    if (leadingZeroBitsBytes(cand) < GRINDING_BITS)
      return { ok: false, reason: `grinding failed` };
    tr.state = cand;
  }

  // Query indices
  for (let i = 0; i < proof.queryIndices.length; i++) {
    const q = tr.challengeIndex(ldeSize / FRI_ARITY);
    if (q !== proof.queryIndices[i])
      return { ok: false, reason: `query index ${i} mismatch` };
  }

  // ── Merkle verifications ───────────────────────────────────────────
  const capH = layerCapHeight(capHeight, ldeSize);
  const traceCols = traceColCount(K);

  // Trace tree
  if (proof.traceCap.length !== 1 << capH) return { ok: false, reason: `trace cap size` };
  const traceLeaves = proof.traceColValues.map((cv, i) => {
    if (cv.length !== traceCols) throw new Error(`trace leaf len`);
    return leafHashFromValuesSalt(cv, proof.traceSalts[i]);
  });
  {
    const r = tsVerifyBatch(proof.traceCap, 1 << capH, ldeSize,
      proof.tracePositions, traceLeaves, proof.traceBatchProof);
    if (!r.ok) return { ok: false, reason: `trace merkle: ${r.reason}` };
  }

  // Interaction tree
  if (proof.interCap.length !== 1 << capH) return { ok: false, reason: `inter cap size` };
  const interLeaves = proof.interColValues.map((cv, i) => {
    if (cv.length !== interColCount(K)) throw new Error(`inter leaf len`);
    return leafHashFromValuesSalt(cv, proof.interSalts[i]);
  });
  {
    const r = tsVerifyBatch(proof.interCap, 1 << capH, ldeSize,
      proof.tracePositions, interLeaves, proof.interBatchProof);
    if (!r.ok) return { ok: false, reason: `inter merkle: ${r.reason}` };
  }

  // Aux tree (R, Q0, Q1)
  if (proof.auxCap.length !== 1 << capH) return { ok: false, reason: `aux cap size` };
  const auxLeaves = proof.auxColValues.map((cv, i) => {
    if (cv.length !== 3) throw new Error(`aux leaf len`);
    return leafHashFromValuesSalt(cv, proof.auxSalts[i]);
  });
  {
    const r = tsVerifyBatch(proof.auxCap, 1 << capH, ldeSize,
      proof.tracePositions, auxLeaves, proof.auxBatchProof);
    if (!r.ok) return { ok: false, reason: `aux merkle: ${r.reason}` };
  }

  // CP chunk tree
  if (proof.cpChunkCap.length !== 1 << capH) return { ok: false, reason: `cpChunk cap size` };
  const cpChunkLeaves = proof.cpChunkColValues.map((cv, i) => {
    if (cv.length !== dChunks) throw new Error(`cpChunk leaf len`);
    return leafHashFromValuesSalt(cv, proof.cpChunkSalts[i]);
  });
  {
    const r = tsVerifyBatch(proof.cpChunkCap, 1 << capH, ldeSize,
      proof.tracePositions, cpChunkLeaves, proof.cpChunkBatchProof);
    if (!r.ok) return { ok: false, reason: `cpChunk merkle: ${r.reason}` };
  }

  // Mask tree
  if (proof.maskCap.length !== 1 << capH) return { ok: false, reason: `mask cap size` };
  const maskLeaves = proof.maskValues.map((v, i) =>
    leafHashFromValuesSalt([v], proof.maskSalts[i]),
  );
  {
    const r = tsVerifyBatch(proof.maskCap, 1 << capH, ldeSize,
      proof.tracePositions, maskLeaves, proof.maskBatchProof);
    if (!r.ok) return { ok: false, reason: `mask merkle: ${r.reason}` };
  }

  // Split tree
  if (proof.splitCap.length !== 1 << capH) return { ok: false, reason: `split cap size` };
  const splitLeaves = proof.splitColValues.map((cv, i) => {
    if (cv.length !== 2) throw new Error(`split leaf len`);
    return leafHashFromValuesSalt(cv, proof.splitSalts[i]);
  });
  {
    const r = tsVerifyBatch(proof.splitCap, 1 << capH, ldeSize,
      proof.tracePositions, splitLeaves, proof.splitBatchProof);
    if (!r.ok) return { ok: false, reason: `split merkle: ${r.reason}` };
  }

  // A oracle tree (unsalted, M*K + 1 cols)
  if (proof.aCap.length !== 1 << capH) return { ok: false, reason: `a cap size` };
  const aLeaves = proof.aColValues.map((av) => {
    if (av.length !== M * K + 1) throw new Error(`a leaf len`);
    return leafHashFromValues(av);
  });
  {
    const r = tsVerifyBatch(proof.aCap, 1 << capH, ldeSize,
      proof.tracePositions, aLeaves, proof.aBatchProof);
    if (!r.ok) return { ok: false, reason: `a merkle: ${r.reason}` };
  }

  // FRI layer trees
  for (let r = 0; r < numFriLayers; r++) {
    const nR = ldeSize >> (2 * r);
    const capHR = layerCapHeight(capHeight, nR);
    if (proof.friCaps[r].length !== 1 << capHR)
      return { ok: false, reason: `fri cap[${r}] size` };
    const leaves = proof.friLayerValues[r].map((v, i) =>
      leafHashFromValuesSalt([v], proof.friLayerSalts[r][i]),
    );
    const res = tsVerifyBatch(proof.friCaps[r], 1 << capHR, nR,
      proof.friLayerPositions[r], leaves, proof.friLayerProofs[r]);
    if (!res.ok) return { ok: false, reason: `fri[${r}] merkle: ${res.reason}` };
  }

  // ── Per-query: reconstruct h, check split + batch, FRI fold ────────
  const traceMap = new Map<number, bigint[]>();
  proof.tracePositions.forEach((p, i) => traceMap.set(p, proof.traceColValues[i]));
  const interMap = new Map<number, bigint[]>();
  proof.tracePositions.forEach((p, i) => interMap.set(p, proof.interColValues[i]));
  const auxMap = new Map<number, bigint[]>();
  proof.tracePositions.forEach((p, i) => auxMap.set(p, proof.auxColValues[i]));
  const cpChunkMap = new Map<number, bigint[]>();
  proof.tracePositions.forEach((p, i) => cpChunkMap.set(p, proof.cpChunkColValues[i]));
  const maskMap = new Map<number, bigint>();
  proof.tracePositions.forEach((p, i) => maskMap.set(p, proof.maskValues[i]));
  const splitMap = new Map<number, bigint[]>();
  proof.tracePositions.forEach((p, i) => splitMap.set(p, proof.splitColValues[i]));
  const aMap = new Map<number, bigint[]>();
  proof.tracePositions.forEach((p, i) => aMap.set(p, proof.aColValues[i]));
  const friMaps: Map<number, bigint>[] = proof.friLayerPositions.map(
    (positions, r) => {
      const m = new Map<number, bigint>();
      positions.forEach((p, i) => m.set(p, proof.friLayerValues[r][i]));
      return m;
    },
  );

  // Source trace offset lookup: hi → trace column offset
  const sourceTraceOff: number[] = [
    traceOffM(K), traceOffMSender(K), traceOffMOrig(K),
  ];

  const quarter0 = ldeSize / FRI_ARITY;
  const mu4 = fpow(ldeOmega, BigInt(ldeSize / FRI_ARITY));

  for (const q of proof.queryIndices) {
    const i0 = q % quarter0;
    const tv = traceMap.get(i0);
    if (!tv) return { ok: false, reason: `missing trace[${i0}]` };
    const iv = interMap.get(i0);
    if (!iv) return { ok: false, reason: `missing inter[${i0}]` };
    const aux = auxMap.get(i0);
    if (!aux) return { ok: false, reason: `missing aux[${i0}]` };
    const cv = cpChunkMap.get(i0);
    if (!cv) return { ok: false, reason: `missing cpChunk[${i0}]` };
    const av = aMap.get(i0);
    if (!av) return { ok: false, reason: `missing a[${i0}]` };
    const maskV = maskMap.get(i0);
    if (maskV === undefined) return { ok: false, reason: `missing mask[${i0}]` };
    const splitV = splitMap.get(i0);
    if (!splitV) return { ok: false, reason: `missing split[${i0}]` };

    // (1) Reconstruct masked DEEP h(x)
    const x = fmul(cosetGen, fpow(ldeOmega, BigInt(i0)));
    const invXZ = finv(fsub(x, z));
    const invXOmegaZ = finv(fsub(x, omegaZ));

    let deep = 0n;
    // Standard trace columns @ z
    for (let k = 0; k < K; k++) deep = fadd(deep, fmul(gBNttZ[k], fmul(fsub(mod(tv[traceOffBNtt(K) + k]), mod(proof.oodBNttZ[k])), invXZ)));
    for (let k = 0; k < K; k++) deep = fadd(deep, fmul(gGHatZ[k], fmul(fsub(mod(tv[traceOffGHat(K) + k]), mod(proof.oodGHatZ[k])), invXZ)));
    for (let k = 0; k < K; k++) deep = fadd(deep, fmul(gGloZ[k], fmul(fsub(mod(tv[traceOffGlo(K) + k]), mod(proof.oodGloZ[k])), invXZ)));
    for (let k = 0; k < K; k++) deep = fadd(deep, fmul(gGhiZ[k], fmul(fsub(mod(tv[traceOffGhi(K) + k]), mod(proof.oodGhiZ[k])), invXZ)));
    // A oracle + table
    for (let m = 0; m < M; m++) {
      const base = m * K;
      for (let k = 0; k < K; k++) deep = fadd(deep, fmul(gAZ[base + k], fmul(fsub(mod(av[base + k]), mod(proof.oodAZ[base + k])), invXZ)));
    }
    deep = fadd(deep, fmul(gTZ, fmul(fsub(mod(av[M * K]), mod(proof.oodTZ)), invXZ)));
    // m, m_orig, m_sender
    deep = fadd(deep, fmul(gM, fmul(fsub(mod(tv[traceOffM(K)]), mod(proof.oodMZ)), invXZ)));
    deep = fadd(deep, fmul(gMOrig, fmul(fsub(mod(tv[traceOffMOrig(K)]), mod(proof.oodMOrigZ)), invXZ)));
    deep = fadd(deep, fmul(gMSender, fmul(fsub(mod(tv[traceOffMSender(K)]), mod(proof.oodMSenderZ)), invXZ)));
    // d^(m), d^(s)
    for (let j = 0; j < NUM_BYTES; j++) deep = fadd(deep, fmul(gDmZ[j], fmul(fsub(mod(tv[traceOffDm(K) + j]), mod(proof.oodDmZ[j])), invXZ)));
    for (let j = 0; j < NUM_BYTES; j++) deep = fadd(deep, fmul(gDsZ[j], fmul(fsub(mod(tv[traceOffDs(K) + j]), mod(proof.oodDsZ[j])), invXZ)));
    // Interaction: p^(m), p^(s), q, μ
    for (let j = 0; j < NUM_BYTES; j++) deep = fadd(deep, fmul(gPmZ[j], fmul(fsub(mod(iv[interOffPm() + j]), mod(proof.oodPmZ[j])), invXZ)));
    for (let j = 0; j < NUM_BYTES; j++) deep = fadd(deep, fmul(gPsZ[j], fmul(fsub(mod(iv[interOffPs() + j]), mod(proof.oodPsZ[j])), invXZ)));
    for (let j = 0; j < 2 * K; j++) deep = fadd(deep, fmul(gPrZ[j], fmul(fsub(mod(iv[interOffPr() + j]), mod(proof.oodPrZ[j])), invXZ)));
    deep = fadd(deep, fmul(gQcol, fmul(fsub(mod(iv[interOffQcol(K)]), mod(proof.oodQcolZ)), invXZ)));
    deep = fadd(deep, fmul(gMu, fmul(fsub(mod(tv[traceOffMu(K)]), mod(proof.oodMuZ)), invXZ)));
    // Z_lup: two quotients
    deep = fadd(deep, fmul(gZlup, fmul(fsub(mod(iv[interOffZlup(K)]), mod(proof.oodZlupZ)), invXZ)));
    deep = fadd(deep, fmul(gZlupOmega, fmul(fsub(mod(iv[interOffZlup(K)]), mod(proof.oodZlupOmegaZ)), invXOmegaZ)));
    // rAur
    deep = fadd(deep, fmul(gRAur, fmul(fsub(mod(tv[traceOffRAur(K)]), mod(proof.oodRAurZ)), invXZ)));
    // Aux R, Q0, Q1
    deep = fadd(deep, fmul(gR, fmul(fsub(mod(aux[0]), mod(proof.oodRZ)), invXZ)));
    deep = fadd(deep, fmul(gQ, fmul(fsub(mod(aux[1]), mod(proof.oodQZ)), invXZ)));
    deep = fadd(deep, fmul(fadd(gQ, 1n), fmul(fsub(mod(aux[2]), mod(proof.oodQ1Z)), invXZ)));
    // CP chunks
    for (let j = 0; j < dChunks; j++) deep = fadd(deep, fmul(gCpChunk[j], fmul(fsub(mod(cv[j]), mod(proof.oodCpChunkZ[j])), invXZ)));

    // Hash columns: state @ z, state @ ωz, sigma @ z
    for (let hi = 0; hi < NUM_HASHES; hi++) {
      for (let ci = 0; ci < HASH_STATE_WIDTH; ci++) {
        const sVal = mod(tv[traceOffHashState(K, hi) + ci]);
        deep = fadd(deep, fmul(gHashStateZ[hi][ci], fmul(fsub(sVal, mod(proof.oodHashStateZ[hi][ci])), invXZ)));
        deep = fadd(deep, fmul(gHashStateOmegaZ[hi][ci], fmul(fsub(sVal, mod(proof.oodHashStateOmegaZ[hi][ci])), invXOmegaZ)));
      }
      for (let cj = 0; cj < HASH_RATE; cj++)
        deep = fadd(deep, fmul(gHashSigmaZ[hi][cj], fmul(fsub(mod(tv[traceOffHashSigma(K, hi) + cj]), mod(proof.oodHashSigmaZ[hi][cj])), invXZ)));
    }

    // Source shifts: source(ω^j z), j=1..7
    for (let hi = 0; hi < NUM_HASHES; hi++) {
      const srcVal = mod(tv[sourceTraceOff[hi]]);
      for (let j = 1; j <= 7; j++) {
        const omJz = fmul(fpow(omega, BigInt(j)), z);
        const invXOmJz = finv(fsub(x, omJz));
        deep = fadd(deep, fmul(gSourceShifts[hi][j - 1], fmul(fsub(srcVal, mod(proof.oodSourceShifts[hi][j - 1])), invXOmJz)));
      }
    }

    // + mask
    const hVal = fadd(deep, mod(maskV));

    // (2) Split consistency: h(x) = g0(x) + x^N·g1(x)
    const g0v = splitV[0];
    const g1v = splitV[1];
    const xN = fpow(x, Nbig);
    const splitRhs = fadd(mod(g0v), fmul(xN, mod(g1v)));
    if (hVal !== splitRhs)
      return { ok: false, reason: `split mismatch q=${q}` };

    // (3) Batch all independently degree-bounded polynomials into FRI layer 0.
    let hBatch = fmul(fpow(x, BigInt(N - b + 1)), mod(aux[2]));
    hBatch = fadd(mod(aux[1]), fmul(lambda, hBatch));
    hBatch = fadd(fmul(x, mod(aux[0])), fmul(lambda, hBatch));
    hBatch = fadd(mod(g1v), fmul(lambda, hBatch));
    hBatch = fadd(mod(g0v), fmul(lambda, hBatch));
    const friL0 = friMaps[0].get(i0);
    if (friL0 === undefined) return { ok: false, reason: `missing fri[0][${i0}]` };
    if (hBatch !== friL0)
      return { ok: false, reason: `batch/FRI0 mismatch q=${q}` };

    // (4) Arity-4 FRI fold checks
    let quarterR = quarter0;
    for (let r = 0; r < numFriLayers; r++) {
      const iR = q % quarterR;
      const e0 = friMaps[r].get(iR);
      const e1 = friMaps[r].get(iR + quarterR);
      const e2 = friMaps[r].get(iR + 2 * quarterR);
      const e3 = friMaps[r].get(iR + 3 * quarterR);
      if (e0 === undefined || e1 === undefined || e2 === undefined || e3 === undefined)
        return { ok: false, reason: `missing fri[${r}] coset at ${iR}` };
      const baseX = fmul(cosetGen, fpow(ldeOmega, BigInt(iR)));
      const l = fpow(baseX, 4n ** BigInt(r));
      const folded = fold4Coset(e0, e1, e2, e3, l, friBetas[r], mu4);
      if (r + 1 < numFriLayers) {
        const nextVal = friMaps[r + 1].get(iR);
        if (nextVal === undefined)
          return { ok: false, reason: `missing fri[${r + 1}][${iR}]` };
        if (folded !== nextVal)
          return { ok: false, reason: `fri fold mismatch r=${r}` };
      } else {
        const y = fpow(l, 4n);
        if (folded !== polyEval(proof.friFinalPoly, y))
          return { ok: false, reason: `fri final-poly mismatch r=${r}` };
      }
      quarterR /= FRI_ARITY;
    }
  }

  return { ok: true, reason: "" };
}

// =============================================================================
// On-chain encoding helpers (Rescue modal B1/B2 + Solidity ZKProofRange struct)
// =============================================================================

const ZETA8 = 48587144059647998670309015740345128105n; // G^{(P-1)/8}
const INV8  = 297747071055821155530452781468974317569n; // 8^{-1} mod P

function computeModalB(arc: bigint[][]): bigint[][] {
  // B[lane][j] = Σ_r arc[r][lane] · ζ_8^{-r·j}  for lane=0..11, j=0..7
  const B: bigint[][] = [];
  for (let lane = 0; lane < 12; lane++) {
    const row: bigint[] = [];
    for (let j = 0; j < 8; j++) {
      let acc = 0n;
      for (let r = 0; r < 8; r++) {
        const exp = (((-r * j) % 8) + 8) % 8;
        acc = mod(acc + arc[r][lane] * fpow(ZETA8, BigInt(exp)));
      }
      row.push(mod(acc));
    }
    B.push(row);
  }
  return B;
}

/**
 * Build the 480-element Rescue parameter table:
 *   M[144] + MINV[144] + B1[96] + B2[96]
 * Row-major: M[i][j] at index i*12+j, B1[lane][j] at 288 + lane*8+j
 */
function buildRescueParams(): bigint[] {
  const B1 = computeModalB(RESCUE_ARC1);
  const B2 = computeModalB(RESCUE_ARC2);

  const params: bigint[] = [];
  // M: 12×12 row-major
  for (let i = 0; i < 12; i++)
    for (let j = 0; j < 12; j++)
      params.push(RESCUE_M[i][j]);
  // MINV: 12×12 row-major
  for (let i = 0; i < 12; i++)
    for (let j = 0; j < 12; j++)
      params.push(RESCUE_MINV[i][j]);
  // B1: 12×8 row-major
  for (let lane = 0; lane < 12; lane++)
    for (let j = 0; j < 8; j++)
      params.push(B1[lane][j]);
  // B2: 12×8 row-major
  for (let lane = 0; lane < 12; lane++)
    for (let j = 0; j < 8; j++)
      params.push(B2[lane][j]);

  if (params.length !== 480) throw new Error(`params length ${params.length} !== 480`);
  return params;
}

function packFieldArrayRangeHash(vals: bigint[]): string {
  const buf = new Uint8Array(vals.length * 16);
  for (let i = 0; i < vals.length; i++) buf.set(packField16(vals[i]), i * 16);
  return bytesToHex0x(buf);
}

function encodeZKProofRangeHash(proof: ZKStarkUpdateRangeHashProof): any {
  return {
    traceLength: proof.traceLength,
    numColumns: proof.numColumns,
    blowup: proof.blowup,
    capHeight: proof.capHeight,
    blindB: proof.blindB,
    blindBSource: proof.blindBSource,
    blindBState: proof.blindBState,
    blindBSigma: proof.blindBSigma,
    cpBlindH: proof.cpBlindH,
    numChunks: proof.numChunks,
    cpChunkWidth: proof.cpChunkWidth,
    betaAur: proof.betaAur,
    friFinalPoly: packFieldArrayRangeHash(proof.friFinalPoly),

    traceCap: proof.traceCap.map(bytesToHex),
    tracePositions: proof.tracePositions,
    traceColValues: proof.traceColValues.map(packFieldArrayRangeHash),
    traceSalts: proof.traceSalts.map(bytesToHex),
    traceBatchProof: proof.traceBatchProof.map(bytesToHex),

    interCap: proof.interCap.map(bytesToHex),
    interColValues: proof.interColValues.map(packFieldArrayRangeHash),
    interSalts: proof.interSalts.map(bytesToHex),
    interBatchProof: proof.interBatchProof.map(bytesToHex),

    auxCap: proof.auxCap.map(bytesToHex),
    auxColValues: proof.auxColValues.map(packFieldArrayRangeHash),
    auxSalts: proof.auxSalts.map(bytesToHex),
    auxBatchProof: proof.auxBatchProof.map(bytesToHex),

    cpChunkCap: proof.cpChunkCap.map(bytesToHex),
    cpChunkColValues: proof.cpChunkColValues.map(packFieldArrayRangeHash),
    cpChunkSalts: proof.cpChunkSalts.map(bytesToHex),
    cpChunkBatchProof: proof.cpChunkBatchProof.map(bytesToHex),

    maskCap: proof.maskCap.map(bytesToHex),
    maskValues: packFieldArrayRangeHash(proof.maskValues),
    maskSalts: proof.maskSalts.map(bytesToHex),
    maskBatchProof: proof.maskBatchProof.map(bytesToHex),

    splitCap: proof.splitCap.map(bytesToHex),
    splitColValues: proof.splitColValues.map(packFieldArrayRangeHash),
    splitSalts: proof.splitSalts.map(bytesToHex),
    splitBatchProof: proof.splitBatchProof.map(bytesToHex),

    aCap: proof.aCap.map(bytesToHex),
    aColValues: proof.aColValues.map(packFieldArrayRangeHash),
    aBatchProof: proof.aBatchProof.map(bytesToHex),

    // Standard OOD openings at z
    oodBNttZ: packFieldArrayRangeHash(proof.oodBNttZ),
    oodGHatZ: packFieldArrayRangeHash(proof.oodGHatZ),
    oodGloZ: packFieldArrayRangeHash(proof.oodGloZ),
    oodGhiZ: packFieldArrayRangeHash(proof.oodGhiZ),
    oodAZ: packFieldArrayRangeHash(proof.oodAZ),
    oodTZ: proof.oodTZ,
    oodMZ: proof.oodMZ,
    oodMOrigZ: proof.oodMOrigZ,
    oodMSenderZ: proof.oodMSenderZ,
    oodDmZ: packFieldArrayRangeHash(proof.oodDmZ),
    oodDsZ: packFieldArrayRangeHash(proof.oodDsZ),
    oodPmZ: packFieldArrayRangeHash(proof.oodPmZ),
    oodPsZ: packFieldArrayRangeHash(proof.oodPsZ),
    oodPrZ: packFieldArrayRangeHash(proof.oodPrZ),
    oodQcolZ: proof.oodQcolZ,
    oodMuZ: proof.oodMuZ,
    oodZlupZ: proof.oodZlupZ,
    oodZlupOmegaZ: proof.oodZlupOmegaZ,
    oodRAurZ: proof.oodRAurZ,
    oodRZ: proof.oodRZ,
    oodQZ: proof.oodQZ,
    oodQ1Z: proof.oodQ1Z,
    oodCpChunkZ: packFieldArrayRangeHash(proof.oodCpChunkZ),

    // Hash OOD openings — flatten [3][12] → [36], [3][8] → [24], [3][7] → [21]
    oodHashStateZ: packFieldArrayRangeHash(proof.oodHashStateZ.flat()),
    oodHashStateOmegaZ: packFieldArrayRangeHash(proof.oodHashStateOmegaZ.flat()),
    oodHashSigmaZ: packFieldArrayRangeHash(proof.oodHashSigmaZ.flat()),
    oodSourceShifts: packFieldArrayRangeHash(proof.oodSourceShifts.flat()),
    tokenM: proof.tokenM,
    tokenS: proof.tokenS,
    tokenO: proof.tokenO,

    // FRI
    friCaps: proof.friCaps.map((cap) => cap.map(bytesToHex)),
    friLayerPositions: proof.friLayerPositions,
    friLayerValues: proof.friLayerValues.map(packFieldArrayRangeHash),
    friLayerSalts: proof.friLayerSalts.map((s) => s.map(bytesToHex)),
    friLayerProofs: proof.friLayerProofs.map((p) => p.map(bytesToHex)),
    grindingNonce: proof.grindingNonce,
    queryIndices: proof.queryIndices,
  };
}

function encodeZKProofRangeHashBytes(
  proof: ZKStarkUpdateRangeHashProof,
  contractInterface: ethers.Interface,
): string {
  const schema = contractInterface.getEvent("ProofSchema")?.inputs[0];
  if (!schema) throw new Error("ProofSchema ABI entry not found");
  return ethers.AbiCoder.defaultAbiCoder().encode(
    [schema],
    [encodeZKProofRangeHash(proof)],
  );
}

function encodeCVecHexRangeHash(cNtts: bigint[][]): string {
  return bytesToHex0x(packCVec(cNtts));
}

// =============================================================================
// On-chain deploy & init helpers
// =============================================================================

async function deployRescueParamsData() {
  const params = buildRescueParams();
  const encodedParams = ethers.AbiCoder.defaultAbiCoder().encode(
    ["uint256[480]"],
    [params],
  );
  const Factory = await (hre as any).ethers.getContractFactory("RescueParamsData");
  const data = await Factory.deploy(encodedParams);
  await data.waitForDeployment();
  return data;
}

async function deployVerifierRangeHash(
  setup: AOracleSetupRangeHash,
  sqrtQ: bigint,
) {
  const rescueData = await deployRescueParamsData();
  const Factory = await (hre as any).ethers.getContractFactory(
    "contracts/ZKStark_update_rangehash.sol:ZKStarkUpdateRangeHashVerifier",
  );
  const c = await Factory.deploy(
    await rescueData.getAddress(), sqrtQ,
    setup.M, setup.K, setup.d, setup.blowup, setup.capHeight,
  );
  await c.waitForDeployment();
  return c;
}

async function deployAndInitRangeHash(
  setup: AOracleSetupRangeHash,
  sqrtQ: bigint,
): Promise<{ verifier: any }> {
  const verifier = await deployVerifierRangeHash(setup, sqrtQ);

  return { verifier };
}

// =============================================================================
// On-chain tests
// =============================================================================

// =============================================================================
// Exports
// =============================================================================

export {
  // Rescue helpers
  rescueSpongeHash,
  rescueRound,
  mdsMultiply,
  mdsInvMultiply,
  sboxForward,
  sboxInverse,
  buildHashTrace,
  buildAbsorbSelectorValues,
  buildPeriodicArcValues,
  evalPeriodicAtZ,
  evalAbsorbSelectorAtZ,
  evalC1bDivisorAtZ,
  // LogUp helpers
  decomposeBytes64,
  buildTableValues,
  computeMultiplicity,
  computeHelperInverse,
  computeZLup,
  POW256, NUM_BYTES, TABLE_SIZE,
  // Layout
  traceColCount,
  traceOffBNtt, traceOffGHat, traceOffGlo, traceOffGhi,
  traceOffM, traceOffMOrig, traceOffMSender,
  traceOffDm, traceOffDs, traceOffMu, traceOffRAur,
  traceOffHashState, traceOffHashSigma,
  interColCount,
  interOffPm, interOffPs, interOffPr, interOffQcol, interOffZlup,
  numAlphaSlots,
  alphaOffC1a, alphaOffC1b, alphaOffC2, alphaOffC3,
  blindingBudgetSource, blindingBudgetState, blindingBudgetSigma,
  dMax, cpNumChunksHash,
  // Prover
  ZKStarkUpdateProverRangeHash,
  // Verifier
  zkVerifyUpdateRangeHash,
  // Input builder
  buildInputsRangeHash,
  // Setup
  buildAOracleSetupRangeHash,
  // On-chain helpers
  encodeZKProofRangeHash,
  encodeZKProofRangeHashBytes,
  encodeCVecHexRangeHash,
  deployAndInitRangeHash,
  buildRescueParams,
  deployRescueParamsData,
  // Types
  type ZKStarkUpdateRangeHashProof,
  type RangeHashProveInputs,
  type AOracleSetupRangeHash,
  // Constants
  HASH_STATE_WIDTH, HASH_RATE, HASH_CAPACITY,
  HASH_ROUNDS, HASH_OUTPUT_LANES, NUM_HASHES,
  BLOWUP, NUM_QUERIES, CAP_HEIGHT,
};
