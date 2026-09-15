// stark-utils.ts — Shared utilities for STARK prover/verifier test files.

import { ethers } from "ethers";

// =============================================================================
// Finite-field arithmetic over F_p
// =============================================================================

export const P: bigint = 340282366920938463463374607393113505793n;
export const G_PRIM: bigint = 3n;

export function mod(a: bigint, m: bigint = P): bigint {
  const r = a % m;
  return r < 0n ? r + m : r;
}
export const fadd = (a: bigint, b: bigint) => mod(a + b);
export const fsub = (a: bigint, b: bigint) => mod(a - b);
export const fmul = (a: bigint, b: bigint) => mod(a * b);

export function fpow(a: bigint, e: bigint, m: bigint = P): bigint {
  let base = mod(a, m);
  let exp = e;
  let result = 1n;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % m;
    base = (base * base) % m;
    exp >>= 1n;
  }
  return result;
}

export const finv = (a: bigint) => fpow(a, P - 2n);

export function rootOfUnity(n: bigint): bigint {
  if ((P - 1n) % n !== 0n) throw new Error(`n=${n} does not divide p-1`);
  return fpow(G_PRIM, (P - 1n) / n);
}

// =============================================================================
// NTT / INTT and coset variants
// =============================================================================

export function ntt(coeffs: bigint[], omega: bigint): bigint[] {
  const n = coeffs.length;
  if (n === 1) return [coeffs[0]];
  if ((n & (n - 1)) !== 0) throw new Error("n must be power of 2");
  const half = n >> 1;
  const even = new Array<bigint>(half);
  const odd = new Array<bigint>(half);
  for (let i = 0; i < half; i++) {
    even[i] = coeffs[2 * i];
    odd[i] = coeffs[2 * i + 1];
  }
  const omega2 = fmul(omega, omega);
  const evalE = ntt(even, omega2);
  const evalO = ntt(odd, omega2);
  const out = new Array<bigint>(n);
  let w = 1n;
  for (let i = 0; i < half; i++) {
    const t = fmul(w, evalO[i]);
    out[i] = fadd(evalE[i], t);
    out[i + half] = fsub(evalE[i], t);
    w = fmul(w, omega);
  }
  return out;
}

export function intt(values: bigint[], omega: bigint): bigint[] {
  const n = BigInt(values.length);
  const omegaInv = finv(omega);
  const coeffs = ntt(values, omegaInv);
  const nInv = finv(n);
  return coeffs.map((c) => fmul(c, nInv));
}

export function nttCoset(coeffs: bigint[], omega: bigint, g: bigint): bigint[] {
  const shifted = coeffs.slice();
  let gp = 1n;
  for (let i = 0; i < shifted.length; i++) {
    shifted[i] = fmul(shifted[i], gp);
    gp = fmul(gp, g);
  }
  return ntt(shifted, omega);
}

export function polyEval(coeffs: bigint[], x: bigint): bigint {
  let result = 0n;
  for (let i = coeffs.length - 1; i >= 0; i--) {
    result = fadd(fmul(result, x), coeffs[i]);
  }
  return result;
}

// =============================================================================
// LDE on a coset
// =============================================================================

export interface LdeCoset {
  ldeOmega: bigint;
  cosetGen: bigint;
  ldeSize: number;
  domain: bigint[];
}

export function buildLdeDomain(N: number, blowup: number): LdeCoset {
  const ldeSize = blowup * N;
  const ldeOmega = rootOfUnity(BigInt(ldeSize));
  const cosetGen = fpow(G_PRIM, (P - 1n) / BigInt(2 * ldeSize));
  const domain = new Array<bigint>(ldeSize);
  for (let i = 0; i < ldeSize; i++) {
    domain[i] = fmul(cosetGen, fpow(ldeOmega, BigInt(i)));
  }
  return { ldeOmega, cosetGen, ldeSize, domain };
}

export function evalOnCoset(coeffs: bigint[], lde: LdeCoset): bigint[] {
  const padded = coeffs.slice();
  while (padded.length < lde.ldeSize) padded.push(0n);
  return nttCoset(padded, lde.ldeOmega, lde.cosetGen);
}

// Inverse coset NTT: given values V[i] = poly(g·ω^i) on the LDE coset,
// recover the unique polynomial coefficients of degree < ldeSize.
export function inttCoset(values: bigint[], lde: LdeCoset): bigint[] {
  const shifted = intt(values, lde.ldeOmega);
  const gInv = finv(lde.cosetGen);
  let gp = 1n;
  for (let j = 0; j < shifted.length; j++) {
    shifted[j] = fmul(shifted[j], gp);
    gp = fmul(gp, gInv);
  }
  return shifted;
}

// =============================================================================
// Hashing — keccak256 with simple framing
// =============================================================================

export function fieldToBytes32(v: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let x = mod(v);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

export function keccak(data: Uint8Array): Uint8Array {
  const hex = ethers.keccak256(data);
  const buf = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    buf[i] = parseInt(hex.slice(2 + 2 * i, 4 + 2 * i), 16);
  }
  return buf;
}

export const LEAF_TAG = new Uint8Array([0x00]);
export const NODE_TAG = new Uint8Array([0x01]);

// Per-leaf salt size for hiding Merkle commitments (§3.3 of zkstark_flow_detail_zk.md).
// Salt is appended at the end of the leaf preimage:
//   leaf = keccak( 0x00 || value_0 || ... || value_{n-1} || salt_16 )
export const SALT_BYTES = 16;

export function leafHashFromValues(values: bigint[]): Uint8Array {
  const payload = concatBytes(...values.map(fieldToBytes32));
  return keccak(concatBytes(LEAF_TAG, payload));
}

export function leafHashFromValuesSalt(values: bigint[], salt: Uint8Array): Uint8Array {
  if (salt.length !== SALT_BYTES)
    throw new Error(`leafHashFromValuesSalt: salt must be ${SALT_BYTES} bytes, got ${salt.length}`);
  const payload = concatBytes(...values.map(fieldToBytes32), salt);
  return keccak(concatBytes(LEAF_TAG, payload));
}

// Cryptographically random 16-byte salt. Uses Node's webcrypto where
// available, falling back to globalThis.crypto.getRandomValues. Test contexts
// always run under Node (Hardhat), so this is reliable.
export function randomSalt(): Uint8Array {
  const s = new Uint8Array(SALT_BYTES);
  const g: any = globalThis as any;
  if (g.crypto && typeof g.crypto.getRandomValues === "function") {
    g.crypto.getRandomValues(s);
    return s;
  }
  // Node fallback (require to avoid bundler issues).
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const nodeCrypto = require("crypto");
  const buf: Buffer = nodeCrypto.randomBytes(SALT_BYTES);
  for (let i = 0; i < SALT_BYTES; i++) s[i] = buf[i];
  return s;
}

export function randomSalts(n: number): Uint8Array[] {
  const out: Uint8Array[] = new Array(n);
  for (let i = 0; i < n; i++) out[i] = randomSalt();
  return out;
}

export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return keccak(concatBytes(NODE_TAG, left, right));
}

// =============================================================================
// BatchedMerkleTree
// =============================================================================

export class BatchedMerkleTree {
  readonly n: number;
  readonly depth: number;
  readonly capHeight: number;
  readonly levels: Uint8Array[][];

  constructor(leafHashes: Uint8Array[], capHeight: number) {
    const n = leafHashes.length;
    if (n <= 0 || (n & (n - 1)) !== 0)
      throw new Error("number of leaves must be power of 2");
    const depth = Math.log2(n) | 0;
    if (capHeight < 0 || capHeight > depth)
      throw new Error(`capHeight out of range [0,${depth}]`);
    this.n = n;
    this.depth = depth;
    this.capHeight = capHeight;
    this.levels = [leafHashes.slice()];
    for (let k = 0; k < depth - capHeight; k++) {
      const prev = this.levels[this.levels.length - 1];
      const cur: Uint8Array[] = [];
      for (let i = 0; i < prev.length; i += 2) {
        cur.push(nodeHash(prev[i], prev[i + 1]));
      }
      this.levels.push(cur);
    }
  }

  cap(): Uint8Array[] {
    return this.levels[this.levels.length - 1].slice();
  }

  openBatch(indices: number[]): Uint8Array[] {
    const proof: Uint8Array[] = [];
    let cur = Array.from(new Set(indices)).sort((a, b) => a - b);
    for (let k = 0; k < this.depth - this.capHeight; k++) {
      const level = this.levels[k];
      const curSet = new Set(cur);
      const nextIndices: number[] = [];
      const seen = new Set<number>();
      for (const idx of cur) {
        if (seen.has(idx)) continue;
        const sib = idx ^ 1;
        seen.add(idx);
        seen.add(sib);
        if (!curSet.has(sib)) {
          proof.push(level[sib]);
        }
        nextIndices.push(idx >> 1);
      }
      cur = Array.from(new Set(nextIndices)).sort((a, b) => a - b);
    }
    return proof;
  }
}

// =============================================================================
// Fiat–Shamir transcript
// =============================================================================

export class FiatShamirTranscript {
  state: Uint8Array;
  constructor() {
    this.state = keccak(new TextEncoder().encode("stark-fs-keccak-v1"));
  }
  append(data: Uint8Array) {
    this.state = keccak(concatBytes(this.state, data));
  }
  appendU64(v: bigint | number) {
    const x = BigInt(v);
    const buf = new Uint8Array(8);
    let xx = x;
    for (let i = 7; i >= 0; i--) {
      buf[i] = Number(xx & 0xffn);
      xx >>= 8n;
    }
    this.append(buf);
  }
  appendField(v: bigint) {
    this.append(fieldToBytes32(v));
  }
  challenge(modulus: bigint): bigint {
    this.state = keccak(concatBytes(this.state, new TextEncoder().encode("challenge")));
    let acc = 0n;
    for (const b of this.state) acc = (acc << 8n) | BigInt(b);
    return mod(acc, modulus);
  }
  challengeIndex(maxVal: number): number {
    this.state = keccak(concatBytes(this.state, new TextEncoder().encode("index")));
    let acc = 0n;
    for (const b of this.state) acc = (acc << 8n) | BigInt(b);
    return Number(acc % BigInt(maxVal));
  }
}

export function trAppendHex32(tr: FiatShamirTranscript, hex: string): void {
  if (!hex.startsWith("0x") || hex.length !== 66)
    throw new Error(`expected 0x-prefixed 32-byte hex, got ${hex}`);
  const buf = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    buf[i] = parseInt(hex.slice(2 + 2 * i, 4 + 2 * i), 16);
  }
  tr.append(buf);
}

// =============================================================================
// FRI fold + helpers
// =============================================================================

export function friFold(
  evals: bigint[],
  domain: bigint[],
  alpha: bigint,
): { newEvals: bigint[]; newDomain: bigint[] } {
  const n = domain.length;
  const half = n >> 1;
  const inv2 = finv(2n);
  const newEvals: bigint[] = [];
  const newDomain: bigint[] = [];
  for (let i = 0; i < half; i++) {
    const x = domain[i];
    const fx = evals[i];
    const fnx = evals[i + half];
    const fEven = fmul(fadd(fx, fnx), inv2);
    const inv2x = finv(fmul(2n, x));
    const fOdd = fmul(fsub(fx, fnx), inv2x);
    const folded = fadd(fEven, fmul(alpha, fOdd));
    newEvals.push(folded);
    newDomain.push(fmul(x, x));
  }
  return { newEvals, newDomain };
}

export function layerCapHeight(cfgCap: number, layerSize: number): number {
  const depth = Math.log2(layerSize) | 0;
  return Math.min(cfgCap, depth);
}

// =============================================================================
// Generic batched Merkle verifier (TS reference)
// =============================================================================

export function tsVerifyBatch(
  cap: Uint8Array[],
  capSize: number,
  n: number,
  positions: number[],
  leafHashes: Uint8Array[],
  proofPath: Uint8Array[],
): { ok: boolean; reason: string } {
  const m = positions.length;
  if (m === 0) return { ok: false, reason: "no positions" };
  if (m !== leafHashes.length) return { ok: false, reason: "leaves/positions mismatch" };
  const depth = Math.log2(n) | 0;
  const capHeightHere = Math.log2(capSize) | 0;
  if (capHeightHere > depth) return { ok: false, reason: "cap height > depth" };

  const keys = positions.slice();
  let hashes = leafHashes.slice();
  for (let i = 0; i < m; i++) {
    if (keys[i] >= n) return { ok: false, reason: `position ${keys[i]} >= n=${n}` };
    if (i > 0 && keys[i] <= keys[i - 1])
      return { ok: false, reason: "positions not strictly sorted" };
  }

  let proofIdx = 0;
  let curLen = m;
  const levels = depth - capHeightHere;
  for (let level = 0; level < levels; level++) {
    let outLen = 0;
    let idx = 0;
    while (idx < curLen) {
      const ki = keys[idx];
      const hi = hashes[idx];
      let hSib: Uint8Array;
      const sibInKeys =
        (ki & 1) === 0 && idx + 1 < curLen && keys[idx + 1] === ki + 1;
      if (sibInKeys) {
        hSib = hashes[idx + 1];
        idx += 2;
      } else {
        if (proofIdx >= proofPath.length)
          return { ok: false, reason: "proof path exhausted" };
        hSib = proofPath[proofIdx];
        proofIdx += 1;
        idx += 1;
      }
      let parent: Uint8Array;
      if ((ki & 1) === 0) parent = nodeHash(hi, hSib);
      else parent = nodeHash(hSib, hi);
      keys[outLen] = ki >> 1;
      hashes[outLen] = parent;
      outLen += 1;
    }
    curLen = outLen;
  }

  if (proofIdx !== proofPath.length)
    return { ok: false, reason: "proof path not fully consumed" };
  for (let i = 0; i < curLen; i++) {
    if (keys[i] >= capSize)
      return { ok: false, reason: `cap key ${keys[i]} >= capSize=${capSize}` };
    let eq = true;
    for (let b = 0; b < 32; b++) if (cap[keys[i]][b] !== hashes[i][b]) { eq = false; break; }
    if (!eq) return { ok: false, reason: `cap mismatch at key ${keys[i]}` };
  }
  return { ok: true, reason: "" };
}

// =============================================================================
// Public-input packing helpers
// =============================================================================

export function packField16(v: bigint): Uint8Array {
  const out = new Uint8Array(16);
  let x = mod(v);
  for (let i = 15; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

export function packCVec(cNtts: bigint[][]): Uint8Array {
  const M = cNtts.length;
  if (M === 0) throw new Error("packCVec: empty c_vec");
  const d = cNtts[0].length;
  const buf = new Uint8Array(M * d * 16);
  let off = 0;
  for (let m = 0; m < M; m++) {
    for (let i = 0; i < d; i++) {
      buf.set(packField16(cNtts[m][i]), off);
      off += 16;
    }
  }
  return buf;
}

export function cVecHash(cNtts: bigint[][]): string {
  return ethers.keccak256(packCVec(cNtts));
}

export function bytesToHex0x(b: Uint8Array): string {
  let s = "0x";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

export function bytesToHex(b: Uint8Array): string {
  return "0x" + Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

// =============================================================================
// Polynomial arithmetic helpers
// =============================================================================

export function polyMul(a: bigint[], b: bigint[]): bigint[] {
  if (a.length === 0 || b.length === 0) return [];
  const out = new Array<bigint>(a.length + b.length - 1).fill(0n);
  for (let i = 0; i < a.length; i++) {
    const ai = a[i];
    if (ai === 0n) continue;
    for (let j = 0; j < b.length; j++) {
      out[i + j] = fadd(out[i + j], fmul(ai, b[j]));
    }
  }
  return out;
}

export function polySub(a: bigint[], b: bigint[]): bigint[] {
  const n = Math.max(a.length, b.length);
  const out = new Array<bigint>(n).fill(0n);
  for (let j = 0; j < a.length; j++) out[j] = fadd(out[j], a[j]);
  for (let j = 0; j < b.length; j++) out[j] = fsub(out[j], b[j]);
  return out;
}

export function polyAddInto(out: bigint[], a: bigint[]): bigint[] {
  if (a.length > out.length) {
    const grown = out.slice();
    while (grown.length < a.length) grown.push(0n);
    out = grown;
  }
  for (let j = 0; j < a.length; j++) out[j] = fadd(out[j], a[j]);
  return out;
}

export function polyAddScaled(a: bigint[], b: bigint[], s: bigint): bigint[] {
  const n = Math.max(a.length, b.length);
  const out = new Array<bigint>(n).fill(0n);
  for (let j = 0; j < a.length; j++) out[j] = fadd(out[j], a[j]);
  for (let j = 0; j < b.length; j++) out[j] = fadd(out[j], fmul(s, b[j]));
  return out;
}

export function blindWithNminus1(poly: bigint[], blind: bigint[], N: number): bigint[] {
  const b = blind.length;
  const out = new Array<bigint>(N + b).fill(0n);
  for (let j = 0; j < poly.length; j++) out[j] = mod(poly[j]);
  for (let j = 0; j < b; j++) {
    out[j] = fsub(out[j], blind[j]);
    out[N + j] = fadd(out[N + j], blind[j]);
  }
  return out;
}

export function shiftUp(poly: bigint[], s: number): bigint[] {
  const out = new Array<bigint>(poly.length + s).fill(0n);
  for (let j = 0; j < poly.length; j++) out[j + s] = mod(poly[j]);
  return out;
}

export function divByXNminus1(poly: bigint[], N: number): { quot: bigint[]; rem: bigint[] } {
  const cur = poly.map((v) => mod(v));
  const quotLen = Math.max(0, cur.length - N);
  const quot = new Array<bigint>(quotLen).fill(0n);
  for (let j = cur.length - 1; j >= N; j--) {
    const q = cur[j];
    quot[j - N] = q;
    cur[j] = 0n;
    cur[j - N] = fadd(cur[j - N], q);
  }
  const rem = cur.slice(0, Math.min(N, cur.length));
  return { quot, rem };
}

// =============================================================================
// Negacyclic NTT and twisted coset helpers
// =============================================================================

export function negacyclicNTT(coeffs: bigint[], psi: bigint): bigint[] {
  const n = coeffs.length;
  const twisted = new Array<bigint>(n);
  let p = 1n;
  for (let j = 0; j < n; j++) {
    twisted[j] = fmul(mod(coeffs[j]), p);
    p = fmul(p, psi);
  }
  const omega = fmul(psi, psi);
  return ntt(twisted, omega);
}

export function inttTwisted(vals: bigint[], omega: bigint, psi: bigint): bigint[] {
  const coeffs = intt(vals, omega);
  const psiInv = finv(psi);
  let p = 1n;
  for (let j = 0; j < coeffs.length; j++) {
    coeffs[j] = fmul(coeffs[j], p);
    p = fmul(p, psiInv);
  }
  return coeffs;
}

// =============================================================================
// Aurora helpers (σ_α and Λ'_α)
// =============================================================================

export function sigmaAlphaCoeffs(alpha: bigint, N: number, omega: bigint): bigint[] {
  const vals = new Array<bigint>(N);
  let a = 1n;
  for (let i = 0; i < N; i++) {
    vals[i] = a;
    a = fmul(a, alpha);
  }
  return intt(vals, omega);
}

export function lambdaAlphaCoeffs(alpha: bigint, N: number, omega: bigint, psi: bigint): bigint[] {
  const Nbig = BigInt(N);
  const alphaN = fpow(alpha, Nbig);
  const alphaNplus1 = fadd(alphaN, 1n);
  const Ninv = finv(Nbig);
  const vals = new Array<bigint>(N);
  let hi = psi;
  for (let i = 0; i < N; i++) {
    const num = fmul(fsub(0n, hi), alphaNplus1);
    const den = fmul(Nbig, fsub(alpha, hi));
    vals[i] = fmul(num, finv(den));
    hi = fmul(hi, omega);
  }
  return intt(vals, omega);
}

// =============================================================================
// Arity-4 FRI fold helpers
// =============================================================================

export const INV4 = finv(4n);

export function fold4Coset(
  e0: bigint, e1: bigint, e2: bigint, e3: bigint,
  l: bigint, beta: bigint, mu: bigint,
): bigint {
  const A = fadd(e0, e2);
  const B = fadd(e1, e3);
  const C = fsub(e0, e2);
  const D = fmul(mu, fsub(e1, e3));
  const g0 = fmul(fadd(A, B), INV4);
  const g2 = fmul(fsub(A, B), INV4);
  const g1 = fmul(fsub(C, D), INV4);
  const g3 = fmul(fadd(C, D), INV4);
  const invL = finv(l);
  const t1 = fmul(beta, invL);
  const t2 = fmul(t1, t1);
  const t3 = fmul(t2, t1);
  return fadd(
    fadd(g0, fmul(t1, g1)),
    fadd(fmul(t2, g2), fmul(t3, g3)),
  );
}

export function friFoldArity4(
  evals: bigint[],
  domain: bigint[],
  beta: bigint,
  mu: bigint,
): { newEvals: bigint[]; newDomain: bigint[] } {
  const n = domain.length;
  const q = n / 4;
  const newEvals: bigint[] = new Array(q);
  const newDomain: bigint[] = new Array(q);
  for (let i = 0; i < q; i++) {
    const l = domain[i];
    newEvals[i] = fold4Coset(
      evals[i], evals[i + q], evals[i + 2 * q], evals[i + 3 * q],
      l, beta, mu,
    );
    newDomain[i] = fpow(l, 4n);
  }
  return { newEvals, newDomain };
}

// =============================================================================
// ZK blinding budget helpers (standard-domain)
// =============================================================================

export function blindingBudget(N: number, numQueries: number): number {
  const b = numQueries + 1;
  if (b < 1) throw new Error(`blindingBudget: N=${N} too small for blinding`);
  if (2 * b >= N) throw new Error(`blindingBudget: need 2b < N (b=${b}, N=${N})`);
  return b;
}

export function cpBlindBudget(numQueries: number): number {
  return numQueries + 1;
}

export function cpChunkWidth(N: number): number {
  return N;
}

export function cpNumChunks(N: number, b: number, w: number): number {
  return Math.ceil((N + 2 * b + 1) / w);
}

// =============================================================================
// Grinding helpers
// =============================================================================

export function u64BE(v: bigint | number): Uint8Array {
  let x = BigInt(v);
  if (x < 0n || x > 0xffffffffffffffffn) throw new Error("u64BE: out of range");
  const out = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

export function leadingZeroBitsBytes(b: Uint8Array): number {
  let n = 0;
  for (const byte of b) {
    if (byte === 0) { n += 8; continue; }
    for (let i = 7; i >= 0; i--) {
      if ((byte >> i) & 1) return n;
      n++;
    }
    return n;
  }
  return n;
}

// =============================================================================
// A-oracle setup (public preprocessing)
// =============================================================================

export interface AOracleSetup {
  M: number;
  K: number;
  d: number;
  blowup: number;
  capHeight: number;
  aPolys: bigint[][][];
  aLde: bigint[][][];
  aTree: BatchedMerkleTree;
  aCap: Uint8Array[];
  aOracleHash: string;
  lde: LdeCoset;
}

export function buildAOracleSetup(
  aMat: bigint[][][],
  blowup: number,
  capHeight: number,
): AOracleSetup {
  const M = aMat.length;
  if (M === 0) throw new Error("buildAOracleSetup: empty M");
  const K = aMat[0].length;
  if (K === 0) throw new Error("buildAOracleSetup: empty K");
  const d = aMat[0][0].length;
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
  const leaves: Uint8Array[] = [];
  for (let i = 0; i < lde.ldeSize; i++) {
    const vals: bigint[] = new Array(M * K);
    for (let m = 0; m < M; m++)
      for (let k = 0; k < K; k++) vals[m * K + k] = aLde[m][k][i];
    leaves.push(leafHashFromValues(vals));
  }
  const cap = layerCapHeight(capHeight, lde.ldeSize);
  const aTree = new BatchedMerkleTree(leaves, cap);
  const aCap = aTree.cap();
  const aOracleHash = ethers.keccak256(concatBytes(...aCap));
  return { M, K, d, blowup, capHeight, aPolys, aLde, aTree, aCap, aOracleHash, lde };
}

// =============================================================================
// Deterministic test RNGs
// =============================================================================

export function detRng(seed: number): () => bigint {
  let s = (seed | 0) || 1;
  return () => {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    return mod(BigInt(s) * 0x9e3779b97f4a7c15n);
  };
}

export function ternaryRng(seed: number): () => bigint {
  const r = detRng(seed);
  return () => {
    const v = r() % 3n;
    return v === 0n ? 0n : v === 1n ? 1n : mod(-1n);
  };
}
