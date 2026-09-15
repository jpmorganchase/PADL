// ZKStark_update_rangehash_rust.ts — Rust prover + TS/on-chain verifier tests
//
// Uses the Rust NAPI prover for fast proof generation, then verifies with
// both the TS reference verifier and the on-chain Solidity verifier.

import { expect } from "chai";
import { P, fadd } from "./stark-utils";

import {
  zkVerifyUpdateRangeHash,
  buildAOracleSetupRangeHash,
  buildInputsRangeHash,
  encodeZKProofRangeHash,
  encodeZKProofRangeHashBytes,
  encodeCVecHexRangeHash,
  deployAndInitRangeHash,
  deployRescueParamsData,
  type ZKStarkUpdateRangeHashProof,
  BLOWUP, NUM_QUERIES, CAP_HEIGHT,
} from "./ZKStark_update_rangehash";

import hre from "hardhat";

const rust = require("../stark-prover-native");

// ─── Conversion helpers ──────────────────────────────────────────────────────

function hexToUint8Array(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  const buf = new Uint8Array(h.length / 2);
  for (let i = 0; i < buf.length; i++)
    buf[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return buf;
}

function convertRustProof(json: any): ZKStarkUpdateRangeHashProof {
  const bi = (s: string) => BigInt(s);
  const biA = (a: string[]) => a.map(bi);
  const biA2 = (a: string[][]) => a.map(biA);
  const by = (s: string) => hexToUint8Array(s);
  const byA = (a: string[]) => a.map(by);

  return {
    traceLength: json.trace_length,
    numColumns: json.num_columns,
    blowup: json.blowup,
    capHeight: json.cap_height,
    blindB: json.blind_b,
    blindBSource: json.blind_b_source,
    blindBState: json.blind_b_state,
    blindBSigma: json.blind_b_sigma,
    cpBlindH: json.cp_blind_h,
    numChunks: json.num_chunks,
    cpChunkWidth: json.cp_chunk_width,
    betaAur: bi(json.beta_aur),
    tokenM: biA(json.token_m),
    tokenS: biA(json.token_s),
    tokenO: biA(json.token_o),
    traceCap: byA(json.trace_cap),
    tracePositions: json.trace_positions,
    traceColValues: biA2(json.trace_col_values),
    traceSalts: byA(json.trace_salts),
    traceBatchProof: byA(json.trace_batch_proof),
    interCap: byA(json.inter_cap),
    interColValues: biA2(json.inter_col_values),
    interSalts: byA(json.inter_salts),
    interBatchProof: byA(json.inter_batch_proof),
    auxCap: byA(json.aux_cap),
    auxColValues: biA2(json.aux_col_values),
    auxSalts: byA(json.aux_salts),
    auxBatchProof: byA(json.aux_batch_proof),
    cpChunkCap: byA(json.cp_chunk_cap),
    cpChunkColValues: biA2(json.cp_chunk_col_values),
    cpChunkSalts: byA(json.cp_chunk_salts),
    cpChunkBatchProof: byA(json.cp_chunk_batch_proof),
    maskCap: byA(json.mask_cap),
    maskValues: biA(json.mask_values),
    maskSalts: byA(json.mask_salts),
    maskBatchProof: byA(json.mask_batch_proof),
    splitCap: byA(json.split_cap),
    splitColValues: biA2(json.split_col_values),
    splitSalts: byA(json.split_salts),
    splitBatchProof: byA(json.split_batch_proof),
    aCap: byA(json.a_cap),
    aColValues: biA2(json.a_col_values),
    aBatchProof: byA(json.a_batch_proof),
    oodBNttZ: biA(json.ood_bntt_z),
    oodGHatZ: biA(json.ood_ghat_z),
    oodGloZ: biA(json.ood_glo_z),
    oodGhiZ: biA(json.ood_ghi_z),
    oodAZ: biA(json.ood_a_z),
    oodTZ: bi(json.ood_t_z),
    oodMZ: bi(json.ood_m_z),
    oodMOrigZ: bi(json.ood_m_orig_z),
    oodMSenderZ: bi(json.ood_m_sender_z),
    oodDmZ: biA(json.ood_dm_z),
    oodDsZ: biA(json.ood_ds_z),
    oodPmZ: biA(json.ood_pm_z),
    oodPsZ: biA(json.ood_ps_z),
    oodPrZ: biA(json.ood_pr_z),
    oodQcolZ: bi(json.ood_qcol_z),
    oodMuZ: bi(json.ood_mu_z),
    oodZlupZ: bi(json.ood_zlup_z),
    oodZlupOmegaZ: bi(json.ood_zlup_omega_z),
    oodRAurZ: bi(json.ood_raur_z),
    oodRZ: bi(json.ood_r_z),
    oodQZ: bi(json.ood_q_z),
    oodQ1Z: bi(json.ood_q1_z),
    oodCpChunkZ: biA(json.ood_cp_chunk_z),
    oodHashStateZ: biA2(json.ood_hash_state_z),
    oodHashStateOmegaZ: biA2(json.ood_hash_state_omega_z),
    oodHashSigmaZ: biA2(json.ood_hash_sigma_z),
    oodSourceShifts: biA2(json.ood_source_shifts),
    friCaps: json.fri_caps.map((c: string[]) => byA(c)),
    friLayerPositions: json.fri_layer_positions,
    friLayerValues: json.fri_layer_values.map((r: string[]) => biA(r)),
    friLayerSalts: json.fri_layer_salts.map((r: string[]) => byA(r)),
    friLayerProofs: json.fri_layer_proofs.map((r: string[]) => byA(r)),
    friFinalPoly: biA(json.fri_final_poly),
    grindingNonce: bi(json.grinding_nonce),
    queryIndices: json.query_indices,
  };
}

// ─── Input flattening for Rust NAPI ──────────────────────────────────────────

function flattenAMat(aMat: bigint[][][]): string[] {
  const out: string[] = [];
  for (const row of aMat) for (const col of row) for (const v of col) out.push(v.toString());
  return out;
}
function flattenBCoeffs(bCoeffs: bigint[][]): string[] {
  const out: string[] = [];
  for (const col of bCoeffs) for (const v of col) out.push(v.toString());
  return out;
}
function flattenCNtts(cNtts: bigint[][]): string[] {
  const out: string[] = [];
  for (const cm of cNtts) for (const v of cm) out.push(v.toString());
  return out;
}
function toStrArr(arr: bigint[]): string[] { return arr.map((v) => v.toString()); }

function rustProveRaw(
  inputs: ReturnType<typeof buildInputsRangeHash>,
  d: number, M: number, K: number, sqrtQ: bigint,
): { proof: ZKStarkUpdateRangeHashProof; aOracleHash: string } {
  const jsonStr = rust.proveRangeHash(
    flattenAMat(inputs.aMat), M, K, d,
    flattenBCoeffs(inputs.bCoeffs),
    toStrArr(inputs.mNtt), toStrArr(inputs.mOrigNtt), toStrArr(inputs.mSenderNtt),
    sqrtQ.toString(), flattenCNtts(inputs.cNtts),
    toStrArr(inputs.tokenM), toStrArr(inputs.tokenS), toStrArr(inputs.tokenO),
  );
  const raw = JSON.parse(jsonStr);
  return { proof: convertRustProof(raw), aOracleHash: raw.a_oracle_hash };
}

function rustProve(
  inputs: ReturnType<typeof buildInputsRangeHash>,
  d: number, M: number, K: number, sqrtQ: bigint,
): ZKStarkUpdateRangeHashProof {
  return rustProveRaw(inputs, d, M, K, sqrtQ).proof;
}

// Deploy on-chain verifier without TS A-oracle setup
async function deployAndInitDirect(
  aOracleHash: string, sqrtQ: bigint,
  M: number, K: number, d: number,
): Promise<{ verifier: any }> {
  const rescueData = await deployRescueParamsData();
  const Factory = await (hre as any).ethers.getContractFactory(
    "ZKStarkUpdateRangeHashVerifier",
  );
  const verifier = await Factory.deploy(
    await rescueData.getAddress(), sqrtQ, M, K, d, BLOWUP, CAP_HEIGHT,
  );
  await verifier.waitForDeployment();
  return { verifier };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("ZK-STARK Rust prover", function () {
  const SQRT_Q = 18446744073709551615n % P;
  const d = 256, M = 2, K = 2;

  let inputs: ReturnType<typeof buildInputsRangeHash>;
  let proof: ZKStarkUpdateRangeHashProof;
  let setup: ReturnType<typeof buildAOracleSetupRangeHash>;

  before(function () {
    this.timeout(600_000);
    inputs = buildInputsRangeHash(d, M, K, SQRT_Q);
    const t0 = Date.now();
    proof = rustProve(inputs, d, M, K, SQRT_Q);
    console.log(`        Rust prove: ${Date.now() - t0} ms`);
    setup = buildAOracleSetupRangeHash(inputs.aMat, BLOWUP, CAP_HEIGHT);
  });

  it("TS verifier accepts Rust proof", function () {
    const r = zkVerifyUpdateRangeHash(proof, setup, SQRT_Q, inputs.cNtts);
    expect(r.ok).to.equal(true, r.reason);
  });

  it("rejects tampered oodMZ", function () {
    const bad = { ...proof, oodMZ: fadd(proof.oodMZ, 1n) };
    const r = zkVerifyUpdateRangeHash(bad, setup, SQRT_Q, inputs.cNtts);
    expect(r.ok).to.equal(false);
  });

  it("rejects tampered token", function () {
    const bad = { ...proof, tokenM: [fadd(proof.tokenM[0], 1n), proof.tokenM[1]] };
    const r = zkVerifyUpdateRangeHash(bad, setup, SQRT_Q, inputs.cNtts);
    expect(r.ok).to.equal(false);
  });

  it("rejects wrong cNtts", function () {
    const cBad = inputs.cNtts.map((r) => r.slice());
    cBad[0][0] = fadd(cBad[0][0], 1n);
    const r = zkVerifyUpdateRangeHash(proof, setup, SQRT_Q, cBad);
    expect(r.ok).to.equal(false);
  });
});

// ─── On-chain verifier with Rust prover ──────────────────────────────────────

describe("ZK-STARK Rust prover — on-chain verifier", function () {
  const SQRT_Q = 18446744073709551615n % P;
  const d = 256, M = 2, K = 2;

  // Shared across all on-chain tests — computed once
  let inputs: ReturnType<typeof buildInputsRangeHash>;
  let proof: ZKStarkUpdateRangeHashProof;
  let setup: ReturnType<typeof buildAOracleSetupRangeHash>;
  let verifier: any;

  before(async function () {
    this.timeout(600_000);
    inputs = buildInputsRangeHash(d, M, K, SQRT_Q);
    proof = rustProve(inputs, d, M, K, SQRT_Q);
    setup = buildAOracleSetupRangeHash(inputs.aMat, BLOWUP, CAP_HEIGHT);
    const tsRes = zkVerifyUpdateRangeHash(proof, setup, SQRT_Q, inputs.cNtts);
    if (!tsRes.ok) throw new Error(`TS verify failed: ${tsRes.reason}`);
    ({ verifier } = await deployAndInitRangeHash(setup, SQRT_Q));
  });

  it("on-chain: accepts Rust proof", async function () {
    this.timeout(60_000);
    const ok = await (verifier as any).verifyZKNttMatVecRangeHashMsg.staticCall(
      encodeZKProofRangeHashBytes(proof, verifier.interface),
      encodeCVecHexRangeHash(inputs.cNtts),
      setup.aOracleHash,
    );
    expect(ok).to.equal(true);
  });

  it("on-chain: rejects tampered token", async function () {
    this.timeout(60_000);
    const bad = { ...proof, tokenM: [fadd(proof.tokenM[0], 1n), proof.tokenM[1]] };
    const ok = await (verifier as any).verifyZKNttMatVecRangeHashMsg.staticCall(
      encodeZKProofRangeHashBytes(bad, verifier.interface),
      encodeCVecHexRangeHash(inputs.cNtts),
      setup.aOracleHash,
    );
    expect(ok).to.equal(false);
  });

  it("on-chain: rejects truncated packed OOD vectors", async function () {
    this.timeout(60_000);
    const truncateLastRow = (rows: bigint[][]): bigint[][] =>
      rows.map((row, index) => index + 1 === rows.length ? row.slice(0, -1) : row);
    const malformed = [
      { ...proof, oodDmZ: proof.oodDmZ.slice(0, -1) },
      { ...proof, oodPmZ: proof.oodPmZ.slice(0, -1) },
      { ...proof, oodHashStateZ: truncateLastRow(proof.oodHashStateZ) },
      { ...proof, oodHashStateOmegaZ: truncateLastRow(proof.oodHashStateOmegaZ) },
      { ...proof, oodHashSigmaZ: truncateLastRow(proof.oodHashSigmaZ) },
      { ...proof, oodSourceShifts: truncateLastRow(proof.oodSourceShifts) },
    ];
    const encodedCVec = encodeCVecHexRangeHash(inputs.cNtts);
    for (const bad of malformed) {
      const ok = await (verifier as any).verifyZKNttMatVecRangeHashMsg.staticCall(
        encodeZKProofRangeHashBytes(bad, verifier.interface),
        encodedCVec,
        setup.aOracleHash,
      );
      expect(ok).to.equal(false);
    }
  });

  it("on-chain: rejects fewer than 23 queries", async function () {
    const bad = { ...proof, queryIndices: proof.queryIndices.slice(0, -1) };
    const ok = await (verifier as any).verifyZKNttMatVecRangeHashMsg.staticCall(
      encodeZKProofRangeHashBytes(bad, verifier.interface),
      encodeCVecHexRangeHash(inputs.cNtts),
      setup.aOracleHash,
    );
    expect(ok).to.equal(false);
  });

  // ─── Gas benchmark ─────────────────────────────────────────────────────────
  const BENCH_CASES: Array<[number, number, number]> = [
    [256, 2, 2],
    [1024, 6, 10],
  ];

  it("on-chain gas benchmark (Rust prover)", async function () {
    this.timeout(3_600_000);
    console.log(
      `        ZK update+range+hash STARK on-chain gas (blowup=${BLOWUP}, queries=${NUM_QUERIES}, capH=${CAP_HEIGHT})`,
    );
    console.log(
      `        ` +
        `   d    M    K    b  ` +
        `${"total gas".padStart(14)}  ` +
        `${"calldata".padStart(11)}  ` +
        `${"exec".padStart(11)}  ` +
        `${"cd bytes".padStart(9)}  ` +
        `${"input ms".padStart(10)}  ` +
        `${"prove ms".padStart(10)}  ` +
        `${"flat ms".padStart(9)}`,
    );
    for (const [bd, bM, bK] of BENCH_CASES) {
      const tInput0 = Date.now();
      const bInputs = buildInputsRangeHash(bd, bM, bK, SQRT_Q);
      const tInput = Date.now() - tInput0;

      const tFlat0 = Date.now();
      const flatA = flattenAMat(bInputs.aMat);
      const flatB = flattenBCoeffs(bInputs.bCoeffs);
      const flatC = flattenCNtts(bInputs.cNtts);
      const tFlat = Date.now() - tFlat0;

      const t0 = Date.now();
      const bRaw = rustProveRaw(bInputs, bd, bM, bK, SQRT_Q);
      const bProof = bRaw.proof;
      const tProve = Date.now() - t0;

      let gasStr = "—", cdGasStr = "—", execGasStr = "—", cdSizeStr = "—";
      try {
        const { verifier: bVerifier } = await deployAndInitDirect(
          bRaw.aOracleHash, SQRT_Q, bM, bK, bd,
        );
        const encodedProof = encodeZKProofRangeHashBytes(bProof, bVerifier.interface);
        const encodedCVec = encodeCVecHexRangeHash(bInputs.cNtts);

        const gas = await bVerifier.verifyZKNttMatVecRangeHashMsg.estimateGas(
          encodedProof, encodedCVec, bRaw.aOracleHash,
        );

        const iface = bVerifier.interface;
        const calldata: string = iface.encodeFunctionData(
          "verifyZKNttMatVecRangeHashMsg", [encodedProof, encodedCVec, bRaw.aOracleHash],
        );
        const cdBytes = Buffer.from(calldata.slice(2), "hex");
        const cdSize = cdBytes.length;
        let cdGas = 0;
        for (let i = 0; i < cdSize; i++) cdGas += cdBytes[i] === 0 ? 4 : 16;
        const totalGas = Number(gas);
        const execGas = totalGas - 21000 - cdGas;

        gasStr = totalGas.toLocaleString();
        cdGasStr = cdGas.toLocaleString();
        execGasStr = execGas.toLocaleString();
        cdSizeStr = cdSize.toLocaleString();
      } catch (e: any) {
        gasStr = `ERR(${(e?.shortMessage || e?.message || "").slice(0, 60)})`;
      }

      console.log(
        `        ${String(bd).padStart(4)}  ${String(bM).padStart(3)}  ${String(bK).padStart(3)}  ${String(bProof.blindB).padStart(3)}  ` +
          `${gasStr.padStart(14)}  ${cdGasStr.padStart(11)}  ${execGasStr.padStart(11)}  ${cdSizeStr.padStart(9)}  ` +
          `${String(tInput).padStart(10)}  ${String(tProve).padStart(10)}  ${String(tFlat).padStart(9)}`,
      );
    }
  });
});
