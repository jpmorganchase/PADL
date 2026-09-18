

import { expect } from "chai";
import { P, fadd, mod } from "./stark-utils";

import {
  buildInputsRangeHash,
  encodeZKProofRangeHash,
  encodeZKProofRangeHashBytes,
  encodeCVecHexRangeHash,
  deployRescueParamsData,
  rescueSpongeHash,
  LATTICE_SIS_SEED,
  LATTICE_DEFAULT_RECIPIENT,
  type ZKStarkUpdateRangeHashProof,
  BLOWUP, NUM_QUERIES, CAP_HEIGHT,
} from "./ZKStark_update_rangehash";

import hre from "hardhat";

const rust = require("../stark-prover-native/stark-prover-native.node");
const MAX_SPLIT_CALLDATA_BYTES = 128 * 1024;
const MAX_SPLIT_GAS = 16_000_000;

// ─── Conversion helpers (from rust test) ─────────────────────────────────────

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
    traceLength: json.trace_length, numColumns: json.num_columns,
    blowup: json.blowup, capHeight: json.cap_height,
    blindB: json.blind_b, blindBSource: json.blind_b_source,
    blindBState: json.blind_b_state, blindBSigma: json.blind_b_sigma,
    cpBlindH: json.cp_blind_h, numChunks: json.num_chunks, cpChunkWidth: json.cp_chunk_width,
    betaAur: bi(json.beta_aur),
    tokenM: biA(json.token_m), tokenS: biA(json.token_s), tokenO: biA(json.token_o),
    traceCap: byA(json.trace_cap), tracePositions: json.trace_positions,
    traceColValues: biA2(json.trace_col_values), traceSalts: byA(json.trace_salts),
    traceBatchProof: byA(json.trace_batch_proof),
    interCap: byA(json.inter_cap), interColValues: biA2(json.inter_col_values),
    interSalts: byA(json.inter_salts), interBatchProof: byA(json.inter_batch_proof),
    auxCap: byA(json.aux_cap), auxColValues: biA2(json.aux_col_values),
    auxSalts: byA(json.aux_salts), auxBatchProof: byA(json.aux_batch_proof),
    cpChunkCap: byA(json.cp_chunk_cap), cpChunkColValues: biA2(json.cp_chunk_col_values),
    cpChunkSalts: byA(json.cp_chunk_salts), cpChunkBatchProof: byA(json.cp_chunk_batch_proof),
    maskCap: byA(json.mask_cap), maskValues: biA(json.mask_values),
    maskSalts: byA(json.mask_salts), maskBatchProof: byA(json.mask_batch_proof),
    splitCap: byA(json.split_cap), splitColValues: biA2(json.split_col_values),
    splitSalts: byA(json.split_salts), splitBatchProof: byA(json.split_batch_proof),
    aCap: byA(json.a_cap), aColValues: biA2(json.a_col_values), aBatchProof: byA(json.a_batch_proof),
    oodBNttZ: biA(json.ood_bntt_z), oodGHatZ: biA(json.ood_ghat_z),
    oodGloZ: biA(json.ood_glo_z), oodGhiZ: biA(json.ood_ghi_z),
    oodAZ: biA(json.ood_a_z), oodTZ: bi(json.ood_t_z),
    oodMZ: bi(json.ood_m_z), oodMOrigZ: bi(json.ood_m_orig_z), oodMSenderZ: bi(json.ood_m_sender_z),
    oodDmZ: biA(json.ood_dm_z), oodDsZ: biA(json.ood_ds_z),
    oodPmZ: biA(json.ood_pm_z), oodPsZ: biA(json.ood_ps_z), oodPrZ: biA(json.ood_pr_z),
    oodQcolZ: bi(json.ood_qcol_z), oodMuZ: bi(json.ood_mu_z),
    oodZlupZ: bi(json.ood_zlup_z), oodZlupOmegaZ: bi(json.ood_zlup_omega_z),
    oodRAurZ: bi(json.ood_raur_z), oodRZ: bi(json.ood_r_z), oodQZ: bi(json.ood_q_z),
    oodQ1Z: bi(json.ood_q1_z),
    oodCpChunkZ: biA(json.ood_cp_chunk_z),
    oodHashStateZ: biA2(json.ood_hash_state_z), oodHashStateOmegaZ: biA2(json.ood_hash_state_omega_z),
    oodHashSigmaZ: biA2(json.ood_hash_sigma_z), oodSourceShifts: biA2(json.ood_source_shifts),
    friCaps: json.fri_caps.map((c: string[]) => byA(c)),
    friLayerPositions: json.fri_layer_positions,
    friLayerValues: json.fri_layer_values.map((r: string[]) => biA(r)),
    friLayerSalts: json.fri_layer_salts.map((r: string[]) => byA(r)),
    friLayerProofs: json.fri_layer_proofs.map((r: string[]) => byA(r)),
    friFinalPoly: biA(json.fri_final_poly), grindingNonce: bi(json.grinding_nonce),
    queryIndices: json.query_indices,
  };
}

function flattenAMat(aMat: bigint[][][]): string[] {
  const out: string[] = [];
  for (const row of aMat) for (const col of row) for (const v of col) out.push(v.toString());
  return out;
}
function flattenBCoeffs(b: bigint[][]): string[] {
  const out: string[] = [];
  for (const col of b) for (const v of col) out.push(v.toString());
  return out;
}
function flattenCNtts(c: bigint[][]): string[] {
  const out: string[] = [];
  for (const cm of c) for (const v of cm) out.push(v.toString());
  return out;
}
function toStrArr(a: bigint[]): string[] { return a.map((v) => v.toString()); }

type SplitProofPart = "header" | "base" | "fri";

function partitionSplitProof(
  proof: ZKStarkUpdateRangeHashProof,
  part: SplitProofPart,
): ZKStarkUpdateRangeHashProof {
  const result = { ...proof };
  if (part !== "base") {
    Object.assign(result, {
      tracePositions: [],
      traceColValues: [], traceSalts: [], traceBatchProof: [],
      interColValues: [], interSalts: [], interBatchProof: [],
      auxColValues: [], auxSalts: [], auxBatchProof: [],
      cpChunkColValues: [], cpChunkSalts: [], cpChunkBatchProof: [],
      maskValues: [], maskSalts: [], maskBatchProof: [],
      splitColValues: [], splitSalts: [], splitBatchProof: [],
      aColValues: [], aBatchProof: [],
    });
  }
  if (part !== "fri") {
    Object.assign(result, {
      friLayerPositions: [], friLayerValues: [],
      friLayerSalts: [], friLayerProofs: [],
    });
  }
  if (part === "base") {
    Object.assign(result, {
      traceLength: 0, numColumns: 0, blowup: 0,
      blindB: 0, blindBSource: 0, blindBState: 0, blindBSigma: 0,
      cpBlindH: 0, numChunks: 0, cpChunkWidth: 0, betaAur: 0n,
      maskValues: [], maskSalts: [], maskBatchProof: [],
      maskCap: [], aCap: [], aColValues: [], aBatchProof: [],
      friCaps: [], friFinalPoly: [], grindingNonce: 0n,
    });
  } else if (part === "fri") {
    Object.assign(result, {
      traceLength: 0, numColumns: 0, blowup: 0,
      blindB: 0, blindBSource: 0, blindBState: 0, blindBSigma: 0,
      cpBlindH: 0, numChunks: 0, cpChunkWidth: 0, betaAur: 0n,
      tracePositions: proof.tracePositions,
      traceCap: [], interCap: [], auxCap: [], cpChunkCap: [], splitCap: [],
      maskValues: proof.maskValues,
      maskSalts: proof.maskSalts,
      maskBatchProof: proof.maskBatchProof,
      aColValues: proof.aColValues,
      aBatchProof: proof.aBatchProof,
      oodBNttZ: [], oodGHatZ: [], oodGloZ: [], oodGhiZ: [],
      oodMZ: 0n, oodMOrigZ: 0n, oodMSenderZ: 0n,
      oodDmZ: [], oodDsZ: [], oodPmZ: [], oodPsZ: [], oodPrZ: [],
      oodQcolZ: 0n, oodMuZ: 0n, oodZlupZ: 0n, oodZlupOmegaZ: 0n,
      oodRAurZ: 0n, oodRZ: 0n, oodQZ: 0n, oodQ1Z: 0n,
      oodCpChunkZ: [], oodHashStateZ: [], oodHashStateOmegaZ: [],
      oodHashSigmaZ: [], oodSourceShifts: [],
    });
  }
  return result;
}

function calldataBytes(data: string): number {
  return (data.length - 2) / 2;
}

function parsedEvents(receipt: any, contract: any, eventName: string): any[] {
  const events: any[] = [];
  for (const log of receipt.logs) {
    try {
      const parsed = contract.interface.parseLog(log);
      if (parsed?.name === eventName) events.push(parsed.args);
    } catch {
      // Ignore events from the other contract in the staged call.
    }
  }
  return events;
}

function rustProveRaw(
  inputs: ReturnType<typeof buildInputsRangeHash>,
  d: number, M: number, K: number, sqrtQ: bigint,
  grindingBits?: number,
): { proof: ZKStarkUpdateRangeHashProof; aOracleHash: string } {
  const jsonStr = rust.proveRangeHash(
    flattenAMat(inputs.aMat), M, K, d, flattenBCoeffs(inputs.bCoeffs),
    toStrArr(inputs.mNtt), toStrArr(inputs.mOrigNtt), toStrArr(inputs.mSenderNtt),
    sqrtQ.toString(), flattenCNtts(inputs.cNtts),
    toStrArr(inputs.tokenM), toStrArr(inputs.tokenS), toStrArr(inputs.tokenO),
    grindingBits,
  );
  const raw = JSON.parse(jsonStr);
  return { proof: convertRustProof(raw), aOracleHash: raw.a_oracle_hash };
}

// ─── AES helpers ─────────────────────────────────────────────────────────────

const rSeedCounter = { v: 1 };

function latticeEncrypt(valsNtt: bigint[], d: number, K: number, sqrtQ: bigint, ownerSeed: number): Buffer {
  const flat: string[] = rust.latticeCommitNttR(
    d, K, sqrtQ.toString(), LATTICE_SIS_SEED, ownerSeed,
    valsNtt.map((v) => mod(v).toString()), rSeedCounter.v++,
  );
  const buf = Buffer.alloc(flat.length * 16);
  for (let i = 0; i < flat.length; i++) {
    const bytes = (BigInt(flat[i]) % P).toString(16).padStart(32, "0");
    buf.set(Buffer.from(bytes, "hex"), i * 16);
  }
  return buf;
}

function latticeDecrypt(blob: Buffer, d: number, K: number, sqrtQ: bigint, ownerSeed: number): bigint[] {
  const n = blob.length / 16;
  const flat: string[] = [];
  for (let i = 0; i < n; i++)
    flat.push(BigInt("0x" + blob.subarray(i * 16, (i + 1) * 16).toString("hex")).toString());
  return rust
    .latticeExtractNttR(d, K, sqrtQ.toString(), LATTICE_SIS_SEED, ownerSeed, flat)
    .map((s: string) => BigInt(s));
}

// First TokenEncData ciphertext emitted in a transaction receipt.
function encDataFromReceipt(receipt: any, contract: any): string {
  for (const log of receipt.logs) {
    try {
      const parsed = contract.interface.parseLog(log);
      if (parsed && parsed.name === "TokenEncData") return parsed.args.encData;
    } catch {
      /* not a contract log */
    }
  }
  throw new Error("TokenEncData event not found in receipt");
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("ZK-STARK state management (Rust prover)", function () {
  const SQRT_Q = 18446744073709551615n % P;
  const d = 1024, M = 6, K = 10;
  // const d = 1024, M = 6, K = 10;
  const OWNER_SEED = LATTICE_DEFAULT_RECIPIENT; // signer's per-recipient key

  let stateContract: any;
  let verifierContract: any;
  let signer: any;
  let inputs: ReturnType<typeof buildInputsRangeHash>;
  let proof: ZKStarkUpdateRangeHashProof;
  let aOracleHash: string;
  let tInput = 0, tProve = 0, tFlat = 0;

  before(async function () {
    this.timeout(600_000);
    const signers = await (hre as any).ethers.getSigners();
    signer = signers[0];

    // Generate inputs and proof
    const tInput0 = Date.now();
    inputs = buildInputsRangeHash(d, M, K, SQRT_Q);
    tInput = Date.now() - tInput0;

    const tFlat0 = Date.now();
    flattenAMat(inputs.aMat);
    flattenBCoeffs(inputs.bCoeffs);
    flattenCNtts(inputs.cNtts);
    tFlat = Date.now() - tFlat0;

    const t0 = Date.now();
    const raw = rustProveRaw(inputs, d, M, K, SQRT_Q);
    tProve = Date.now() - t0;
    proof = raw.proof;
    aOracleHash = raw.aOracleHash;
    console.log(`        Rust prove: ${tProve} ms`);

    // Deploy the verifier, then deploy the state wrapper.
    const VerifierFactory = await (hre as any).ethers.getContractFactory(
      "contracts/ZKStark_update_rangehash.sol:ZKStarkUpdateRangeHashVerifier",
    );
    const StateFactory = await (hre as any).ethers.getContractFactory(
      "ZKStarkRangeHashState",
    );
    const rescueData = await deployRescueParamsData();
    verifierContract = await VerifierFactory.deploy(
      await rescueData.getAddress(), SQRT_Q, M, K, d, BLOWUP, CAP_HEIGHT,
    );
    await verifierContract.waitForDeployment();

    stateContract = await StateFactory.deploy(await verifierContract.getAddress());
    await stateContract.waitForDeployment();
    // Register the signer's commitment key (recipient == sender in this test).
    await (await stateContract.registerPubKey(raw.aOracleHash, "0x")).wait();
  });

  it("pre-issue token and verify state", async function () {
    const tokenO = inputs.tokenO; // H(m_original)
    const encOrig = latticeEncrypt(inputs.mOrigNtt, d, K, SQRT_Q, OWNER_SEED);

    const receipt = await (await stateContract.preissue(
      signer.address, tokenO[0], tokenO[1], encOrig,
    )).wait();

    const count = await stateContract.tokenCount(signer.address);
    expect(count).to.equal(1n);

    const [h0, h1] = await stateContract.getToken(signer.address, 0);
    expect(h0).to.equal(tokenO[0]);
    expect(h1).to.equal(tokenO[1]);

    // Ciphertext is emitted (not stored) — recover from event, decrypt, hash.
    const encData = encDataFromReceipt(receipt, stateContract);
    const decrypted = latticeDecrypt(Buffer.from(encData.slice(2), "hex"), d, K, SQRT_Q, OWNER_SEED);
    const reHash = rescueSpongeHash(decrypted);
    expect(reHash[0]).to.equal(mod(tokenO[0]));
    expect(reHash[1]).to.equal(mod(tokenO[1]));
  });

  it("rejects transfer to an unregistered recipient", async function () {
    const signers = await (hre as any).ethers.getSigners();
    const stranger = signers[1].address; // never called registerPubKey
    let reverted = false;
    try {
      await stateContract.processTransfer.staticCall(
        encodeZKProofRangeHashBytes(proof, verifierContract.interface),
        encodeCVecHexRangeHash(inputs.cNtts),
        stranger,
      );
    } catch (e: any) {
      reverted = e.message.includes("RecipientNotRegistered");
    }
    expect(reverted, "should revert RecipientNotRegistered").to.be.true;
  });

  it("processTransfer: removes token_o, adds token_s + token_m", async function () {
    this.timeout(120_000);

    const encodedProof = encodeZKProofRangeHashBytes(proof, verifierContract.interface);
    const encodedCVec = encodeCVecHexRangeHash(inputs.cNtts);
    const transferArgs = [
      encodedProof,
      encodedCVec,
      signer.address, // recipient = sender for this test
    ];

    const tx = await stateContract.processTransfer(...transferArgs);
    const receipt = await tx.wait();

    // ─── Gas breakdown ────────────────────────────────────────────────────────
    const calldata: string = stateContract.interface.encodeFunctionData(
      "processTransfer", transferArgs,
    );
    const cdBytes = Buffer.from(calldata.slice(2), "hex");
    const cdSize = cdBytes.length;
    let cdGas = 0;
    for (let i = 0; i < cdSize; i++) cdGas += cdBytes[i] === 0 ? 4 : 16;
    const totalGas = Number(receipt.gasUsed);
    const execGas = totalGas - 21000 - cdGas;

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
    console.log(
      `        ${String(d).padStart(4)}  ${String(M).padStart(3)}  ${String(K).padStart(3)}  ${String(proof.blindB).padStart(3)}  ` +
        `${totalGas.toLocaleString().padStart(14)}  ${cdGas.toLocaleString().padStart(11)}  ${execGas.toLocaleString().padStart(11)}  ${cdSize.toLocaleString().padStart(9)}  ` +
        `${String(tInput).padStart(10)}  ${String(tProve).padStart(10)}  ${String(tFlat).padStart(9)}`,
    );

    // Should now have 2 tokens (token_o removed, token_s + token_m added)
    const count = await stateContract.tokenCount(signer.address);
    expect(count).to.equal(2n);

    // Collect tokens
    const stored: Array<{ h0: bigint; h1: bigint }> = [];
    for (let i = 0; i < Number(count); i++) {
      const [h0, h1] = await stateContract.getToken(signer.address, i);
      stored.push({ h0, h1 });
    }

    // Verify token_s is present
    const tokenS = inputs.tokenS;
    const hasTokenS = stored.some(
      (t) => t.h0 === mod(tokenS[0]) && t.h1 === mod(tokenS[1]),
    );
    expect(hasTokenS, "token_s not found in state").to.be.true;

    // Verify token_m is present
    const tokenM = inputs.tokenM;
    const hasTokenM = stored.some(
      (t) => t.h0 === mod(tokenM[0]) && t.h1 === mod(tokenM[1]),
    );
    expect(hasTokenM, "token_m not found in state").to.be.true;

    // Verify token_o is NOT present
    const tokenO = inputs.tokenO;
    const hasTokenO = stored.some(
      (t) => t.h0 === mod(tokenO[0]) && t.h1 === mod(tokenO[1]),
    );
    expect(hasTokenO, "token_o should have been removed").to.be.false;
  });

  it("attachSenderEncData: emits sender ciphertext after a verified transfer", async function () {
    const tokenS = inputs.tokenS;
    const encSender = latticeEncrypt(inputs.mSenderNtt, d, K, SQRT_Q, OWNER_SEED);

    const receipt = await (await stateContract.attachSenderEncData(
      tokenS[0], tokenS[1], encSender,
    )).wait();

    const encData = encDataFromReceipt(receipt, stateContract);
    const decrypted = latticeDecrypt(Buffer.from(encData.slice(2), "hex"), d, K, SQRT_Q, OWNER_SEED);
    const reHash = rescueSpongeHash(decrypted);
    expect(reHash[0]).to.equal(mod(tokenS[0]));
    expect(reHash[1]).to.equal(mod(tokenS[1]));

    // Second attach for the same token_s must revert (flag consumed).
    let reverted = false;
    try {
      await stateContract.attachSenderEncData.staticCall(tokenS[0], tokenS[1], encSender);
    } catch (e: any) {
      reverted = e.message.includes("NoPendingEnc");
    }
    expect(reverted, "should revert NoPendingEnc").to.be.true;
  });

  it("decrypt emitted ciphertext and verify hash consistency", async function () {
    // token_o / token_s ciphertexts are emitted as TokenEncData events.
    const filter = stateContract.filters.TokenEncData(signer.address);
    const events = await stateContract.queryFilter(filter);
    expect(events.length).to.be.greaterThan(0);

    for (const ev of events) {
      const { h0, h1, encData } = (ev as any).args;
      const decrypted = latticeDecrypt(Buffer.from(encData.slice(2), "hex"), d, K, SQRT_Q, OWNER_SEED);
      const reHash = rescueSpongeHash(decrypted);
      expect(reHash[0]).to.equal(mod(h0), `hash[0] mismatch`);
      expect(reHash[1]).to.equal(mod(h1), `hash[1] mismatch`);
    }

    // token_m: recipient extracts the transfer amount from the commitment
    // cVecPacked itself (reuse) — no separate ciphertext is emitted.
    const cFlat: string[] = [];
    for (const row of inputs.cNtts) for (const v of row) cFlat.push(v.toString());
    const mRec: bigint[] = rust
      .latticeExtractNttR(d, K, SQRT_Q.toString(), LATTICE_SIS_SEED, LATTICE_DEFAULT_RECIPIENT, cFlat)
      .map((s: string) => BigInt(s));
    const mHash = rescueSpongeHash(mRec);
    expect(mHash[0]).to.equal(mod(inputs.tokenM[0]), "token_m hash[0] mismatch");
    expect(mHash[1]).to.equal(mod(inputs.tokenM[1]), "token_m hash[1] mismatch");
  });

  it("rejects double-spend (same token_o consumed twice)", async function () {
    this.timeout(120_000);

    // Try submitting the same proof again — token_o already removed
    try {
      const tx = await stateContract.processTransfer(
        encodeZKProofRangeHashBytes(proof, verifierContract.interface),
        encodeCVecHexRangeHash(inputs.cNtts),
        signer.address,
      );
      await tx.wait();
      expect.fail("should have reverted");
    } catch (e: any) {
      expect(e.message).to.include("TokenNotFound");
    }
  });

  it("split state path stays below 128 KiB and 16M gas per transaction", async function () {
    this.timeout(180_000);

    const rescueData = await deployRescueParamsData();
    const OodFactory = await (hre as any).ethers.getContractFactory("ZKStarkOodPhaseVerifier");
    const oodVerifier = await OodFactory.deploy(
      await rescueData.getAddress(), SQRT_Q, M, K, d, BLOWUP, CAP_HEIGHT,
    );
    await oodVerifier.waitForDeployment();
    const BaseFactory = await (hre as any).ethers.getContractFactory("ZKStarkBasePhaseVerifier");
    const baseVerifier = await BaseFactory.deploy(
      await rescueData.getAddress(), SQRT_Q, M, K, d, BLOWUP, CAP_HEIGHT,
    );
    await baseVerifier.waitForDeployment();
    const FriFactory = await (hre as any).ethers.getContractFactory("ZKStarkFriPhaseVerifier");
    const friVerifier = await FriFactory.deploy(
      await rescueData.getAddress(), SQRT_Q, M, K, d, BLOWUP, CAP_HEIGHT,
    );
    await friVerifier.waitForDeployment();
    const SplitFactory = await (hre as any).ethers.getContractFactory("ZKStarkSplittingVerifier");
    const splitVerifier = await SplitFactory.deploy(
      await rescueData.getAddress(), SQRT_Q, M, K, d, BLOWUP, CAP_HEIGHT,
      await oodVerifier.getAddress(),
      await baseVerifier.getAddress(), await friVerifier.getAddress(),
    );
    await splitVerifier.waitForDeployment();

    const StateFactory = await (hre as any).ethers.getContractFactory("ZKStarkRangeHashState");
    const splitState = await StateFactory.deploy(await verifierContract.getAddress());
    await splitState.waitForDeployment();
    await (await splitState.setSplittingVerifier(await splitVerifier.getAddress())).wait();
    await (await splitState.registerPubKey(aOracleHash, "0x")).wait();
    await (await splitState.preissue(
      signer.address, proof.tokenO[0], proof.tokenO[1], "0x",
    )).wait();

    const headerData = encodeZKProofRangeHashBytes(
      partitionSplitProof(proof, "header"), splitVerifier.interface,
    );
    const baseData = encodeZKProofRangeHashBytes(
      partitionSplitProof(proof, "base"), splitVerifier.interface,
    );
    const friData = encodeZKProofRangeHashBytes(
      partitionSplitProof(proof, "fri"), splitVerifier.interface,
    );
    const cVecPacked = encodeCVecHexRangeHash(inputs.cNtts);
    const [baseContext, friContext] = await splitVerifier.prepareVerificationContext(
      headerData, hre.ethers.keccak256(cVecPacked), aOracleHash,
    );

    const beginArgs = [headerData, cVecPacked, signer.address];
    const beginReceipt = await (await splitState.beginSplitTransfer(...beginArgs)).wait();
    const sessionId = parsedEvents(beginReceipt, splitVerifier, "VerificationBegun")[0].sessionId;

    const baseArgs = [sessionId, baseData, baseContext];
    const baseReceipt = await (await splitState.verifySplitTransferBase(...baseArgs)).wait();
    const checkpoints = parsedEvents(baseReceipt, splitVerifier, "BaseQueryCheckpoint")
      .sort((left, right) => Number(left.queryOrdinal - right.queryOrdinal));
    expect(checkpoints).to.have.length(NUM_QUERIES);
    const finalArgs = [sessionId, friData, friContext];
    const finalReceipt = await (await splitState.finalizeSplitTransfer(...finalArgs)).wait();
    expect(await splitVerifier.isVerified(sessionId)).to.equal(true);
    expect(await splitState.tokenCount(signer.address)).to.equal(2n);

    const stored: Array<{ h0: bigint; h1: bigint }> = [];
    for (let i = 0; i < 2; i++) {
      const [h0, h1] = await splitState.getToken(signer.address, i);
      stored.push({ h0, h1 });
    }
    const contains = (token: bigint[]) => stored.some(
      ({ h0, h1 }) => h0 === mod(token[0]) && h1 === mod(token[1]),
    );
    expect(contains(inputs.tokenS), "split transfer must add token_s").to.equal(true);
    expect(contains(inputs.tokenM), "split transfer must add token_m").to.equal(true);
    expect(contains(inputs.tokenO), "split transfer must consume token_o").to.equal(false);

    const calls = [
      splitState.interface.encodeFunctionData("beginSplitTransfer", beginArgs),
      splitState.interface.encodeFunctionData("verifySplitTransferBase", baseArgs),
      splitState.interface.encodeFunctionData("finalizeSplitTransfer", finalArgs),
    ];
    const receipts = [beginReceipt, baseReceipt, finalReceipt];
    const labels = ["header/OOD", "base openings", "FRI/finalize"];
    for (let i = 0; i < calls.length; i++) {
      const bytes = calldataBytes(calls[i]);
      const gas = Number(receipts[i].gasUsed);
      console.log(
        `        split state ${labels[i].padEnd(14)} calldata=${bytes.toLocaleString()} bytes ` +
        `gas=${gas.toLocaleString()}`,
      );
      expect(bytes, `${labels[i]} calldata`).to.be.at.most(MAX_SPLIT_CALLDATA_BYTES);
      expect(gas, `${labels[i]} gas`).to.be.lessThan(MAX_SPLIT_GAS);
    }
  });

  it("benchmarks Rust proof generation with 23-bit grinding", function () {
    this.timeout(1_800_000);

    const startedAt = Date.now();
    const { proof: grindingProof } = rustProveRaw(inputs, d, M, K, SQRT_Q, 23);
    const elapsedMs = Date.now() - startedAt;

    console.log(
      `        Rust prove (23-bit grinding): ${elapsedMs} ms, nonce ${grindingProof.grindingNonce}`,
    );
    expect(grindingProof.grindingNonce).to.be.at.least(0n);
  });
});
