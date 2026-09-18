
import { expect } from "chai";
import { ethers } from "ethers";
import hre from "hardhat";

import { P } from "./stark-utils";
import {
  BLOWUP,
  CAP_HEIGHT,
  buildInputsRangeHash,
  deployRescueParamsData,
  encodeCVecHexRangeHash,
  encodeZKProofRangeHashBytes,
  type ZKStarkUpdateRangeHashProof,
} from "./ZKStark_update_rangehash";

const rust = require("../stark-prover-native/stark-prover-native.node");

type ProofPart = "header" | "base" | "fri";

function hexBytes(hex: string): Uint8Array {
  const body = hex.startsWith("0x") ? hex.slice(2) : hex;
  return Uint8Array.from(Buffer.from(body, "hex"));
}

function convertRustProof(json: any): ZKStarkUpdateRangeHashProof {
  const bigintValue = (value: string) => BigInt(value);
  const bigintArray = (values: string[]) => values.map(bigintValue);
  const bigintMatrix = (values: string[][]) => values.map(bigintArray);
  const bytesArray = (values: string[]) => values.map(hexBytes);
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
    betaAur: bigintValue(json.beta_aur),
    tokenM: bigintArray(json.token_m),
    tokenS: bigintArray(json.token_s),
    tokenO: bigintArray(json.token_o),
    traceCap: bytesArray(json.trace_cap),
    tracePositions: json.trace_positions,
    traceColValues: bigintMatrix(json.trace_col_values),
    traceSalts: bytesArray(json.trace_salts),
    traceBatchProof: bytesArray(json.trace_batch_proof),
    interCap: bytesArray(json.inter_cap),
    interColValues: bigintMatrix(json.inter_col_values),
    interSalts: bytesArray(json.inter_salts),
    interBatchProof: bytesArray(json.inter_batch_proof),
    auxCap: bytesArray(json.aux_cap),
    auxColValues: bigintMatrix(json.aux_col_values),
    auxSalts: bytesArray(json.aux_salts),
    auxBatchProof: bytesArray(json.aux_batch_proof),
    cpChunkCap: bytesArray(json.cp_chunk_cap),
    cpChunkColValues: bigintMatrix(json.cp_chunk_col_values),
    cpChunkSalts: bytesArray(json.cp_chunk_salts),
    cpChunkBatchProof: bytesArray(json.cp_chunk_batch_proof),
    maskCap: bytesArray(json.mask_cap),
    maskValues: bigintArray(json.mask_values),
    maskSalts: bytesArray(json.mask_salts),
    maskBatchProof: bytesArray(json.mask_batch_proof),
    splitCap: bytesArray(json.split_cap),
    splitColValues: bigintMatrix(json.split_col_values),
    splitSalts: bytesArray(json.split_salts),
    splitBatchProof: bytesArray(json.split_batch_proof),
    aCap: bytesArray(json.a_cap),
    aColValues: bigintMatrix(json.a_col_values),
    aBatchProof: bytesArray(json.a_batch_proof),
    oodBNttZ: bigintArray(json.ood_bntt_z),
    oodGHatZ: bigintArray(json.ood_ghat_z),
    oodGloZ: bigintArray(json.ood_glo_z),
    oodGhiZ: bigintArray(json.ood_ghi_z),
    oodAZ: bigintArray(json.ood_a_z),
    oodTZ: bigintValue(json.ood_t_z),
    oodMZ: bigintValue(json.ood_m_z),
    oodMOrigZ: bigintValue(json.ood_m_orig_z),
    oodMSenderZ: bigintValue(json.ood_m_sender_z),
    oodDmZ: bigintArray(json.ood_dm_z),
    oodDsZ: bigintArray(json.ood_ds_z),
    oodPmZ: bigintArray(json.ood_pm_z),
    oodPsZ: bigintArray(json.ood_ps_z),
    oodPrZ: bigintArray(json.ood_pr_z),
    oodQcolZ: bigintValue(json.ood_qcol_z),
    oodMuZ: bigintValue(json.ood_mu_z),
    oodZlupZ: bigintValue(json.ood_zlup_z),
    oodZlupOmegaZ: bigintValue(json.ood_zlup_omega_z),
    oodRAurZ: bigintValue(json.ood_raur_z),
    oodRZ: bigintValue(json.ood_r_z),
    oodQZ: bigintValue(json.ood_q_z),
    oodQ1Z: bigintValue(json.ood_q1_z),
    oodCpChunkZ: bigintArray(json.ood_cp_chunk_z),
    oodHashStateZ: bigintMatrix(json.ood_hash_state_z),
    oodHashStateOmegaZ: bigintMatrix(json.ood_hash_state_omega_z),
    oodHashSigmaZ: bigintMatrix(json.ood_hash_sigma_z),
    oodSourceShifts: bigintMatrix(json.ood_source_shifts),
    friCaps: json.fri_caps.map(bytesArray),
    friLayerPositions: json.fri_layer_positions,
    friLayerValues: json.fri_layer_values.map(bigintArray),
    friLayerSalts: json.fri_layer_salts.map(bytesArray),
    friLayerProofs: json.fri_layer_proofs.map(bytesArray),
    friFinalPoly: bigintArray(json.fri_final_poly),
    grindingNonce: bigintValue(json.grinding_nonce),
    queryIndices: json.query_indices,
  };
}

function flatten3(values: bigint[][][]): string[] {
  return values.flat(2).map(String);
}

function flatten2(values: bigint[][]): string[] {
  return values.flat().map(String);
}

function proveUnchanged(
  inputs: ReturnType<typeof buildInputsRangeHash>,
  d: number,
  M: number,
  K: number,
  sqrtQ: bigint,
): { proof: ZKStarkUpdateRangeHashProof; aOracleHash: string } {
  const result = JSON.parse(rust.proveRangeHash(
    flatten3(inputs.aMat), M, K, d,
    flatten2(inputs.bCoeffs),
    inputs.mNtt.map(String), inputs.mOrigNtt.map(String), inputs.mSenderNtt.map(String),
    sqrtQ.toString(), flatten2(inputs.cNtts),
    inputs.tokenM.map(String), inputs.tokenS.map(String), inputs.tokenO.map(String),
  ));
  return { proof: convertRustProof(result), aOracleHash: result.a_oracle_hash };
}

function partitionProof(
  proof: ZKStarkUpdateRangeHashProof,
  part: ProofPart,
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
      friLayerPositions: [],
      friLayerValues: [],
      friLayerSalts: [],
      friLayerProofs: [],
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

function eventArgs(receipt: any, contract: any, eventName: string): any[] {
  const found: any[] = [];
  for (const log of receipt.logs) {
    try {
      const parsed = contract.interface.parseLog(log);
      if (parsed?.name === eventName) found.push(parsed.args);
    } catch {
      // Ignore logs emitted by other contracts.
    }
  }
  return found;
}

describe("split range/hash STARK verifier", function () {
  this.timeout(600_000);

  const sqrtQ = 18446744073709551615n % P;
  const d = 256;
  const M = 2;
  const K = 2;

  let verifier: any;
  let proof: ZKStarkUpdateRangeHashProof;
  let headerData: string;
  let baseData: string;
  let friData: string;
  let cVecPacked: string;
  let cVecHash: string;
  let baseContext: string;
  let friContext: string;
  let aOracleHash: string;
  let inputs: ReturnType<typeof buildInputsRangeHash>;

  before(async function () {
    inputs = buildInputsRangeHash(d, M, K, sqrtQ);
    ({ proof, aOracleHash } = proveUnchanged(inputs, d, M, K, sqrtQ));
    cVecPacked = encodeCVecHexRangeHash(inputs.cNtts);
    cVecHash = ethers.keccak256(cVecPacked);

    const rescueData = await deployRescueParamsData();
    const oodFactory = await (hre as any).ethers.getContractFactory("ZKStarkOodPhaseVerifier");
    const oodVerifier = await oodFactory.deploy(
      await rescueData.getAddress(), sqrtQ, M, K, d, BLOWUP, CAP_HEIGHT,
    );
    await oodVerifier.waitForDeployment();
    const baseFactory = await (hre as any).ethers.getContractFactory("ZKStarkBasePhaseVerifier");
    const baseVerifier = await baseFactory.deploy(
      await rescueData.getAddress(), sqrtQ, M, K, d, BLOWUP, CAP_HEIGHT,
    );
    await baseVerifier.waitForDeployment();
    const friFactory = await (hre as any).ethers.getContractFactory("ZKStarkFriPhaseVerifier");
    const friVerifier = await friFactory.deploy(
      await rescueData.getAddress(), sqrtQ, M, K, d, BLOWUP, CAP_HEIGHT,
    );
    await friVerifier.waitForDeployment();
    const factory = await (hre as any).ethers.getContractFactory("ZKStarkSplittingVerifier");
    verifier = await factory.deploy(
      await rescueData.getAddress(), sqrtQ, M, K, d, BLOWUP, CAP_HEIGHT,
      await oodVerifier.getAddress(),
      await baseVerifier.getAddress(), await friVerifier.getAddress(),
    );
    await verifier.waitForDeployment();

    headerData = encodeZKProofRangeHashBytes(partitionProof(proof, "header"), verifier.interface);
    baseData = encodeZKProofRangeHashBytes(partitionProof(proof, "base"), verifier.interface);
    friData = encodeZKProofRangeHashBytes(partitionProof(proof, "fri"), verifier.interface);
    [baseContext, friContext] = await verifier.prepareVerificationContext(
      headerData, cVecHash, aOracleHash,
    );
  });

  async function begin(): Promise<{ sessionId: string; receipt: any }> {
    const tx = await verifier.beginVerification(headerData, cVecPacked, aOracleHash);
    const receipt = await tx.wait();
    const events = eventArgs(receipt, verifier, "VerificationBegun");
    expect(events).to.have.length(1);
    return { sessionId: events[0].sessionId, receipt };
  }

  it("verifies one unchanged proof across three transactions", async function () {
    const started = await begin();

    const baseTx = await verifier.verifyBaseOpenings(
      started.sessionId, baseData, baseContext,
    );
    const baseReceipt = await baseTx.wait();
    const checkpoints = eventArgs(baseReceipt, verifier, "BaseQueryCheckpoint")
      .sort((left, right) => Number(left.queryOrdinal - right.queryOrdinal))
    expect(checkpoints).to.have.length(23);

    const friTx = await verifier.verifyFriAndFinalize(
      started.sessionId, friData, friContext,
    );
    const friReceipt = await friTx.wait();
    expect(await verifier.isVerified(started.sessionId)).to.equal(true);

    const calls = [
      verifier.interface.encodeFunctionData("beginVerification", [headerData, cVecPacked, aOracleHash]),
      verifier.interface.encodeFunctionData("verifyBaseOpenings", [started.sessionId, baseData, baseContext]),
      verifier.interface.encodeFunctionData("verifyFriAndFinalize", [
        started.sessionId, friData, friContext,
      ]),
    ];
    const receipts = [started.receipt, baseReceipt, friReceipt];
    const labels = ["header/OOD", "base openings", "FRI/finalize"];
    for (let i = 0; i < calls.length; i++) {
      console.log(
        `        ${labels[i].padEnd(14)} calldata=${calldataBytes(calls[i]).toLocaleString()} bytes ` +
        `gas=${Number(receipts[i].gasUsed).toLocaleString()}`,
      );
    }
  });

  it("rejects a commitment mutation between phases", async function () {
    const started = await begin();
    const mutated = {
      ...partitionProof(proof, "base"),
      tokenM: [(proof.tokenM[0] + 1n) % P, proof.tokenM[1]],
    };
    const mutatedData = encodeZKProofRangeHashBytes(mutated, verifier.interface);
    await expect(
      verifier.verifyBaseOpenings(started.sessionId, mutatedData, baseContext),
    ).to.be.revertedWithCustomError(verifier, "TranscriptMismatch");
  });

  it("rejects a modified authenticated context", async function () {
    const started = await begin();
    const modified = ethers.getBytes(baseContext);
    modified[modified.length - 1] ^= 1;
    await expect(
      verifier.verifyBaseOpenings(started.sessionId, baseData, ethers.hexlify(modified)),
    ).to.be.revertedWithCustomError(verifier, "TranscriptMismatch");
  });

  it("rejects an FRI commitment not bound in phase one", async function () {
    const started = await begin();
    await (await verifier.verifyBaseOpenings(started.sessionId, baseData, baseContext)).wait();
    const mutated = partitionProof(proof, "fri");
    mutated.friCaps = proof.friCaps.map((cap) => cap.map((node) => Uint8Array.from(node)));
    mutated.friCaps[0][0][0] ^= 1;
    const mutatedData = encodeZKProofRangeHashBytes(mutated, verifier.interface);
    await expect(
      verifier.verifyFriAndFinalize(started.sessionId, mutatedData, friContext),
    ).to.be.revertedWithCustomError(verifier, "TranscriptMismatch");
  });

  it("rejects finalization before base verification", async function () {
    const started = await begin();
    await expect(
      verifier.verifyFriAndFinalize(started.sessionId, friData, friContext),
    ).to.be.revertedWithCustomError(verifier, "InvalidPhase");
  });

  it("applies a split transfer through the legacy-compatible state manager", async function () {
    const [signer] = await (hre as any).ethers.getSigners();
    const stateFactory = await (hre as any).ethers.getContractFactory("ZKStarkRangeHashState");
    const state = await stateFactory.deploy(await verifier.getAddress());
    await state.waitForDeployment();
    await (await state.setSplittingVerifier(await verifier.getAddress())).wait();
    await (await state.registerPubKey(aOracleHash, "0x")).wait();
    await (await state.preissue(
      signer.address, proof.tokenO[0], proof.tokenO[1], "0x",
    )).wait();

    const beginReceipt = await (await state.beginSplitTransfer(
      headerData, cVecPacked, signer.address,
    )).wait();
    const sessionId = eventArgs(beginReceipt, verifier, "VerificationBegun")[0].sessionId;
    expect(await state.tokenCount(signer.address)).to.equal(1n);

    const baseReceipt = await (await state.verifySplitTransferBase(
      sessionId, baseData, baseContext,
    )).wait();
    const checkpoints = eventArgs(baseReceipt, verifier, "BaseQueryCheckpoint")
      .sort((left, right) => Number(left.queryOrdinal - right.queryOrdinal));
    const values = checkpoints.map((args) => args.layer0Value);
    const splitValues = checkpoints.map((args) => args.splitValue);
    const partialDeep = checkpoints.map((args) => args.partialDeep);
    expect(await state.tokenCount(signer.address)).to.equal(1n);

    await (await state.finalizeSplitTransfer(
      sessionId, friData, friContext,
    )).wait();
    expect(await verifier.isVerified(sessionId)).to.equal(true);
    expect(await state.tokenCount(signer.address)).to.equal(2n);
  });

  it("benchmark test", async function () {
    const benchD = 1024;
    const benchM = 6;
    const benchK = 10;
    const inputs = buildInputsRangeHash(benchD, benchM, benchK, sqrtQ);
    const generated = proveUnchanged(inputs, benchD, benchM, benchK, sqrtQ);
    const packedCVec = encodeCVecHexRangeHash(inputs.cNtts);
    const packedCVecHash = ethers.keccak256(packedCVec);

    const rescueData = await deployRescueParamsData();
    const oodFactory = await (hre as any).ethers.getContractFactory("ZKStarkOodPhaseVerifier");
    const oodVerifier = await oodFactory.deploy(
      await rescueData.getAddress(), sqrtQ, benchM, benchK, benchD, BLOWUP, CAP_HEIGHT,
    );
    await oodVerifier.waitForDeployment();
    const baseFactory = await (hre as any).ethers.getContractFactory("ZKStarkBasePhaseVerifier");
    const baseVerifier = await baseFactory.deploy(
      await rescueData.getAddress(), sqrtQ, benchM, benchK, benchD, BLOWUP, CAP_HEIGHT,
    );
    await baseVerifier.waitForDeployment();
    const friFactory = await (hre as any).ethers.getContractFactory("ZKStarkFriPhaseVerifier");
    const friVerifier = await friFactory.deploy(
      await rescueData.getAddress(), sqrtQ, benchM, benchK, benchD, BLOWUP, CAP_HEIGHT,
    );
    await friVerifier.waitForDeployment();
    const factory = await (hre as any).ethers.getContractFactory("ZKStarkSplittingVerifier");
    const benchVerifier = await factory.deploy(
      await rescueData.getAddress(), sqrtQ, benchM, benchK, benchD, BLOWUP, CAP_HEIGHT,
      await oodVerifier.getAddress(),
      await baseVerifier.getAddress(), await friVerifier.getAddress(),
    );
    await benchVerifier.waitForDeployment();

    const header = encodeZKProofRangeHashBytes(
      partitionProof(generated.proof, "header"), benchVerifier.interface,
    );
    const base = encodeZKProofRangeHashBytes(
      partitionProof(generated.proof, "base"), benchVerifier.interface,
    );
    const fri = encodeZKProofRangeHashBytes(
      partitionProof(generated.proof, "fri"), benchVerifier.interface,
    );
    const [benchBaseContext, benchFriContext] = await benchVerifier.prepareVerificationContext(
      header, packedCVecHash, generated.aOracleHash,
    );
    const beginTx = await benchVerifier.beginVerification(
      header, packedCVec, generated.aOracleHash,
    );
    const beginReceipt = await beginTx.wait();
    const sessionId = eventArgs(beginReceipt, benchVerifier, "VerificationBegun")[0].sessionId;

    const baseTx = await benchVerifier.verifyBaseOpenings(
      sessionId, base, benchBaseContext,
    );
    const baseReceipt = await baseTx.wait();
    const checkpoints = eventArgs(baseReceipt, benchVerifier, "BaseQueryCheckpoint")
      .sort((left, right) => Number(left.queryOrdinal - right.queryOrdinal))
    expect(checkpoints).to.have.length(23);

    const friTx = await benchVerifier.verifyFriAndFinalize(
      sessionId, fri, benchFriContext,
    );
    const friReceipt = await friTx.wait();
    expect(await benchVerifier.isVerified(sessionId)).to.equal(true);

    const calls = [
      benchVerifier.interface.encodeFunctionData(
        "beginVerification", [header, packedCVec, generated.aOracleHash],
      ),
      benchVerifier.interface.encodeFunctionData(
        "verifyBaseOpenings", [sessionId, base, benchBaseContext],
      ),
      benchVerifier.interface.encodeFunctionData(
        "verifyFriAndFinalize", [sessionId, fri, benchFriContext],
      ),
    ];
    const receipts = [beginReceipt, baseReceipt, friReceipt];
    const labels = ["header/OOD", "base openings", "FRI/finalize"];
    const measurements: Array<{ label: string; bytes: number; gas: number }> = [];
    for (let i = 0; i < calls.length; i++) {
      const bytes = calldataBytes(calls[i]);
      const gas = Number(receipts[i].gasUsed);
      console.log(
        `        realistic ${labels[i].padEnd(14)} calldata=${bytes.toLocaleString()} bytes ` +
        `gas=${gas.toLocaleString()}`,
      );
      measurements.push({ label: labels[i], bytes, gas });
    }
    for (const measurement of measurements) {
      expect(measurement.bytes, `${measurement.label} calldata`).to.be.at.most(131 * 1024);
      expect(measurement.gas, `${measurement.label} gas`).to.be.lessThan(16_000_000);
    }
  });
});
