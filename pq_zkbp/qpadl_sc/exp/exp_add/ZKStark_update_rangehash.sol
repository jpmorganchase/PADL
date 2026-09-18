pragma solidity ^0.8.26;

abstract contract ZKStarkUpdateRangeHashCore {

    // Custom errors 
    error InvalidParam();
    error BadRescueParams();
    error BlindingOverflow();

    // Field parameters
    uint256 internal constant P = 340282366920938463463374607393113505793;
    uint256 internal constant G_PRIM = 3;
    uint256 internal constant FRI_ARITY = 4;
    uint256 internal constant FINAL_POLY_BOUND = 16;
    uint256 internal constant GRINDING_BITS = 23;
    uint256 internal constant NUM_QUERIES = 23;
    uint256 internal constant NUM_BYTES = 8;
    uint256 internal constant TABLE_SIZE = 256;
    uint256 internal constant INTER_COL_COUNT = 18; // Fixed columns; total is 18 + 2K.
    // Range-check shift (η = 2^15): ĝ ∈ [−2^15, 2^15) ⇒ ĝ + 2^15 ∈ [0, 2^16) = 2 bytes.
    uint256 internal constant R_SHIFT = 1 << 15;

    // Hash constants
    uint256 internal constant HASH_STATE_WIDTH = 12;
    uint256 internal constant HASH_RATE = 8;
    uint256 internal constant HASH_OUTPUT_LANES = 2;
    uint256 internal constant NUM_HASHES = 3;
    uint256 internal constant INV8 = 297747071055821155530452781468974317569;

    // Rescue params hash: keccak256(abi.encodePacked(M[144], MINV[144], B1[96], B2[96]))
    bytes32 internal constant RESCUE_PARAMS_HASH = 0x6028ed518a9cb36421a5dab2193a686cb4a0d708d4f1a47fa80d671a7b5f2d74;
    uint256 private constant RESCUE_PARAM_BYTES = 480 * 32;
    uint256 private constant RESCUE_DATA_CODE_BYTES = RESCUE_PARAM_BYTES + 1;

    // Preprocessed state
    address internal immutable _rescueData;
    bytes32 internal immutable _rescueDataCodeHash;
    uint256 internal immutable _sqrtQ;
    uint32 internal immutable _matM;
    uint32 internal immutable _matK;
    uint32 internal immutable _matD;
    uint32 internal immutable _aBlowup;
    uint32 internal immutable _aCapHeight;

    constructor(
        address rescueData_,
        uint256 sqrtQ_,
        uint32 M_,
        uint32 K_,
        uint32 d_,
        uint32 blowup_,
        uint32 capHeight_
    ) {
        if (rescueData_ == address(0) || rescueData_.code.length != RESCUE_DATA_CODE_BYTES) {
            revert BadRescueParams();
        }
        bytes32 paramsHash;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            extcodecopy(rescueData_, ptr, 1, RESCUE_PARAM_BYTES)
            paramsHash := keccak256(ptr, RESCUE_PARAM_BYTES)
        }
        if (paramsHash != RESCUE_PARAMS_HASH) revert BadRescueParams();
        _rescueData = rescueData_;
        _rescueDataCodeHash = rescueData_.codehash;
        if (M_ < 2 || K_ == 0) revert InvalidParam();
        if (d_ < TABLE_SIZE || !_isPow2(d_)) revert InvalidParam();
        if (blowup_ == 0 || !_isPow2(blowup_) || blowup_ % 2 != 0) revert InvalidParam();
        if ((P - 1) % uint256(d_) != 0) revert InvalidParam();
        if ((P - 1) % (2 * uint256(d_)) != 0) revert InvalidParam();
        if ((P - 1) % (uint256(d_) * uint256(blowup_)) != 0) revert InvalidParam();
        if ((P - 1) % (2 * uint256(d_) * uint256(blowup_)) != 0) revert InvalidParam();
        uint256 sq = sqrtQ_ % P;
        if (sq == 0) revert InvalidParam();
        _sqrtQ = sq;
        _matM = M_;
        _matK = K_;
        _matD = d_;
        _aBlowup = blowup_;
        _aCapHeight = capHeight_;
    }

    // Proof struct

    struct ZKProofRange {
        uint32 traceLength;       // N
        uint32 numColumns;        // K
        uint32 blowup;
        uint32 capHeight;
        uint32 blindB;
        uint32 blindBSource;      // source cols blinding (Q+8)
        uint32 blindBState;       // hash state blinding (Q+2)
        uint32 blindBSigma;       // hash sigma blinding (Q+1)
        uint32 cpBlindH;
        uint32 numChunks;
        uint32 cpChunkWidth;
        uint256 betaAur;
        bytes friFinalPoly;

        // Round 0 trace (4K+81 cols, salted)
        bytes32[] traceCap;
        uint32[]  tracePositions;
        bytes[] traceColValues;  // packed canonical uint128 values
        bytes16[] traceSalts;
        bytes32[] traceBatchProof;

        // Round 0.5 interaction (18+2K cols, salted, after β_lup)
        bytes32[] interCap;
        bytes[] interColValues;  // packed canonical uint128 values
        bytes16[] interSalts;
        bytes32[] interBatchProof;

        // Aurora aux R, Q0, Q1 (3 cols, salted)
        bytes32[] auxCap;
        bytes[] auxColValues;    // packed canonical uint128 values
        bytes16[] auxSalts;
        bytes32[] auxBatchProof;

        // CP chunks (numChunks cols, salted)
        bytes32[] cpChunkCap;
        bytes[] cpChunkColValues; // packed canonical uint128 values
        bytes16[] cpChunkSalts;
        bytes32[] cpChunkBatchProof;

        // Mask R_deep (1 col, salted)
        bytes32[] maskCap;
        bytes maskValues;        // packed canonical uint128 values
        bytes16[] maskSalts;
        bytes32[] maskBatchProof;

        // Split g0, g1 (2-col, salted)
        bytes32[] splitCap;
        bytes[] splitColValues;  // packed canonical uint128 values
        bytes16[] splitSalts;
        bytes32[] splitBatchProof;

        // A oracle (M*K + 1 cols incl. table, UNSALTED)
        bytes32[] aCap;
        bytes[] aColValues;        // packed 16-byte per field
        bytes32[] aBatchProof;

        // OOD openings at z
        bytes oodBNttZ;           // K packed uint128 values
        bytes oodGHatZ;           // K packed uint128 values
        bytes oodGloZ;            // K packed uint128 values
        bytes oodGhiZ;            // K packed uint128 values
        bytes oodAZ;              // M*K packed uint128 values
        uint256   oodTZ;          // table at z
        uint256   oodMZ;
        uint256   oodMOrigZ;
        uint256   oodMSenderZ;
        bytes oodDmZ;             // 8 packed d^(m)_j values
        bytes oodDsZ;             // 8 packed d^(s)_j values
        bytes oodPmZ;             // 8 packed p^(m)_j values
        bytes oodPsZ;             // 8 packed p^(s)_j values
        bytes oodPrZ;             // 2K packed p^(r)_j values
        uint256   oodQcolZ;       // q(z)
        uint256   oodMuZ;
        uint256   oodZlupZ;
        uint256   oodZlupOmegaZ;  // Z_lup(ωz)
        uint256   oodRAurZ;
        uint256   oodRZ;
        uint256   oodQZ;          // Q0(z), where Q = Q0 + X^N Q1
        uint256   oodQ1Z;
        bytes oodCpChunkZ;        // d packed uint128 values

        // Hash OOD openings
        bytes oodHashStateZ;       // 36 packed uint128 values
        bytes oodHashStateOmegaZ;  // 36 packed uint128 values
        bytes oodHashSigmaZ;       // 24 packed uint128 values
        bytes oodSourceShifts;     // 21 packed uint128 values
        uint256[2] tokenM;            // public hash commitment
        uint256[2] tokenS;
        uint256[2] tokenO;

        // FRI (arity-4)
        bytes32[][] friCaps;
        uint32[][]  friLayerPositions;
        bytes[] friLayerValues;  // one packed uint128 buffer per FRI layer
        bytes16[][] friLayerSalts;
        bytes32[][] friLayerProofs;
        uint64      grindingNonce;
        uint32[]    queryIndices;
    }

    // Verify context (populated during transcript replay)

    struct VerifyCtx {
        uint256 N;
        uint256 K;
        uint256 M;
        uint256 MK;
        uint256 traceCols;       // 4K+81
        uint256 ldeSize;
        uint256 b;
        uint256 bSource;         // source blinding (Q+8)
        uint256 bState;          // hash state blinding (Q+2)
        uint256 bSigma;          // hash sigma blinding (Q+1)
        uint256 hBlind;
        uint256 dChunks;
        uint256 w;               // N
        uint256 omega;
        uint256 psi;
        uint256 ldeOmega;
        uint256 cosetGen;
        uint256 numFriLayers;
        uint256 inv4;
        uint256 mu;              // primitive 4th root
        uint256 quarter0;
        uint256 omegaNm1;        // ω^{N-1}

        uint256 z;
        uint256 omegaZ;
        uint256 alpha;
        uint256 lambda;
        uint256 betaLup;
        uint256 rhoMsg;
        uint256 rhoAurora;
        uint256 betaAur;

        // Cached OOD scalars
        uint256 oodM;
        uint256 oodMOrig;
        uint256 oodMSender;
        uint256 oodRAur;
        uint256 oodR;
        uint256 oodQ;
        uint256 oodQ1;
        uint256 oodTZ;
        uint256 oodQcol;
        uint256 oodMu;
        uint256 oodZlup;
        uint256 oodZlupOmega;

        uint256[] alphaPows;     // 3K+124
        uint256[] rhos;          // M
        uint256[] lamK;          // K

        // DEEP γ challenges
        uint256[] gBNttZ;        // K
        uint256[] gGHatZ;        // K
        uint256[] gGloZ;         // K
        uint256[] gGhiZ;         // K
        uint256[] gPrZ;          // 2K
        uint256[] gAZ;           // M*K
        uint256 gTZ;
        uint256 gM;
        uint256 gMOrig;
        uint256 gMSender;
        uint256[8] gDmZ;
        uint256[8] gDsZ;
        uint256[8] gPmZ;
        uint256[8] gPsZ;
        uint256 gQcol;
        uint256 gMu;
        uint256 gZlup;
        uint256 gZlupOmega;
        uint256 gRAur;
        uint256 gR;
        uint256 gQ;
        uint256[] gCpChunk;      // d

        // Hash DEEP γ challenges
        uint256[] gHashStateZ;      // NUM_HASHES * HASH_STATE_WIDTH = 36
        uint256[] gHashStateOmegaZ; // 36
        uint256[] gHashSigmaZ;      // NUM_HASHES * HASH_RATE = 24
        uint256[] gSourceShifts;    // NUM_HASHES * 7 = 21

        uint256[] friBetas;
        uint256[] friInverses;
        uint256[] queryPoints;
        uint256 friInvStride;
        uint256 rescueParamsPtr;
    }

    function _proofFromBytes(bytes calldata proofData)
        internal pure returns (ZKProofRange calldata proof)
    {
        if (proofData.length < 32) revert InvalidParam();
        uint256 tupleOffset;
        assembly ("memory-safe") { tupleOffset := calldataload(proofData.offset) }
        if (tupleOffset != 32) revert InvalidParam();
        assembly ("memory-safe") { proof := add(proofData.offset, tupleOffset) }
    }

    function _loadRescueParams() internal view returns (uint256 ptr) {
        address rescueData = _rescueData;
        if (rescueData.codehash != _rescueDataCodeHash) revert BadRescueParams();
        assembly ("memory-safe") {
            ptr := mload(0x40)
            extcodecopy(rescueData, ptr, 1, RESCUE_PARAM_BYTES)
            mstore(0x40, add(ptr, RESCUE_PARAM_BYTES))
        }
    }

    // Verification orchestration

    function _verify(
        ZKProofRange calldata proof,
        bytes calldata cVecPacked,
        bytes32 aOracleHashExpected
    ) internal view returns (bool) {
        uint256 d = uint256(_matD);
        uint256 K = uint256(_matK);
        uint256 M = uint256(_matM);
        if (d == 0 || K == 0 || M == 0) return false;
        if (cVecPacked.length != M * d * 16) return false;
        if (uint256(proof.numColumns) != K) return false;
        if (uint256(proof.traceLength) != d) return false;
        if (uint256(proof.blowup) != uint256(_aBlowup)) return false;
        if (uint256(proof.capHeight) != uint256(_aCapHeight)) return false;
        if (proof.queryIndices.length != NUM_QUERIES) return false;
        if (proof.oodBNttZ.length != K * 16) return false;
        if (proof.oodGHatZ.length != K * 16) return false;
        if (proof.oodGloZ.length != K * 16) return false;
        if (proof.oodGhiZ.length != K * 16) return false;
        if (proof.oodDmZ.length != NUM_BYTES * 16) return false;
        if (proof.oodDsZ.length != NUM_BYTES * 16) return false;
        if (proof.oodPmZ.length != NUM_BYTES * 16) return false;
        if (proof.oodPsZ.length != NUM_BYTES * 16) return false;
        if (proof.oodPrZ.length != 2 * K * 16) return false;
        if (proof.oodAZ.length != M * K * 16) return false;
        if (proof.oodHashStateZ.length != NUM_HASHES * HASH_STATE_WIDTH * 16) return false;
        if (proof.oodHashStateOmegaZ.length != NUM_HASHES * HASH_STATE_WIDTH * 16) return false;
        if (proof.oodHashSigmaZ.length != NUM_HASHES * HASH_RATE * 16) return false;
        if (proof.oodSourceShifts.length != NUM_HASHES * (HASH_RATE - 1) * 16) return false;
        if (proof.interCap.length == 0) return false;
        if (proof.auxCap.length == 0) return false;
        if (proof.cpChunkCap.length == 0) return false;
        if (proof.maskCap.length == 0) return false;
        if (proof.splitCap.length == 0) return false;
        if (proof.aCap.length == 0) return false;

        VerifyCtx memory ctx;
        ctx.rescueParamsPtr = _loadRescueParams();
        ctx.N = d;
        ctx.K = K;
        ctx.M = M;
        ctx.MK = M * K;
        ctx.traceCols = 4 * K + 81;
        ctx.ldeSize = ctx.N * uint256(proof.blowup);

        ctx.b = _blindingBudget(ctx.N, proof.queryIndices.length);
        ctx.bSource = proof.queryIndices.length + 8;
        ctx.bState = proof.queryIndices.length + 2;
        ctx.bSigma = proof.queryIndices.length + 1;
        ctx.hBlind = proof.queryIndices.length + 1;
        ctx.w = ctx.N;
        ctx.dChunks = _cpNumChunksHash(ctx.N, ctx.bState);
        if (uint256(proof.blindB) != ctx.b) return false;
        if (uint256(proof.blindBSource) != ctx.bSource) return false;
        if (uint256(proof.blindBState) != ctx.bState) return false;
        if (uint256(proof.blindBSigma) != ctx.bSigma) return false;
        if (uint256(proof.cpBlindH) != ctx.hBlind) return false;
        if (uint256(proof.cpChunkWidth) != ctx.w) return false;
        if (uint256(proof.numChunks) != ctx.dChunks) return false;
        if (proof.oodCpChunkZ.length != ctx.dChunks * 16) return false;

        ctx.numFriLayers = proof.friCaps.length;
        ctx.omega = _pow(G_PRIM, (P - 1) / ctx.N);
        ctx.psi = _pow(G_PRIM, (P - 1) / (2 * ctx.N));
        ctx.ldeOmega = _pow(G_PRIM, (P - 1) / ctx.ldeSize);
        ctx.cosetGen = _pow(G_PRIM, (P - 1) / (2 * ctx.ldeSize));
        ctx.omegaNm1 = _pow(ctx.omega, ctx.N - 1);

        // Cache OOD scalars
        ctx.oodM = proof.oodMZ % P;
        ctx.oodMOrig = proof.oodMOrigZ % P;
        ctx.oodMSender = proof.oodMSenderZ % P;
        ctx.oodRAur = proof.oodRAurZ % P;
        ctx.oodR = proof.oodRZ % P;
        ctx.oodQ = proof.oodQZ % P;
        ctx.oodQ1 = proof.oodQ1Z % P;
        ctx.oodTZ = proof.oodTZ % P;
        ctx.oodQcol = proof.oodQcolZ % P;
        ctx.oodMu = proof.oodMuZ % P;
        ctx.oodZlup = proof.oodZlupZ % P;
        ctx.oodZlupOmega = proof.oodZlupOmegaZ % P;

        // A-oracle cap binding (assembly avoids abi.encodePacked allocation)
        {
            bytes32[] calldata aCap = proof.aCap;
            bytes32 capHash;
            assembly ("memory-safe") {
                let ptr := mload(0x40)
                let sz := mul(aCap.length, 32)
                calldatacopy(ptr, aCap.offset, sz)
                capHash := keccak256(ptr, sz)
            }
            if (capHash != aOracleHashExpected) return false;
        }

        // ── Fiat–Shamir transcript rebuild ───────────────────────────────
        bytes32 cHash = keccak256(cVecPacked);
        bytes32 state = _initTranscript();
        state = _absorbU64(state, uint32(M));
        state = _absorbU64(state, proof.traceLength);
        state = _absorbU64(state, proof.numColumns);
        state = _absorbU64(state, proof.blowup);
        state = _absorbU64(state, proof.capHeight);
        state = _absorbU64(state, uint32(ctx.b));
        state = _absorbU64(state, uint32(ctx.bSource));
        state = _absorbU64(state, uint32(ctx.bState));
        state = _absorbU64(state, uint32(ctx.bSigma));
        state = _absorbU64(state, uint32(ctx.hBlind));
        state = _absorbU64(state, uint32(ctx.w));
        state = _absorbHash(state, aOracleHashExpected);
        state = _absorbField(state, _sqrtQ);
        state = _absorbHash(state, cHash);
        // Public hash tokens
        state = _absorbField(state, proof.tokenM[0]);
        state = _absorbField(state, proof.tokenM[1]);
        state = _absorbField(state, proof.tokenS[0]);
        state = _absorbField(state, proof.tokenS[1]);
        state = _absorbField(state, proof.tokenO[0]);
        state = _absorbField(state, proof.tokenO[1]);

        // Absorb trace cap
        state = _absorbHashArray(state, proof.traceCap);

        // ── Squeeze: ρ, α, λ_k, β_lup ──────────────────────────────────
        uint256 rho0;
        (state, rho0) = _challenge(state);
        ctx.rhos = new uint256[](M);
        unchecked {
            uint256 acc = rho0;
            for (uint256 m = 0; m < M; m++) {
                ctx.rhos[m] = acc;
                acc = mulmod(acc, rho0, P);
            }
        }
        ctx.rhoMsg = addmod(ctx.rhos[M - 2], mulmod(ctx.rhos[M - 1], _sqrtQ, P), P);

        (state, ctx.alpha) = _challenge(state);
        {
            uint256 nQ = 3 * K + 124;
            ctx.alphaPows = new uint256[](nQ);
            ctx.alphaPows[0] = ctx.alpha;
            unchecked {
                for (uint256 i = 1; i < nQ; i++)
                    ctx.alphaPows[i] = mulmod(ctx.alphaPows[i - 1], ctx.alpha, P);
            }
        }

        ctx.lamK = new uint256[](K);
        unchecked {
            for (uint256 k = 0; k < K; k++)
                (state, ctx.lamK[k]) = _challenge(state);
        }

        (state, ctx.betaLup) = _challenge(state);

        // ── Absorb interaction cap (Round 0.5)
        state = _absorbHashArray(state, proof.interCap);

        // ── Aurora: absorb β, squeeze ρ_aurora 
        ctx.betaAur = proof.betaAur % P;
        state = _absorbField(state, proof.betaAur);
        (state, ctx.rhoAurora) = _challenge(state);

        // ── Absorb aux cap, CP chunk cap 
        state = _absorbHashArray(state, proof.auxCap);
        state = _absorbHashArray(state, proof.cpChunkCap);

        // ── OOD point z 
        (state, ctx.z) = _challenge(state);
        ctx.omegaZ = mulmod(ctx.omega, ctx.z, P);

        // ── Absorb OOD claims
        state = _absorbOodClaims(state, proof, ctx);

        // ── OOD constraint check (CP + Aurora + Hash)
        if (!_checkOodConstraint(proof, cVecPacked, ctx)) return false;
        // Rescue params were copied from the validated data contract before this check.

        // ── Mask cap 
        state = _absorbHashArray(state, proof.maskCap);

        // ── DEEP γ challenges
        state = _squeezeDeepChallenges(state, ctx);

        // ── Split cap + λ 
        state = _absorbHashArray(state, proof.splitCap);
        (state, ctx.lambda) = _challenge(state);

        // ── FRI transcript 
        if (ctx.numFriLayers == 0) return false;
        {
            uint256 shift = 2 * ctx.numFriLayers;
            if (shift >= 256) return false;
            uint256 divisor = uint256(1) << shift;
            if (ctx.N % divisor != 0) return false;
            uint256 expectedFinalBound = ctx.N / divisor;
            if (expectedFinalBound < 1 || expectedFinalBound > FINAL_POLY_BOUND) return false;
            if (proof.friFinalPoly.length != expectedFinalBound * 16) return false;
        }
        state = _absorbHashArray(state, proof.friCaps[0]);
        ctx.friBetas = new uint256[](ctx.numFriLayers);
        unchecked {
            for (uint256 r = 0; r < ctx.numFriLayers; r++) {
                (state, ctx.friBetas[r]) = _challenge(state);
                if (r + 1 < ctx.numFriLayers) {
                    state = _absorbHashArray(state, proof.friCaps[r + 1]);
                }
            }
        }
        state = _absorbPackedFieldArray(state, proof.friFinalPoly);

        // ── Grinding 
        state = _absorbU64Long(state, proof.grindingNonce);
        if (_leadingZeroBits(state) < GRINDING_BITS) return false;

        // ── Query indices
        ctx.quarter0 = ctx.ldeSize / FRI_ARITY;
        unchecked {
            for (uint256 i = 0; i < proof.queryIndices.length; i++) {
                uint256 idx;
                (state, idx) = _challengeIndex(state, ctx.quarter0);
                if (uint256(proof.queryIndices[i]) != idx) return false;
            }
        }

        // ── Merkle verifications 
        if (!_verifyAllMerkle(proof, ctx)) return false;

        // ── Per-query checks 
        if (!_verifyQueries(proof, ctx)) return false;

        return true;
    }

    // Absorb OOD claims into transcript (mirrors TS ordering)

    function _absorbOodClaims(
        bytes32 state,
        ZKProofRange calldata proof,
        VerifyCtx memory ctx
    ) internal pure returns (bytes32) {
        uint256 K = ctx.K;
        unchecked {
            for (uint256 i = 0; i < K; i++) state = _absorbField(state, _packedFieldAt(proof.oodBNttZ, i));
            for (uint256 i = 0; i < K; i++) state = _absorbField(state, _packedFieldAt(proof.oodGHatZ, i));
            for (uint256 i = 0; i < K; i++) state = _absorbField(state, _packedFieldAt(proof.oodGloZ, i));
            for (uint256 i = 0; i < K; i++) state = _absorbField(state, _packedFieldAt(proof.oodGhiZ, i));
            for (uint256 i = 0; i < ctx.MK; i++) state = _absorbField(state, _packedFieldAt(proof.oodAZ, i));
        }
        state = _absorbField(state, proof.oodTZ);
        state = _absorbField(state, proof.oodMZ);
        state = _absorbField(state, proof.oodMOrigZ);
        state = _absorbField(state, proof.oodMSenderZ);
        unchecked {
            for (uint256 j = 0; j < NUM_BYTES; j++) state = _absorbField(state, _packedFieldAt(proof.oodDmZ, j));
            for (uint256 j = 0; j < NUM_BYTES; j++) state = _absorbField(state, _packedFieldAt(proof.oodDsZ, j));
            for (uint256 j = 0; j < NUM_BYTES; j++) state = _absorbField(state, _packedFieldAt(proof.oodPmZ, j));
            for (uint256 j = 0; j < NUM_BYTES; j++) state = _absorbField(state, _packedFieldAt(proof.oodPsZ, j));
            for (uint256 j = 0; j < 2 * K; j++) state = _absorbField(state, _packedFieldAt(proof.oodPrZ, j));
        }
        state = _absorbField(state, proof.oodQcolZ);
        state = _absorbField(state, proof.oodMuZ);
        state = _absorbField(state, proof.oodZlupZ);
        state = _absorbField(state, proof.oodZlupOmegaZ);
        state = _absorbField(state, proof.oodRAurZ);
        state = _absorbField(state, proof.oodRZ);
        state = _absorbField(state, proof.oodQZ);
        state = _absorbField(state, proof.oodQ1Z);
        unchecked {
            for (uint256 i = 0; i < ctx.dChunks; i++)
                state = _absorbField(state, _packedFieldAt(proof.oodCpChunkZ, i));
        }
        // Hash OOD absorptions — batch using assembly for ~36+36+24+21=117 calls
        state = _absorbPackedFieldArray(state, proof.oodHashStateZ);
        state = _absorbPackedFieldArray(state, proof.oodHashStateOmegaZ);
        state = _absorbPackedFieldArray(state, proof.oodHashSigmaZ);
        state = _absorbPackedFieldArray(state, proof.oodSourceShifts);
        return state;
    }

    /// @dev Absorb an entire calldata bytes32[] array in assembly.
    ///      Used for Merkle cap absorption — avoids per-element function calls.
    function _absorbHashArray(bytes32 state, bytes32[] calldata arr)
        internal pure returns (bytes32)
    {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            let n := arr.length
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                mstore(ptr, state)
                mstore(add(ptr, 32), calldataload(add(arr.offset, mul(i, 32))))
                state := keccak256(ptr, 64)
            }
        }
        return state;
    }

    // Squeeze DEEP γ challenges

    function _squeezeDeepChallenges(bytes32 state, VerifyCtx memory ctx)
        internal pure returns (bytes32)
    {
        uint256 K = ctx.K;
        ctx.gBNttZ = new uint256[](K);
        ctx.gGHatZ = new uint256[](K);
        ctx.gGloZ  = new uint256[](K);
        ctx.gGhiZ  = new uint256[](K);
        ctx.gPrZ   = new uint256[](2 * K);
        ctx.gAZ    = new uint256[](ctx.MK);
        ctx.gCpChunk = new uint256[](ctx.dChunks);

        unchecked {
            for (uint256 k = 0; k < K; k++) (state, ctx.gBNttZ[k]) = _challenge(state);
            for (uint256 k = 0; k < K; k++) (state, ctx.gGHatZ[k]) = _challenge(state);
            for (uint256 k = 0; k < K; k++) (state, ctx.gGloZ[k])  = _challenge(state);
            for (uint256 k = 0; k < K; k++) (state, ctx.gGhiZ[k])  = _challenge(state);
            for (uint256 j = 0; j < ctx.MK; j++) (state, ctx.gAZ[j]) = _challenge(state);
        }
        (state, ctx.gTZ) = _challenge(state);
        (state, ctx.gM) = _challenge(state);
        (state, ctx.gMOrig) = _challenge(state);
        (state, ctx.gMSender) = _challenge(state);
        unchecked {
            for (uint256 j = 0; j < NUM_BYTES; j++) (state, ctx.gDmZ[j]) = _challenge(state);
            for (uint256 j = 0; j < NUM_BYTES; j++) (state, ctx.gDsZ[j]) = _challenge(state);
            for (uint256 j = 0; j < NUM_BYTES; j++) (state, ctx.gPmZ[j]) = _challenge(state);
            for (uint256 j = 0; j < NUM_BYTES; j++) (state, ctx.gPsZ[j]) = _challenge(state);
            for (uint256 j = 0; j < 2 * K; j++) (state, ctx.gPrZ[j]) = _challenge(state);
        }
        (state, ctx.gQcol) = _challenge(state);
        (state, ctx.gMu) = _challenge(state);
        (state, ctx.gZlup) = _challenge(state);
        (state, ctx.gZlupOmega) = _challenge(state);
        (state, ctx.gRAur) = _challenge(state);
        (state, ctx.gR) = _challenge(state);
        (state, ctx.gQ) = _challenge(state);
        unchecked {
            for (uint256 j = 0; j < ctx.dChunks; j++) (state, ctx.gCpChunk[j]) = _challenge(state);
        }
        // Hash DEEP γ challenges
        ctx.gHashStateZ = new uint256[](NUM_HASHES * HASH_STATE_WIDTH);
        ctx.gHashStateOmegaZ = new uint256[](NUM_HASHES * HASH_STATE_WIDTH);
        ctx.gHashSigmaZ = new uint256[](NUM_HASHES * HASH_RATE);
        ctx.gSourceShifts = new uint256[](NUM_HASHES * 7);
        unchecked {
            for (uint256 hi = 0; hi < NUM_HASHES; hi++) {
                for (uint256 ci = 0; ci < HASH_STATE_WIDTH; ci++)
                    (state, ctx.gHashStateZ[hi * HASH_STATE_WIDTH + ci]) = _challenge(state);
                for (uint256 ci = 0; ci < HASH_STATE_WIDTH; ci++)
                    (state, ctx.gHashStateOmegaZ[hi * HASH_STATE_WIDTH + ci]) = _challenge(state);
                for (uint256 cj = 0; cj < HASH_RATE; cj++)
                    (state, ctx.gHashSigmaZ[hi * HASH_RATE + cj]) = _challenge(state);
            }
            for (uint256 hi = 0; hi < NUM_HASHES; hi++)
                for (uint256 j = 0; j < 7; j++)
                    (state, ctx.gSourceShifts[hi * 7 + j]) = _challenge(state);
        }
        return state;
    }

    // OOD constraint check 
    function _checkOodConstraint(
        ZKProofRange calldata proof,
        bytes calldata cVecPacked,
        VerifyCtx memory ctx
    ) internal view returns (bool) {
        uint256[] memory lagrangeW = _buildLagrangeWeights(ctx.z, ctx.omega, ctx.N);
        return _checkOodCP(proof, cVecPacked, ctx, lagrangeW) && _checkOodAurora(proof, ctx, lagrangeW);
    }

    function _checkOodCP(
        ZKProofRange calldata proof,
        bytes calldata cVecPacked,
        VerifyCtx memory ctx,
        uint256[] memory lagrangeW
    ) internal view returns (bool) {
        uint256 zN = _pow(ctx.z, ctx.N);
        uint256 zD = addmod(zN, P - 1, P);
        if (zD == 0) return false;
        uint256 zDInv = _inv(zD);

        // Accumulate CP expected value from all constraint slots
        uint256 cpExpected = _cpSlotsMatmulTernary(proof, cVecPacked, ctx, zDInv, lagrangeW);
        cpExpected = addmod(cpExpected, _cpSlotsBalanceRecompose(proof, ctx, zDInv), P);
        cpExpected = addmod(cpExpected, _cpSlotsLogUp(proof, ctx, zDInv), P);
        cpExpected = addmod(cpExpected, _cpSlotsHash(proof, ctx, zDInv), P);

        // Reassemble CP from chunks
        uint256 cpAtZ;
        {
            uint256 zPow = 1;
            uint256 zW = _pow(ctx.z, ctx.w);
            unchecked {
                for (uint256 j = 0; j < ctx.dChunks; j++) {
                    cpAtZ = addmod(cpAtZ, mulmod(zPow, _packedFieldAt(proof.oodCpChunkZ, j), P), P);
                    zPow = mulmod(zPow, zW, P);
                }
            }
        }
        return cpAtZ == cpExpected;
    }

    // Slots 0..K: one batched matmul/message constraint + K range recompositions
    function _cpSlotsMatmulTernary(
        ZKProofRange calldata proof,
        bytes calldata cVecPacked,
        VerifyCtx memory ctx,
        uint256 zDInv,
        uint256[] memory lagrangeW
    ) internal pure returns (uint256 cpExpected) {
        uint256 matmulZ = _oodMatmul(proof, cVecPacked, lagrangeW, ctx);
        matmulZ = addmod(matmulZ, mulmod(ctx.rhoMsg, ctx.oodM, P), P);
        cpExpected = mulmod(ctx.alphaPows[0], mulmod(matmulZ, zDInv, P), P);

        uint256 K = ctx.K;
        unchecked {
            for (uint256 k = 0; k < K; k++) {
                // Range recompose: (ĝ + 2^15) − (gLo + 256·gHi)
                uint256 rc = addmod(
                    addmod(_packedFieldAt(proof.oodGHatZ, k), R_SHIFT, P),
                    P - addmod(_packedFieldAt(proof.oodGloZ, k), mulmod(256, _packedFieldAt(proof.oodGhiZ, k), P), P),
                    P
                );
                cpExpected = addmod(cpExpected, mulmod(ctx.alphaPows[1 + k], mulmod(rc, zDInv, P), P), P);
            }
        }
    }

    function _absorbPackedFieldArray(bytes32 state, bytes calldata arr)
        internal pure returns (bytes32)
    {
        unchecked {
            for (uint256 i = 0; i < arr.length / 16; i++) {
                state = _absorbField(state, _packedFieldAt(arr, i));
            }
        }
        return state;
    }

    //  balance + recompose m + recompose m_sender
    function _cpSlotsBalanceRecompose(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx,
        uint256 zDInv
    ) internal pure returns (uint256 acc) {
        uint256 K = ctx.K;

        // Balance: m_original − m_sender − m
        uint256 bal = addmod(ctx.oodMOrig, P - addmod(ctx.oodMSender, ctx.oodM, P), P);
        acc = mulmod(ctx.alphaPows[K+1], mulmod(bal, zDInv, P), P);

        // Recompose m: m − Σ 2^{8j} d^(m)_j
        uint256 recompM = ctx.oodM;
        unchecked {
            uint256 pw = 1;
            for (uint256 j = 0; j < NUM_BYTES; j++) {
                recompM = addmod(recompM, P - mulmod(pw, _packedFieldAt(proof.oodDmZ, j), P), P);
                pw = pw << 8;
            }
        }
        acc = addmod(acc, mulmod(ctx.alphaPows[K+2], mulmod(recompM, zDInv, P), P), P);

        // Recompose m_sender: m_sender − Σ 2^{8j} d^(s)_j
        uint256 recompS = ctx.oodMSender;
        unchecked {
            uint256 pw = 1;
            for (uint256 j = 0; j < NUM_BYTES; j++) {
                recompS = addmod(recompS, P - mulmod(pw, _packedFieldAt(proof.oodDsZ, j), P), P);
                pw = pw << 8;
            }
        }
        acc = addmod(acc, mulmod(ctx.alphaPows[K+3], mulmod(recompS, zDInv, P), P), P);
    }

    // Slots K+4..3K+21: LogUp transition + 17+2K inverse-correctness constraints
    function _cpSlotsLogUp(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx,
        uint256 zDInv
    ) internal pure returns (uint256 acc) {
        uint256 K = ctx.K;

        // Slot K+4: accumulator transition (Σpm + Σps + Σpr)
        uint256 accT = addmod(ctx.oodZlupOmega, P - ctx.oodZlup, P);
        unchecked {
            for (uint256 j = 0; j < NUM_BYTES; j++) {
                accT = addmod(accT, P - _packedFieldAt(proof.oodPmZ, j), P);
                accT = addmod(accT, P - _packedFieldAt(proof.oodPsZ, j), P);
            }
            for (uint256 j = 0; j < 2 * K; j++) {
                accT = addmod(accT, P - _packedFieldAt(proof.oodPrZ, j), P);
            }
        }
        accT = addmod(accT, mulmod(ctx.oodMu, ctx.oodQcol, P), P);
        acc = mulmod(ctx.alphaPows[K+4], mulmod(accT, zDInv, P), P);

        // Slots K+5..K+12: p^(m)_j·(β−d^(m)_j) − 1
        unchecked {
            for (uint256 j = 0; j < NUM_BYTES; j++) {
                uint256 ic = addmod(mulmod(_packedFieldAt(proof.oodPmZ, j), addmod(ctx.betaLup, P - _packedFieldAt(proof.oodDmZ, j), P), P), P - 1, P);
                acc = addmod(acc, mulmod(ctx.alphaPows[K+5+j], mulmod(ic, zDInv, P), P), P);
            }
        }

        // Slots K+13..K+20: p^(s)_j·(β−d^(s)_j) − 1
        unchecked {
            for (uint256 j = 0; j < NUM_BYTES; j++) {
                uint256 ic = addmod(mulmod(_packedFieldAt(proof.oodPsZ, j), addmod(ctx.betaLup, P - _packedFieldAt(proof.oodDsZ, j), P), P), P - 1, P);
                acc = addmod(acc, mulmod(ctx.alphaPows[K+13+j], mulmod(ic, zDInv, P), P), P);
            }
        }

        // Slots K+21..K+20+2K: p^(r)_j·(β−r_j) − 1  (r_j = gLo[j] or gHi[j−K])
        unchecked {
            for (uint256 j = 0; j < 2 * K; j++) {
                uint256 rbv = j < K ? _packedFieldAt(proof.oodGloZ, j) : _packedFieldAt(proof.oodGhiZ, j - K);
                uint256 ic = addmod(mulmod(_packedFieldAt(proof.oodPrZ, j), addmod(ctx.betaLup, P - rbv, P), P), P - 1, P);
                acc = addmod(acc, mulmod(ctx.alphaPows[K+21+j], mulmod(ic, zDInv, P), P), P);
            }
        }

        // Slot K+21+2K: q·(β−t) − 1
        {
            uint256 icT = addmod(mulmod(ctx.oodQcol, addmod(ctx.betaLup, P - ctx.oodTZ, P), P), P - 1, P);
            acc = addmod(acc, mulmod(ctx.alphaPows[K+21+2*K], mulmod(icT, zDInv, P), P), P);
        }
    }

    // Hash constraint evaluation

    function _cpSlotsHash(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx,
        uint256 zDInv
    ) internal view returns (uint256 acc) {
        // Precompute shared scalars
        uint256 fAbsZ = _evalAbsorbSelectorAtZ(ctx.z, ctx.N);
        uint256 invZminus1 = _inv(addmod(ctx.z, P - 1, P));
        uint256 invZminusOmNm1 = _inv(addmod(ctx.z, P - ctx.omegaNm1, P));
        uint256 zMinusOmNm1 = addmod(ctx.z, P - ctx.omegaNm1, P);
        // Precompute arc1AtZ and arc2AtZ for all 12 lanes
        uint256[12] memory arc1AtZ;
        uint256[12] memory arc2AtZ;
        unchecked {
            for (uint256 ci = 0; ci < HASH_STATE_WIDTH; ci++) {
                arc1AtZ[ci] = _evalPeriodicClosedForm(ci, ctx.z, ctx.N, ctx.rescueParamsPtr);
                arc2AtZ[ci] = _evalPeriodicClosedFormB2(ci, ctx.z, ctx.N, ctx.rescueParamsPtr);
            }
        }
        // Source OOD at z: source[0]=m, source[1]=m_sender, source[2]=m_orig
        uint256[3] memory sourceOodZ;
        sourceOodZ[0] = proof.oodMZ % P;
        sourceOodZ[1] = proof.oodMSenderZ % P;
        sourceOodZ[2] = proof.oodMOrigZ % P;

        acc = 0;
        unchecked {
            for (uint256 hi = 0; hi < NUM_HASHES; hi++) {
                acc = addmod(acc, _cpSlotsHashC1a(proof, ctx, zDInv, fAbsZ, sourceOodZ[hi], hi), P);
                acc = addmod(acc, _cpSlotsHashC1b(proof, ctx, zDInv, arc1AtZ, arc2AtZ, zMinusOmNm1, hi), P);
                acc = addmod(acc, _cpSlotsHashC2(proof, ctx, invZminus1, hi), P);
                acc = addmod(acc, _cpSlotsHashC3(proof, ctx, invZminusOmNm1, hi), P);
            }
        }
    }

    /// @dev C1a: σ_j(z) − s_j(z) − fAbsZ·src(ω^j z) = 0 for j=0..RATE-1
    function _cpSlotsHashC1a(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx,
        uint256 zDInv,
        uint256 fAbsZ,
        uint256 srcOodZ,
        uint256 hi
    ) internal pure returns (uint256 acc) {
        uint256 K = ctx.K;
        acc = 0;
        unchecked {
            for (uint256 j = 0; j < HASH_RATE; j++) {
                uint256 sj = _packedFieldAt(proof.oodHashStateZ, hi * HASH_STATE_WIDTH + j);
                uint256 sigj = _packedFieldAt(proof.oodHashSigmaZ, hi * HASH_RATE + j);
                uint256 srcAtOmJz;
                if (j == 0) {
                    srcAtOmJz = srcOodZ;
                } else {
                    srcAtOmJz = _packedFieldAt(proof.oodSourceShifts, hi * 7 + (j - 1));
                }
                // c1a = σ_j − (s_j + fAbsZ · src)
                uint256 c1a = addmod(sigj, P - addmod(sj, mulmod(fAbsZ, srcAtOmJz, P), P), P);
                acc = addmod(acc, mulmod(ctx.alphaPows[3*K+22 + hi*HASH_RATE + j],
                    mulmod(c1a, zDInv, P), P), P);
            }
        }
    }

    /// @dev C1b: (M^{-1}(s(ωz)-arc2))^3 − (M·σ̂^3 + arc1) = 0
    ///      Divisor includes extra (z-ω^{N-1}) factor
    ///      Reads MDS/MDSINV from the bytecode table copied into memory.
    function _cpSlotsHashC1b(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx,
        uint256 zDInv,
        uint256[12] memory arc1AtZ,
        uint256[12] memory arc2AtZ,
        uint256 zMinusOmNm1,
        uint256 hi
    ) internal pure returns (uint256 acc) {
        uint256 K = ctx.K;
        uint256 rescueParamsPtr = ctx.rescueParamsPtr;
        acc = 0;
        unchecked {
            // smA2 = s_next - arc2
            uint256[12] memory smA2;
            for (uint256 ci = 0; ci < HASH_STATE_WIDTH; ci++) {
                uint256 sNextI = _packedFieldAt(proof.oodHashStateOmegaZ, hi * HASH_STATE_WIDTH + ci);
                smA2[ci] = addmod(sNextI, P - arc2AtZ[ci], P);
            }
            // mInvZ = MINV · smA2
            uint256[12] memory mInvZ;
            for (uint256 ci = 0; ci < HASH_STATE_WIDTH; ci++) {
                uint256 dot = 0;
                for (uint256 cj = 0; cj < HASH_STATE_WIDTH; cj++) {
                    uint256 mInvVal;
                    assembly ("memory-safe") {
                        mInvVal := mload(add(rescueParamsPtr, mul(add(144, add(mul(ci, 12), cj)), 32)))
                    }
                    dot = addmod(dot, mulmod(mInvVal, smA2[cj], P), P);
                }
                mInvZ[ci] = dot;
            }
            // lhsC = mInvZ^3
            uint256[12] memory lhsC;
            for (uint256 ci = 0; ci < HASH_STATE_WIDTH; ci++)
                lhsC[ci] = mulmod(mulmod(mInvZ[ci], mInvZ[ci], P), mInvZ[ci], P);

            // σ̂ = [σ_0..σ_{R-1}, s_R..s_{W-1}]
            uint256[12] memory sigHat;
            for (uint256 cj = 0; cj < HASH_RATE; cj++)
                sigHat[cj] = _packedFieldAt(proof.oodHashSigmaZ, hi * HASH_RATE + cj);
            for (uint256 cj = HASH_RATE; cj < HASH_STATE_WIDTH; cj++)
                sigHat[cj] = _packedFieldAt(proof.oodHashStateZ, hi * HASH_STATE_WIDTH + cj);
            // scZ = sigHat^3
            uint256[12] memory scZ;
            for (uint256 cj = 0; cj < HASH_STATE_WIDTH; cj++)
                scZ[cj] = mulmod(mulmod(sigHat[cj], sigHat[cj], P), sigHat[cj], P);
            // mAppZ = MDS · scZ
            uint256[12] memory mAppZ;
            for (uint256 ci = 0; ci < HASH_STATE_WIDTH; ci++) {
                uint256 dot = 0;
                for (uint256 cj = 0; cj < HASH_STATE_WIDTH; cj++) {
                    uint256 mdsVal;
                    assembly ("memory-safe") {
                        mdsVal := mload(add(rescueParamsPtr, mul(add(mul(ci, 12), cj), 32)))
                    }
                    dot = addmod(dot, mulmod(mdsVal, scZ[cj], P), P);
                }
                mAppZ[ci] = dot;
            }
            // rhsC = mAppZ + arc1; c1bNum = lhsC - rhsC
            // slot += α · c1bNum · (z-ω^{N-1}) · zDInv
            for (uint256 ci = 0; ci < HASH_STATE_WIDTH; ci++) {
                uint256 rhsI = addmod(mAppZ[ci], arc1AtZ[ci], P);
                uint256 c1bNum = addmod(lhsC[ci], P - rhsI, P);
                uint256 scaled = mulmod(mulmod(c1bNum, zMinusOmNm1, P), zDInv, P);
                acc = addmod(acc, mulmod(ctx.alphaPows[3*K+46 + hi*HASH_STATE_WIDTH + ci],
                    scaled, P), P);
            }
        }
    }

    /// @dev C2: boundary s(1) = 0 → s_i(z) / (z-1)
    function _cpSlotsHashC2(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx,
        uint256 invZminus1,
        uint256 hi
    ) internal pure returns (uint256 acc) {
        uint256 K = ctx.K;
        acc = 0;
        unchecked {
            for (uint256 ci = 0; ci < HASH_STATE_WIDTH; ci++) {
                uint256 si = _packedFieldAt(proof.oodHashStateZ, hi * HASH_STATE_WIDTH + ci);
                acc = addmod(acc, mulmod(ctx.alphaPows[3*K+82 + hi*HASH_STATE_WIDTH + ci],
                    mulmod(si, invZminus1, P), P), P);
            }
        }
    }

    /// @dev C3: output s(ω^{N-1}) = token → (s_lane(z) - token) / (z - ω^{N-1})
    function _cpSlotsHashC3(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx,
        uint256 invZminusOmNm1,
        uint256 hi
    ) internal pure returns (uint256 acc) {
        uint256 K = ctx.K;
        // tokens[0]=tokenM, tokens[1]=tokenS, tokens[2]=tokenO
        uint256[2] memory tok;
        if (hi == 0) tok = proof.tokenM;
        else if (hi == 1) tok = proof.tokenS;
        else tok = proof.tokenO;
        acc = 0;
        unchecked {
            for (uint256 lane = 0; lane < HASH_OUTPUT_LANES; lane++) {
                uint256 si = _packedFieldAt(proof.oodHashStateZ, hi * HASH_STATE_WIDTH + lane);
                uint256 c3n = addmod(si, P - (tok[lane] % P), P);
                acc = addmod(acc, mulmod(ctx.alphaPows[3*K+118 + hi*HASH_OUTPUT_LANES + lane],
                    mulmod(c3n, invZminusOmNm1, P), P), P);
            }
        }
    }

    /// @dev Absorb selector: (z^N - 1) / (8·(z^{N/8} - 1))
    function _evalAbsorbSelectorAtZ(uint256 z, uint256 N) internal pure returns (uint256) {
        uint256 zN = _pow(z, N);
        uint256 zN8 = _pow(z, N / 8);
        uint256 numer = addmod(zN, P - 1, P);
        uint256 denom = mulmod(8, addmod(zN8, P - 1, P), P);
        return mulmod(numer, _inv(denom), P);
    }

    /// @dev Evaluate periodic arc1[lane] at z: (1/8) Σ_{j=0}^{7} z^{jN/8} · B1[lane][j]
    ///      Reads B1 constants from the bytecode table copied into memory.
    function _evalPeriodicClosedForm(
        uint256 lane, uint256 z, uint256 N, uint256 rescueParamsPtr
    ) internal pure returns (uint256 result) {
        uint256 zStep = _pow(z, N / 8);
        result = 0;
        uint256 zPow = 1;
        unchecked {
            for (uint256 j = 0; j < 8; j++) {
                uint256 b1Val;
                assembly ("memory-safe") {
                    b1Val := mload(add(rescueParamsPtr, mul(add(288, add(mul(lane, 8), j)), 32)))
                }
                result = addmod(result, mulmod(zPow, b1Val, P), P);
                zPow = mulmod(zPow, zStep, P);
            }
        }
        result = mulmod(result, INV8, P);
    }

    /// @dev Same for arc2 using B2 constants.
    function _evalPeriodicClosedFormB2(
        uint256 lane, uint256 z, uint256 N, uint256 rescueParamsPtr
    ) internal pure returns (uint256 result) {
        uint256 zStep = _pow(z, N / 8);
        result = 0;
        uint256 zPow = 1;
        unchecked {
            for (uint256 j = 0; j < 8; j++) {
                uint256 b2Val;
                assembly ("memory-safe") {
                    b2Val := mload(add(rescueParamsPtr, mul(add(384, add(mul(lane, 8), j)), 32)))
                }
                result = addmod(result, mulmod(zPow, b2Val, P), P);
                zPow = mulmod(zPow, zStep, P);
            }
        }
        result = mulmod(result, INV8, P);
    }

    function _checkOodAurora(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx,
        uint256[] memory lagrangeW
    ) internal pure returns (bool) {
        uint256 zN = _pow(ctx.z, ctx.N);
        uint256 zD = addmod(zN, P - 1, P);

        // Compute Λ'_α(z) and σ_α(z) in a sub-call to avoid stack depth
        (uint256 lambdaAtZ, uint256 sigmaAtZ) = _auroraScalars(ctx, zN, lagrangeW);

        // Batch across witness columns
        uint256 gBatch;
        uint256 fBatch;
        unchecked {
            for (uint256 k = 0; k < ctx.K; k++) {
                gBatch = addmod(gBatch, mulmod(ctx.lamK[k], _packedFieldAt(proof.oodGHatZ, k), P), P);
                fBatch = addmod(fBatch, mulmod(ctx.lamK[k], _packedFieldAt(proof.oodBNttZ, k), P), P);
            }
        }
        uint256 inner = addmod(
            mulmod(gBatch, sigmaAtZ, P),
            P - mulmod(fBatch, lambdaAtZ, P),
            P
        );
        uint256 lhs = addmod(mulmod(ctx.rhoAurora, inner, P), ctx.oodRAur, P);
        uint256 qAtZ = addmod(ctx.oodQ, mulmod(zN, ctx.oodQ1, P), P);
        uint256 rhs = addmod(ctx.betaAur, addmod(mulmod(ctx.z, ctx.oodR, P), mulmod(qAtZ, zD, P), P), P);
        return lhs == rhs;
    }

    function _auroraScalars(VerifyCtx memory ctx, uint256 zN, uint256[] memory lagrangeW)
        internal pure returns (uint256 lambdaAtZ, uint256 sigmaAtZ)
    {
        // Λ'_α(z) = [α(1−z^N) − ψz(1+α^N)] / [N·(α−ψz)]
        uint256 alphaN = _pow(ctx.alpha, ctx.N);
        uint256 alphaNplus1 = addmod(alphaN, 1, P);
        uint256 num = addmod(
            mulmod(ctx.alpha, addmod(1, P - zN, P), P),
            P - mulmod(mulmod(ctx.psi, ctx.z, P), alphaNplus1, P),
            P
        );
        uint256 den = mulmod(ctx.N, addmod(ctx.alpha, P - mulmod(ctx.psi, ctx.z, P), P), P);
        lambdaAtZ = mulmod(num, _inv(den), P);

        // σ_α(z) via Lagrange — reuse precomputed weights
        sigmaAtZ = _evalSigmaAlpha(ctx.alpha, ctx.N, lagrangeW);
    }

    // Matmul: Σ_m ρ_m·(Σ_k A_{m,k}(z)·b̃Ntt_k(z) − c_m(z))
    function _oodMatmul(
        ZKProofRange calldata proof,
        bytes calldata cVecPacked,
        uint256[] memory lagrangeW,
        VerifyCtx memory ctx
    ) internal pure returns (uint256 acc) {
        uint256 M = ctx.M;
        uint256 K = ctx.K;
        uint256 N = ctx.N;
        unchecked {
            for (uint256 m = 0; m < M; m++) {
                uint256 inner = 0;
                uint256 base = m * K;
                for (uint256 k = 0; k < K; k++) {
                    inner = addmod(inner, mulmod(_packedFieldAt(proof.oodAZ, base + k), _packedFieldAt(proof.oodBNttZ, k), P), P);
                }
                uint256 cAtZ = _evalCLagrange(cVecPacked, m * N, N, lagrangeW);
                acc = addmod(acc, mulmod(ctx.rhos[m], addmod(inner, P - cAtZ, P), P), P);
            }
        }
    }

    // Lagrange weights for H = {ω^i}, vanishing X^N−1

    function _buildLagrangeWeights(uint256 z, uint256 omega, uint256 N)
        internal pure returns (uint256[] memory weights)
    {
        weights = new uint256[](N);
        uint256[] memory denoms = new uint256[](N);
        uint256[] memory hVals  = new uint256[](N);
        unchecked {
            uint256 hi = 1;
            for (uint256 i = 0; i < N; i++) {
                hVals[i] = hi;
                denoms[i] = addmod(z, P - hi, P);
                hi = mulmod(hi, omega, P);
            }
        }
        uint256[] memory denomInvs = _batchInv(denoms);
        uint256 zN = _pow(z, N);
        uint256 zNm1OverN = mulmod(addmod(zN, P - 1, P), _inv(N), P);
        unchecked {
            for (uint256 i = 0; i < N; i++) {
                weights[i] = mulmod(mulmod(zNm1OverN, denomInvs[i], P), hVals[i], P);
            }
        }
    }

    function _evalCLagrange(bytes calldata pack, uint256 elemOff, uint256 d, uint256[] memory weights)
        internal pure returns (uint256 result)
    {
        assembly ("memory-safe") {
            let p := 340282366920938463463374607393113505793
            result := 0
            let base := add(pack.offset, mul(elemOff, 16))
            let wBase := add(weights, 32)
            for { let i := 0 } lt(i, d) { i := add(i, 1) } {
                let coeff := shr(128, calldataload(add(base, mul(i, 16))))
                let w := mload(add(wBase, mul(i, 32)))
                result := addmod(result, mulmod(coeff, w, p), p)
            }
        }
    }

    function _evalSigmaAlpha(uint256 alpha, uint256 N, uint256[] memory weights)
        internal pure returns (uint256 result)
    {
        uint256 alphaI = 1;
        unchecked {
            for (uint256 i = 0; i < N; i++) {
                result = addmod(result, mulmod(alphaI, weights[i], P), P);
                alphaI = mulmod(alphaI, alpha, P);
            }
        }
    }

    // Merkle verification (all trees)

    function _verifyAllMerkle(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx
    ) internal pure returns (bool) {
        uint256 capH = _capHeightForLayer(uint256(proof.capHeight), ctx.ldeSize);
        uint256 capSize = uint256(1) << capH;
        uint256 m = proof.tracePositions.length;
        if (m == 0) return false;

        // Trace (4K+81 cols, salted)
        if (proof.traceCap.length != capSize) return false;
        if (proof.traceColValues.length != m) return false;
        if (proof.traceSalts.length != m) return false;
        {
            uint256 W = ctx.traceCols;
            bytes32[] memory leaves = new bytes32[](m);
            unchecked {
                for (uint256 i = 0; i < m; i++) {
                    if (proof.traceColValues[i].length != W * 16) return false;
                    leaves[i] = _hashBundledLeafPackedSalt(proof.traceColValues[i], W, proof.traceSalts[i]);
                }
            }
            if (!_verifyBatch(proof.traceCap, capSize, ctx.ldeSize, proof.tracePositions, leaves, proof.traceBatchProof))
                return false;
        }

        // Interaction (18+2K cols, salted)
        if (proof.interCap.length != capSize) return false;
        if (proof.interColValues.length != m) return false;
        if (proof.interSalts.length != m) return false;
        {
            bytes32[] memory leaves = new bytes32[](m);
            uint256 icc = 18 + 2 * ctx.K;
            unchecked {
                for (uint256 i = 0; i < m; i++) {
                    if (proof.interColValues[i].length != icc * 16) return false;
                    leaves[i] = _hashBundledLeafPackedSalt(proof.interColValues[i], icc, proof.interSalts[i]);
                }
            }
            if (!_verifyBatch(proof.interCap, capSize, ctx.ldeSize, proof.tracePositions, leaves, proof.interBatchProof))
                return false;
        }

        // Aux (R, Q0, Q1; salted)
        if (proof.auxCap.length != capSize) return false;
        if (proof.auxColValues.length != m) return false;
        if (proof.auxSalts.length != m) return false;
        {
            bytes32[] memory leaves = new bytes32[](m);
            unchecked {
                for (uint256 i = 0; i < m; i++) {
                    if (proof.auxColValues[i].length != 3 * 16) return false;
                    leaves[i] = _hashBundledLeafPackedSalt(proof.auxColValues[i], 3, proof.auxSalts[i]);
                }
            }
            if (!_verifyBatch(proof.auxCap, capSize, ctx.ldeSize, proof.tracePositions, leaves, proof.auxBatchProof))
                return false;
        }

        // CP chunks (numChunks cols, salted)
        if (proof.cpChunkCap.length != capSize) return false;
        if (proof.cpChunkColValues.length != m) return false;
        if (proof.cpChunkSalts.length != m) return false;
        {
            uint256 W = ctx.dChunks;
            bytes32[] memory leaves = new bytes32[](m);
            unchecked {
                for (uint256 i = 0; i < m; i++) {
                    if (proof.cpChunkColValues[i].length != W * 16) return false;
                    leaves[i] = _hashBundledLeafPackedSalt(proof.cpChunkColValues[i], W, proof.cpChunkSalts[i]);
                }
            }
            if (!_verifyBatch(proof.cpChunkCap, capSize, ctx.ldeSize, proof.tracePositions, leaves, proof.cpChunkBatchProof))
                return false;
        }

        // Mask (single value, salted)
        if (!_verifyMerkleSingleValueSalted(
            proof.maskCap, proof.tracePositions, proof.maskValues, proof.maskSalts,
            proof.maskBatchProof, uint256(proof.capHeight), ctx.ldeSize
        )) return false;

        // Split (2 cols, salted)
        if (proof.splitCap.length != capSize) return false;
        if (proof.splitColValues.length != m) return false;
        if (proof.splitSalts.length != m) return false;
        {
            bytes32[] memory leaves = new bytes32[](m);
            unchecked {
                for (uint256 i = 0; i < m; i++) {
                    if (proof.splitColValues[i].length != 2 * 16) return false;
                    leaves[i] = _hashBundledLeafPackedSalt(proof.splitColValues[i], 2, proof.splitSalts[i]);
                }
            }
            if (!_verifyBatch(proof.splitCap, capSize, ctx.ldeSize, proof.tracePositions, leaves, proof.splitBatchProof))
                return false;
        }

        // A oracle (M*K+1 packed, unsalted)
        if (proof.aCap.length != capSize) return false;
        if (proof.aColValues.length != m) return false;
        {
            uint256 MKplus1 = ctx.MK + 1;
            bytes32[] memory leaves = new bytes32[](m);
            unchecked {
                for (uint256 i = 0; i < m; i++) {
                    if (proof.aColValues[i].length != MKplus1 * 16) return false;
                    leaves[i] = _hashBundledLeafPacked(proof.aColValues[i], MKplus1);
                }
            }
            if (!_verifyBatch(proof.aCap, capSize, ctx.ldeSize, proof.tracePositions, leaves, proof.aBatchProof))
                return false;
        }

        // FRI layers
        if (proof.friLayerSalts.length != ctx.numFriLayers) return false;
        unchecked {
            for (uint256 r = 0; r < ctx.numFriLayers; r++) {
                uint256 nR = ctx.ldeSize >> (2 * r);
                if (!_verifyMerkleSingleValueSalted(
                    proof.friCaps[r], proof.friLayerPositions[r], proof.friLayerValues[r],
                    proof.friLayerSalts[r], proof.friLayerProofs[r],
                    uint256(proof.capHeight), nR
                )) return false;
            }
        }

        return true;
    }

    // Leaf hashing helpers

    function _hashBundledLeafPacked(bytes calldata vals, uint256 n)
        internal pure returns (bytes32 h)
    {
        assembly ("memory-safe") {
            let scratch := mload(0x40)
            mstore8(scratch, 0x00)
            let ptr := add(scratch, 1)
            let p := 340282366920938463463374607393113505793
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let v := shr(128, calldataload(add(vals.offset, mul(i, 16))))
                v := mod(v, p)
                mstore(ptr, v)
                ptr := add(ptr, 32)
            }
            h := keccak256(scratch, add(1, mul(n, 32)))
        }
    }

    function _hashBundledLeafPackedSalt(bytes calldata vals, uint256 n, bytes16 salt)
        internal pure returns (bytes32 h)
    {
        assembly ("memory-safe") {
            let scratch := mload(0x40)
            mstore8(scratch, 0x00)
            let ptr := add(scratch, 1)
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                mstore(ptr, shr(128, calldataload(add(vals.offset, mul(i, 16)))))
                ptr := add(ptr, 32)
            }
            mstore(ptr, salt)
            h := keccak256(scratch, add(add(1, mul(n, 32)), 16))
        }
    }

    function _packedFieldAt(bytes calldata values, uint256 index)
        internal pure returns (uint256 value)
    {
        assembly ("memory-safe") {
            value := shr(128, calldataload(add(values.offset, mul(index, 16))))
        }
    }

    function _verifyMerkleSingleValueSalted(
        bytes32[] calldata cap,
        uint32[] calldata positions,
        bytes calldata values,
        bytes16[] calldata salts,
        bytes32[] calldata batchProof,
        uint256 capHeightCfg,
        uint256 layerSize
    ) internal pure returns (bool) {
        uint256 capH = _capHeightForLayer(capHeightCfg, layerSize);
        if (cap.length != (uint256(1) << capH)) return false;
        if (values.length != positions.length * 16) return false;
        if (salts.length != positions.length) return false;
        uint256 m = positions.length;
        if (m == 0) return false;
        bytes32[] memory leafHashes = new bytes32[](m);
        unchecked {
            for (uint256 i = 0; i < m; i++) {
                bytes32 h;
                uint256 v = _packedFieldAt(values, i);
                bytes16 salt = salts[i];
                assembly ("memory-safe") {
                    let ptr := mload(0x40)
                    mstore8(ptr, 0)
                    mstore(add(ptr, 1), v)
                    mstore(add(ptr, 33), salt)
                    h := keccak256(ptr, 49)
                }
                leafHashes[i] = h;
            }
        }
        return _verifyBatch(cap, uint256(1) << capH, layerSize, positions, leafHashes, batchProof);
    }

    // Batched Merkle verification

    function _verifyBatch(
        bytes32[] calldata cap,
        uint256 capSize,
        uint256 n,
        uint32[] calldata positions,
        bytes32[] memory leafHashes,
        bytes32[] calldata proofPath
    ) internal pure returns (bool) {
        uint256 m = positions.length;
        if (m == 0 || m != leafHashes.length) return false;
        if (n == 0 || (n & (n - 1)) != 0) return false;
        if (capSize == 0 || (capSize & (capSize - 1)) != 0) return false;
        if (capSize > n) return false;

        uint256 depth = _log2(n);
        uint256 capHeightHere = _log2(capSize);

        uint256[] memory keys = new uint256[](m);
        bytes32[] memory hashes = new bytes32[](m);
        keys[0] = uint256(positions[0]);
        if (keys[0] >= n) return false;
        hashes[0] = leafHashes[0];
        unchecked {
            for (uint256 i = 1; i < m; i++) {
                uint256 v = uint256(positions[i]);
                if (v >= n || v <= keys[i - 1]) return false;
                keys[i] = v;
                hashes[i] = leafHashes[i];
            }
        }

        uint256 proofIdx = 0;
        uint256 levels = depth - capHeightHere;
        unchecked {
            for (uint256 level = 0; level < levels; level++) {
                uint256 outLen = 0;
                uint256 idx2 = 0;
                while (idx2 < m) {
                    uint256 ki = keys[idx2];
                    bytes32 hi = hashes[idx2];
                    bytes32 hSib;
                    bool sibInKeys = ((ki & 1) == 0) && (idx2 + 1 < m) && (keys[idx2 + 1] == ki + 1);
                    if (sibInKeys) {
                        hSib = hashes[idx2 + 1];
                        idx2 += 2;
                    } else {
                        if (proofIdx >= proofPath.length) return false;
                        hSib = proofPath[proofIdx++];
                        idx2 += 1;
                    }
                    bytes32 parent;
                    // Assembly: keccak256([0x01 | left(32) | right(32)]) = 65 bytes
                    assembly ("memory-safe") {
                        let ptr := mload(0x40)
                        mstore8(ptr, 0x01)
                        switch and(ki, 1)
                        case 0 {
                            mstore(add(ptr, 1), hi)
                            mstore(add(ptr, 33), hSib)
                        }
                        default {
                            mstore(add(ptr, 1), hSib)
                            mstore(add(ptr, 33), hi)
                        }
                        parent := keccak256(ptr, 65)
                    }
                    keys[outLen] = ki >> 1;
                    hashes[outLen] = parent;
                    outLen++;
                }
                m = outLen;
            }
        }
        if (proofIdx != proofPath.length) return false;
        for (uint256 i = 0; i < m; i++) {
            if (keys[i] >= capSize || cap[keys[i]] != hashes[i]) return false;
        }
        return true;
    }

    // Batch inversion (Montgomery)

    function _batchInv(uint256[] memory vals) internal pure returns (uint256[] memory result) {
        uint256 n = vals.length;
        result = new uint256[](n);
        if (n == 0) return result;
        uint256[] memory prefix = new uint256[](n);
        assembly ("memory-safe") {
            let p := 340282366920938463463374607393113505793
            let vBase := add(vals, 32)
            let pBase := add(prefix, 32)
            let prev := mload(vBase)
            mstore(pBase, prev)
            for { let i := 1 } lt(i, n) { i := add(i, 1) } {
                let vi := mload(add(vBase, shl(5, i)))
                switch iszero(vi)
                case 1 { mstore(add(pBase, shl(5, i)), prev) }
                default {
                    prev := mulmod(prev, vi, p)
                    mstore(add(pBase, shl(5, i)), prev)
                }
            }
        }
        uint256 inv = _inv(prefix[n - 1]);
        assembly ("memory-safe") {
            let p := 340282366920938463463374607393113505793
            let vBase := add(vals, 32)
            let pBase := add(prefix, 32)
            let rBase := add(result, 32)
            for { let i := sub(n, 1) } iszero(gt(0, i)) { } {
                let vi := mload(add(vBase, shl(5, i)))
                switch iszero(vi)
                case 1 { mstore(add(rBase, shl(5, i)), 0) }
                default {
                    switch iszero(i)
                    case 1 { mstore(add(rBase, shl(5, i)), inv) }
                    default {
                        mstore(add(rBase, shl(5, i)), mulmod(inv, mload(add(pBase, shl(5, sub(i, 1)))), p))
                    }
                    inv := mulmod(inv, vi, p)
                }
                if iszero(i) { break }
                i := sub(i, 1)
            }
        }
    }

    // Per-query verification (DEEP reconstruction + split + FRI)

    function _verifyQueries(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx
    ) internal pure returns (bool) {
        ctx.quarter0 = ctx.ldeSize / FRI_ARITY;
        ctx.inv4 = _inv(FRI_ARITY);
        ctx.mu = _pow(ctx.ldeOmega, ctx.quarter0); // primitive 4th root
        uint256 nQueries = proof.queryIndices.length;
        uint256 nFri = ctx.numFriLayers;

        // Precompute ω^j·z for j=1..7 (used in source-shift denominators)
        uint256[7] memory omJz;
        unchecked {
            uint256 omPow = ctx.omega;
            for (uint256 j = 0; j < 7; j++) {
                omJz[j] = mulmod(omPow, ctx.z, P);
                omPow = mulmod(omPow, ctx.omega, P);
            }
        }

        // Batch-invert all denominators:
        //   per query: inv(ℓ−z), inv(ℓ−ωz), 7 source shifts inv(ℓ−ω^j·z), per FRI layer: inv(ℓ_r)
        uint256 stride = 9 + nFri; // 2 + 7 source shifts + nFri
        uint256[] memory toInvert = new uint256[](nQueries * stride);
        ctx.queryPoints = new uint256[](nQueries);

        unchecked {
            for (uint256 qi = 0; qi < nQueries; qi++) {
                uint256 q = uint256(proof.queryIndices[qi]);
                uint256 i0 = q % ctx.quarter0;
                uint256 x = mulmod(ctx.cosetGen, _pow(ctx.ldeOmega, i0), P);
            ctx.queryPoints[qi] = x;
                toInvert[qi * stride]     = addmod(x, P - ctx.z, P);      // ℓ − z
                toInvert[qi * stride + 1] = addmod(x, P - ctx.omegaZ, P); // ℓ − ωz
                // Source shift denominators: ℓ − ω^j·z for j=1..7
                for (uint256 j = 0; j < 7; j++) {
                    toInvert[qi * stride + 2 + j] = addmod(x, P - omJz[j], P);
                }
                uint256 base = qi * stride + 9;
                uint256 quarterR = ctx.quarter0;
                uint256 layerPoint = x;
                for (uint256 r = 0; r < nFri; r++) {
                    uint256 iR = q % quarterR;
                    toInvert[base + r] = layerPoint;
                    if (r + 1 < nFri) {
                        uint256 nextQuarter = quarterR >> 2;
                        layerPoint = _friNextPoint(layerPoint, iR / nextQuarter, ctx.mu);
                    }
                    quarterR >>= 2;
                }
            }
        }

        ctx.friInverses = _batchInv(toInvert);
        ctx.friInvStride = stride;

        unchecked {
            for (uint256 qi = 0; qi < nQueries; qi++) {
                if (!_verifyOneQuery(proof, ctx, qi)) return false;
            }
        }
        return true;
    }

    function _verifyOneQuery(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx,
        uint256 qi
    ) internal pure returns (bool) {
        uint256 q = uint256(proof.queryIndices[qi]);
        uint256 i0 = q % ctx.quarter0;
        uint256 invOff = qi * ctx.friInvStride;
        uint256 x = ctx.queryPoints[qi];

        (bool ok, uint256 idx) = _binarySearch(proof.tracePositions, i0);
        if (!ok) return false;

        // (1) Reconstruct masked DEEP h(ℓ) from all column openings
        uint256 hVal = _combineDeep(proof, ctx, idx, invOff);

        // (2) Split consistency: h(ℓ) = g0(ℓ) + ℓ^N·g1(ℓ)
        {
            uint256 xN = _pow(x, ctx.N);
            bytes calldata sv = proof.splitColValues[idx];
            if (sv.length != 2 * 16) return false;
            uint256 g0v = _packedFieldAt(sv, 0);
            uint256 g1v = _packedFieldAt(sv, 1);
            uint256 splitRhs = addmod(g0v, mulmod(xN, g1v, P), P);
            if (hVal != splitRhs) return false;

            // (3) Batch all independently degree-bounded polynomials into FRI layer 0.
            bytes calldata auxV = proof.auxColValues[idx];
            uint256 hBatch = mulmod(_pow(x, ctx.N - ctx.b + 1), _packedFieldAt(auxV, 2), P);
            hBatch = addmod(_packedFieldAt(auxV, 1), mulmod(ctx.lambda, hBatch, P), P);
            hBatch = addmod(mulmod(x, _packedFieldAt(auxV, 0), P), mulmod(ctx.lambda, hBatch, P), P);
            hBatch = addmod(g1v, mulmod(ctx.lambda, hBatch, P), P);
            hBatch = addmod(g0v, mulmod(ctx.lambda, hBatch, P), P);
            (bool okFri, uint256 friL0) = _lookupFri(proof, 0, i0);
            if (!okFri) return false;
            if (hBatch != friL0) return false;
        }

        // (4) FRI fold chain
        return _verifyFriFolds(proof, ctx, q, x, invOff + 9);
    }

    // DEEP combination h(ℓ) — all columns including balance/range/LogUp

    function _combineDeep(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx,
        uint256 traceIdx,
        uint256 invOff
    ) internal pure returns (uint256) {
        uint256 invXZ = ctx.friInverses[invOff];       // inv(ℓ−z)
        uint256 invXOmegaZ = ctx.friInverses[invOff + 1]; // inv(ℓ−ωz)

        // All terms divided by (ℓ−z)
        uint256 numAtZ = _deepTraceColumns(proof, ctx, traceIdx);
        numAtZ = addmod(numAtZ, _deepInterColumnsAtZ(proof, ctx, traceIdx), P);
        numAtZ = addmod(numAtZ, _deepAuxAndCp(proof, ctx, traceIdx), P);
        numAtZ = addmod(numAtZ, _deepAOracle(proof, ctx, traceIdx), P);

        uint256 deep = mulmod(numAtZ, invXZ, P);

        // Z_lup at ωz — uses inv(ℓ−ωz) separately
        {
            bytes calldata iv = proof.interColValues[traceIdx];
            uint256 zv = _packedFieldAt(iv, 17 + 2 * ctx.K);
            uint256 numOmega = mulmod(ctx.gZlupOmega, addmod(zv, P - ctx.oodZlupOmega, P), P);
            deep = addmod(deep, mulmod(numOmega, invXOmegaZ, P), P);
        }

        // Hash state columns at ωz + source shifts
        deep = addmod(deep, _deepHashOmegaAndShifts(proof, ctx, traceIdx, invXOmegaZ, invOff), P);

        // + mask
        uint256 maskV = _packedFieldAt(proof.maskValues, traceIdx);
        return addmod(deep, maskV, P);
    }

    /// @dev Hash state@ωz quotients and source shift quotients
    function _deepHashOmegaAndShifts(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx,
        uint256 traceIdx,
        uint256 invXOmegaZ,
        uint256 invOff
    ) internal pure returns (uint256 deep) {
        bytes calldata tv = proof.traceColValues[traceIdx];
        uint256 K = ctx.K;
        bytes calldata oodHashStateOmegaZ = proof.oodHashStateOmegaZ;
        bytes calldata oodSourceShifts = proof.oodSourceShifts;
        uint256[] memory gHashStateOmegaZ = ctx.gHashStateOmegaZ;
        uint256[] memory gSourceShifts = ctx.gSourceShifts;
        uint256[] memory friInverses = ctx.friInverses;
        assembly ("memory-safe") {
            let p := 340282366920938463463374607393113505793
            let hashNumerator := 0
            let hashGammas := add(gHashStateOmegaZ, 32)

            for { let hi := 0 } lt(hi, 3) { hi := add(hi, 1) } {
                let traceBase := add(add(mul(4, K), 21), mul(hi, 20))
                let stateBase := mul(hi, 12)
                for { let ci := 0 } lt(ci, 12) { ci := add(ci, 1) } {
                    let stateIndex := add(stateBase, ci)
                    let value := shr(128, calldataload(add(tv.offset, shl(4, add(traceBase, ci)))))
                    let ood := shr(128, calldataload(add(oodHashStateOmegaZ.offset, shl(4, stateIndex))))
                    hashNumerator := addmod(
                        hashNumerator,
                        mulmod(mload(add(hashGammas, shl(5, stateIndex))), addmod(value, sub(p, ood), p), p),
                        p
                    )
                }
            }
            deep := mulmod(hashNumerator, invXOmegaZ, p)

            let sourceGammas := add(gSourceShifts, 32)
            let inverseBase := add(add(friInverses, 32), shl(5, add(invOff, 2)))
            for { let hi := 0 } lt(hi, 3) { hi := add(hi, 1) } {
                let sourceIndex := mul(4, K)
                switch hi
                case 1 { sourceIndex := add(sourceIndex, 2) }
                case 2 { sourceIndex := add(sourceIndex, 1) }
                let sourceValue := shr(128, calldataload(add(tv.offset, shl(4, sourceIndex))))
                let shiftBase := mul(hi, 7)
                for { let j := 0 } lt(j, 7) { j := add(j, 1) } {
                    let shiftIndex := add(shiftBase, j)
                    let ood := shr(128, calldataload(add(oodSourceShifts.offset, shl(4, shiftIndex))))
                    let numerator := mulmod(
                        mload(add(sourceGammas, shl(5, shiftIndex))),
                        addmod(sourceValue, sub(p, ood), p),
                        p
                    )
                    deep := addmod(deep, mulmod(numerator, mload(add(inverseBase, shl(5, j))), p), p)
                }
            }
        }
    }

    // DEEP quotients for trace tree columns (at z only)
    function _deepTraceColumns(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx,
        uint256 traceIdx
    ) internal pure returns (uint256 acc) {
        bytes calldata tv = proof.traceColValues[traceIdx];
        uint256 K = ctx.K;
        bytes calldata oodBNttZ = proof.oodBNttZ;
        bytes calldata oodGHatZ = proof.oodGHatZ;
        bytes calldata oodGloZ = proof.oodGloZ;
        bytes calldata oodGhiZ = proof.oodGhiZ;
        bytes calldata oodDmZ = proof.oodDmZ;
        bytes calldata oodDsZ = proof.oodDsZ;
        bytes calldata oodHashStateZ = proof.oodHashStateZ;
        bytes calldata oodHashSigmaZ = proof.oodHashSigmaZ;
        uint256[] memory gBNttZ = ctx.gBNttZ;
        uint256[] memory gGHatZ = ctx.gGHatZ;
        uint256[] memory gGloZ = ctx.gGloZ;
        uint256[] memory gGhiZ = ctx.gGhiZ;
        uint256[8] memory gDmZ = ctx.gDmZ;
        uint256[8] memory gDsZ = ctx.gDsZ;
        uint256[] memory gHashStateZ = ctx.gHashStateZ;
        uint256[] memory gHashSigmaZ = ctx.gHashSigmaZ;
        assembly ("memory-safe") {
            function accumulatePacked(accIn, valuesOffset, valuesIndex, oodOffset, gammas, count) -> accOut {
                let p := 340282366920938463463374607393113505793
                accOut := accIn
                let valuesPtr := add(valuesOffset, shl(4, valuesIndex))
                let gammaPtr := add(gammas, 32)
                for { let i := 0 } lt(i, count) { i := add(i, 1) } {
                    let value := shr(128, calldataload(add(valuesPtr, shl(4, i))))
                    let ood := shr(128, calldataload(add(oodOffset, shl(4, i))))
                    let difference := addmod(value, sub(p, ood), p)
                    accOut := addmod(accOut, mulmod(mload(add(gammaPtr, shl(5, i))), difference, p), p)
                }
            }

            acc := accumulatePacked(acc, tv.offset, 0, oodBNttZ.offset, gBNttZ, K)
            acc := accumulatePacked(acc, tv.offset, K, oodGHatZ.offset, gGHatZ, K)
            acc := accumulatePacked(acc, tv.offset, mul(2, K), oodGloZ.offset, gGloZ, K)
            acc := accumulatePacked(acc, tv.offset, mul(3, K), oodGhiZ.offset, gGhiZ, K)
            acc := accumulatePacked(acc, tv.offset, add(mul(4, K), 3), oodDmZ.offset, sub(gDmZ, 32), 8)
            acc := accumulatePacked(acc, tv.offset, add(mul(4, K), 11), oodDsZ.offset, sub(gDsZ, 32), 8)

            for { let hi := 0 } lt(hi, 3) { hi := add(hi, 1) } {
                let traceBase := add(add(mul(4, K), 21), mul(hi, 20))
                let stateBase := mul(hi, 12)
                let sigmaBase := mul(hi, 8)
                acc := accumulatePacked(
                    acc, tv.offset, traceBase,
                    add(oodHashStateZ.offset, shl(4, stateBase)),
                    add(gHashStateZ, shl(5, stateBase)), 12
                )
                acc := accumulatePacked(
                    acc, tv.offset, add(traceBase, 12),
                    add(oodHashSigmaZ.offset, shl(4, sigmaBase)),
                    add(gHashSigmaZ, shl(5, sigmaBase)), 8
                )
            }
        }
        unchecked {
            // m: col 4K
            uint256 mV = _packedFieldAt(tv, 4*K);
            acc = addmod(acc, mulmod(ctx.gM, addmod(mV, P - ctx.oodM, P), P), P);
            // m_orig: col 4K+1
            uint256 moV = _packedFieldAt(tv, 4*K + 1);
            acc = addmod(acc, mulmod(ctx.gMOrig, addmod(moV, P - ctx.oodMOrig, P), P), P);
            // m_sender: col 4K+2
            uint256 msV = _packedFieldAt(tv, 4*K + 2);
            acc = addmod(acc, mulmod(ctx.gMSender, addmod(msV, P - ctx.oodMSender, P), P), P);
            // μ: col 4K+19
            uint256 muV = _packedFieldAt(tv, 4*K + 19);
            acc = addmod(acc, mulmod(ctx.gMu, addmod(muV, P - ctx.oodMu, P), P), P);
            // rAur: col 4K+20
            uint256 raV = _packedFieldAt(tv, 4*K + 20);
            acc = addmod(acc, mulmod(ctx.gRAur, addmod(raV, P - ctx.oodRAur, P), P), P);
        }
    }

    // DEEP quotients for interaction tree columns (at z only; ωz handled in _combineDeep)
    function _deepInterColumnsAtZ(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx,
        uint256 traceIdx
    ) internal pure returns (uint256 acc) {
        bytes calldata iv = proof.interColValues[traceIdx];
        uint256 K = ctx.K;
        bytes calldata oodPmZ = proof.oodPmZ;
        bytes calldata oodPsZ = proof.oodPsZ;
        bytes calldata oodPrZ = proof.oodPrZ;
        uint256[8] memory gPmZ = ctx.gPmZ;
        uint256[8] memory gPsZ = ctx.gPsZ;
        uint256[] memory gPrZ = ctx.gPrZ;
        assembly ("memory-safe") {
            function accumulatePacked(accIn, valuesOffset, valuesIndex, oodOffset, gammas, count) -> accOut {
                let p := 340282366920938463463374607393113505793
                accOut := accIn
                let valuesPtr := add(valuesOffset, shl(4, valuesIndex))
                let gammaPtr := add(gammas, 32)
                for { let i := 0 } lt(i, count) { i := add(i, 1) } {
                    let value := shr(128, calldataload(add(valuesPtr, shl(4, i))))
                    let ood := shr(128, calldataload(add(oodOffset, shl(4, i))))
                    accOut := addmod(
                        accOut,
                        mulmod(mload(add(gammaPtr, shl(5, i))), addmod(value, sub(p, ood), p), p),
                        p
                    )
                }
            }

            acc := accumulatePacked(acc, iv.offset, 0, oodPmZ.offset, sub(gPmZ, 32), 8)
            acc := accumulatePacked(acc, iv.offset, 8, oodPsZ.offset, sub(gPsZ, 32), 8)
            acc := accumulatePacked(acc, iv.offset, 16, oodPrZ.offset, gPrZ, mul(2, K))
        }
        unchecked {
            // q: col 16+2K
            uint256 qv = _packedFieldAt(iv, 16 + 2*K);
            acc = addmod(acc, mulmod(ctx.gQcol, addmod(qv, P - ctx.oodQcol, P), P), P);
            // Z_lup at z: col 17+2K
            uint256 zv = _packedFieldAt(iv, 17 + 2*K);
            acc = addmod(acc, mulmod(ctx.gZlup, addmod(zv, P - ctx.oodZlup, P), P), P);
        }
    }

    // DEEP quotients for aux R,Q0,Q1 + CP chunks (all at z)
    function _deepAuxAndCp(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx,
        uint256 traceIdx
    ) internal pure returns (uint256 acc) {
        // Aux: R, Q0, Q1
        bytes calldata auxV = proof.auxColValues[traceIdx];
        uint256 rV = _packedFieldAt(auxV, 0);
        uint256 qV = _packedFieldAt(auxV, 1);
        uint256 q1V = _packedFieldAt(auxV, 2);
        acc = addmod(mulmod(ctx.gR, addmod(rV, P - ctx.oodR, P), P), mulmod(ctx.gQ, addmod(qV, P - ctx.oodQ, P), P), P);
        acc = addmod(acc, mulmod(addmod(ctx.gQ, 1, P),
            addmod(q1V, P - ctx.oodQ1, P), P), P);
        // CP chunks
        bytes calldata cv = proof.cpChunkColValues[traceIdx];
        unchecked {
            for (uint256 j = 0; j < ctx.dChunks; j++) {
                uint256 cpV = _packedFieldAt(cv, j);
                acc = addmod(acc, mulmod(ctx.gCpChunk[j], addmod(cpV, P - _packedFieldAt(proof.oodCpChunkZ, j), P), P), P);
            }
        }
    }

    // DEEP quotients for A oracle + table (at z, packed 16-byte)
    function _deepAOracle(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx,
        uint256 traceIdx
    ) internal pure returns (uint256 acc) {
        bytes calldata av = proof.aColValues[traceIdx];
        uint256 MKplus1 = ctx.MK + 1;
        unchecked {
            // A_{m,k}: first M*K entries
            for (uint256 j = 0; j < ctx.MK; j++) {
                uint256 aV;
                assembly ("memory-safe") { aV := shr(128, calldataload(add(av.offset, mul(j, 16)))) }
                aV = aV % P;
                acc = addmod(acc, mulmod(ctx.gAZ[j], addmod(aV, P - _packedFieldAt(proof.oodAZ, j), P), P), P);
            }
            // table t: last entry
            uint256 tV;
            assembly ("memory-safe") { tV := shr(128, calldataload(add(av.offset, mul(sub(MKplus1, 1), 16)))) }
            tV = tV % P;
            acc = addmod(acc, mulmod(ctx.gTZ, addmod(tV, P - ctx.oodTZ, P), P), P);
        }
    }

    // FRI fold chain (arity-4)

    function _verifyFriFolds(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx,
        uint256 q,
        uint256 layerPoint,
        uint256 invOff
    ) internal pure returns (bool) {
        uint256 quarterR = ctx.quarter0;
        uint256 nFri = ctx.numFriLayers;
        unchecked {
            for (uint256 r = 0; r < nFri; r++) {
                uint256 iR = q % quarterR;
                uint256 folded = _fold4At(proof, ctx, r, iR, quarterR, ctx.friInverses[invOff + r], ctx.friBetas[r]);
                if (folded == type(uint256).max) return false;
                if (r + 1 < nFri) {
                    (bool okN, uint256 nv) = _lookupFri(proof, r + 1, iR);
                    if (!okN) return false;
                    if (folded != nv) return false;
                    uint256 nextQuarter = quarterR >> 2;
                    layerPoint = _friNextPoint(layerPoint, iR / nextQuarter, ctx.mu);
                } else {
                    uint256 layerPoint2 = mulmod(layerPoint, layerPoint, P);
                    uint256 y = mulmod(layerPoint2, layerPoint2, P);
                    if (folded != _polyEval(proof.friFinalPoly, y)) return false;
                }
                quarterR >>= 2;
            }
        }
        return true;
    }

    function _friNextPoint(uint256 point, uint256 digit, uint256 fourthRoot)
        internal pure returns (uint256)
    {
        uint256 point2 = mulmod(point, point, P);
        uint256 point4 = mulmod(point2, point2, P);
        if (digit == 0) return point4;
        if (digit == 1) return mulmod(point4, P - fourthRoot, P);
        if (digit == 2) return P - point4;
        return mulmod(point4, fourthRoot, P);
    }

    function _fold4At(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx,
        uint256 r,
        uint256 iR,
        uint256 quarterR,
        uint256 invL,
        uint256 beta
    ) internal pure returns (uint256) {
        (bool ok0, uint256 e0) = _lookupFri(proof, r, iR);
        if (!ok0) return type(uint256).max;
        (bool ok1, uint256 e1) = _lookupFri(proof, r, iR + quarterR);
        if (!ok1) return type(uint256).max;
        (bool ok2, uint256 e2) = _lookupFri(proof, r, iR + 2 * quarterR);
        if (!ok2) return type(uint256).max;
        (bool ok3, uint256 e3) = _lookupFri(proof, r, iR + 3 * quarterR);
        if (!ok3) return type(uint256).max;

        uint256 inv4 = ctx.inv4;
        uint256 A = addmod(e0, e2, P);
        uint256 B = addmod(e1, e3, P);
        uint256 C = addmod(e0, P - e2, P);
        uint256 D = mulmod(ctx.mu, addmod(e1, P - e3, P), P);
        uint256 g0 = mulmod(addmod(A, B, P), inv4, P);
        uint256 g2 = mulmod(addmod(A, P - B, P), inv4, P);
        uint256 g1 = mulmod(addmod(C, P - D, P), inv4, P);
        uint256 g3 = mulmod(addmod(C, D, P), inv4, P);
        uint256 t1 = mulmod(beta, invL, P);
        uint256 t2 = mulmod(t1, t1, P);
        uint256 t3 = mulmod(t2, t1, P);
        return addmod(
            addmod(g0, mulmod(t1, g1, P), P),
            addmod(mulmod(t2, g2, P), mulmod(t3, g3, P), P),
            P
        );
    }

    function _polyEval(bytes calldata coeffs, uint256 x)
        internal pure returns (uint256 acc)
    {
        uint256 n = coeffs.length / 16;
        unchecked {
            for (uint256 i = n; i > 0; i--)
                acc = addmod(mulmod(acc, x, P), _packedFieldAt(coeffs, i - 1), P);
        }
    }

    function _lookupFri(ZKProofRange calldata proof, uint256 layer, uint256 pos)
        internal pure returns (bool, uint256)
    {
        uint32[] calldata positions = proof.friLayerPositions[layer];
        bytes calldata values = proof.friLayerValues[layer];
        uint256 lo = 0;
        uint256 hi = positions.length;
        unchecked {
            while (lo < hi) {
                uint256 mid = (lo + hi) / 2;
                uint256 v = uint256(positions[mid]);
                if (v == pos) return (true, _packedFieldAt(values, mid));
                if (v < pos) lo = mid + 1;
                else hi = mid;
            }
        }
        return (false, 0);
    }

    function _binarySearch(uint32[] calldata positions, uint256 pos)
        internal pure returns (bool found, uint256 idx)
    {
        uint256 lo = 0;
        uint256 hi = positions.length;
        unchecked {
            while (lo < hi) {
                uint256 mid = (lo + hi) / 2;
                uint256 v = uint256(positions[mid]);
                if (v == pos) return (true, mid);
                if (v < pos) lo = mid + 1;
                else hi = mid;
            }
        }
        return (false, 0);
    }

    // Budget helpers

    function _blindingBudget(uint256 N, uint256 numQ) internal pure returns (uint256) {
        uint256 b = numQ + 1;
        if (2 * b >= N) revert BlindingOverflow();
        return b;
    }

    /// @dev D_max = 2N + 3*bS + 1 (from Rescue C1b cube constraint)
    function _cpNumChunksHash(uint256 N, uint256 bS) internal pure returns (uint256) {
        uint256 dMax = 2 * N + 3 * bS + 1;
        return (dMax + N - 1) / N; // ceil(dMax / N)
    }

    // Field arithmetic

    function _pow(uint256 a, uint256 e) internal pure returns (uint256) {
        uint256 base = a % P;
        uint256 result = 1;
        uint256 exp = e;
        unchecked {
            while (exp > 0) {
                if (exp & 1 == 1) result = mulmod(result, base, P);
                base = mulmod(base, base, P);
                exp >>= 1;
            }
        }
        return result;
    }

    function _inv(uint256 a) internal pure returns (uint256) {
        function (uint256) internal view returns (uint256) viewFn = _invView;
        function (uint256) internal pure returns (uint256) pureFn;
        assembly ("memory-safe") { pureFn := viewFn }
        return pureFn(a);
    }

    function _invView(uint256 a) internal view returns (uint256 result) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, 0x20)
            mstore(add(ptr, 0x20), 0x20)
            mstore(add(ptr, 0x40), 0x20)
            mstore(add(ptr, 0x60), a)
            mstore(add(ptr, 0x80), 340282366920938463463374607393113505791) // P - 2
            mstore(add(ptr, 0xa0), 340282366920938463463374607393113505793) // P
            if iszero(staticcall(gas(), 0x05, ptr, 0xc0, ptr, 0x20)) {
                revert(0, 0)
            }
            result := mload(ptr)
        }
    }

    // Fiat–Shamir helpers

    function _initTranscript() internal pure returns (bytes32) {
        return keccak256(bytes("stark-fs-keccak-v1"));
    }

    /// @dev Absorb uint64 — uses scratch memory to avoid abi.encodePacked allocation.
    ///      Layout: [state(32) | v_as_u64(8)] = 40 bytes
    function _absorbU64(bytes32 state, uint32 v) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, state)
            // Store uint64(v) right-aligned in 8 bytes at ptr+32
            mstore(add(ptr, 32), shl(192, v))
            result := keccak256(ptr, 40)
        }
    }

    function _absorbU64Long(bytes32 state, uint64 v) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, state)
            mstore(add(ptr, 32), shl(192, v))
            result := keccak256(ptr, 40)
        }
    }

    /// @dev Absorb bytes32 — [state(32) | h(32)] = 64 bytes
    function _absorbHash(bytes32 state, bytes32 h) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, state)
            mstore(add(ptr, 32), h)
            result := keccak256(ptr, 64)
        }
    }

    /// @dev Absorb field element — [state(32) | (v mod P)(32)] = 64 bytes
    function _absorbField(bytes32 state, uint256 v) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            let p := 340282366920938463463374607393113505793
            mstore(ptr, state)
            mstore(add(ptr, 32), mod(v, p))
            result := keccak256(ptr, 64)
        }
    }

    /// @dev Squeeze challenge — [state(32) | "challenge"(9)] = 41 bytes
    function _challenge(bytes32 state) internal pure returns (bytes32 ns, uint256 val) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, state)
            // "challenge" = 0x6368616c6c656e6765 (9 bytes), left-aligned
            mstore(add(ptr, 32), 0x6368616c6c656e67650000000000000000000000000000000000000000000000)
            ns := keccak256(ptr, 41)
            val := mod(ns, 340282366920938463463374607393113505793)
        }
    }

    /// @dev Squeeze index — [state(32) | "index"(5)] = 37 bytes
    function _challengeIndex(bytes32 state, uint256 maxVal)
        internal pure returns (bytes32 ns, uint256 val)
    {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, state)
            // "index" = 0x696e646578 (5 bytes), left-aligned
            mstore(add(ptr, 32), 0x696e646578000000000000000000000000000000000000000000000000000000)
            ns := keccak256(ptr, 37)
            val := mod(ns, maxVal)
        }
    }

    function _leadingZeroBits(bytes32 h) internal pure returns (uint256 n) {
        uint256 v = uint256(h);
        if (v == 0) return 256;
        unchecked {
            uint256 mask = uint256(1) << 255;
            while ((v & mask) == 0) { n++; mask >>= 1; }
        }
    }

    // Misc helpers

    function _isPow2(uint32 x) internal pure returns (bool) {
        return x != 0 && (x & (x - 1)) == 0;
    }

    function _log2(uint256 x) internal pure returns (uint256 r) {
        uint256 v = x;
        unchecked { while (v > 1) { v >>= 1; r += 1; } }
    }

    function _capHeightForLayer(uint256 cfgCap, uint256 layerSize)
        internal pure returns (uint256)
    {
        uint256 d = _log2(layerSize);
        return cfgCap < d ? cfgCap : d;
    }
}

contract ZKStarkUpdateRangeHashVerifier is ZKStarkUpdateRangeHashCore {
    constructor(
        address rescueData_,
        uint256 sqrtQ_,
        uint32 M_,
        uint32 K_,
        uint32 d_,
        uint32 blowup_,
        uint32 capHeight_
    ) ZKStarkUpdateRangeHashCore(
        rescueData_, sqrtQ_, M_, K_, d_, blowup_, capHeight_
    ) {}

    function verifyZKNttMatVecRangeHashMsg(
        bytes calldata proofData,
        bytes calldata cVecPacked,
        bytes32 aOracleHashExpected
    ) external view returns (bool) {
        ZKProofRange calldata proof = _proofFromBytes(proofData);
        return _verify(proof, cVecPacked, aOracleHashExpected);
    }

    /// @dev Retains the tuple schema in the ABI without adding runtime code.
    event ProofSchema(ZKProofRange proof);
}
