pragma solidity ^0.8.26;

import "./ZKStark_update_rangehash.sol";

interface IZKStarkOodPhaseVerifier {
    function verifyOodPhase(
        bytes calldata proofData,
        bytes calldata cVecPacked,
        ZKStarkUpdateRangeHashCore.VerifyCtx calldata ctx
    ) external view returns (bool);
}

interface IZKStarkFriPhaseVerifier {
    function verifyFriPhase(
        bytes calldata proofData,
        ZKStarkUpdateRangeHashCore.VerifyCtx calldata ctx,
        uint256[] calldata expectedLayer0,
        uint256[] calldata expectedSplit,
        uint256[] calldata partialDeep
    ) external view returns (bool);
}

interface IZKStarkBasePhaseVerifier {
    function verifyBasePhase(
        bytes32 sessionId,
        bytes calldata proofData,
        ZKStarkUpdateRangeHashCore.VerifyCtx calldata ctx
    ) external returns (bytes32 valuesHash, bytes memory packedCheckpoints);
}


contract ZKStarkSplittingVerifier is ZKStarkUpdateRangeHashCore {
    uint64 public constant SESSION_LIFETIME = 256;

    uint8 private constant PHASE_HEADER = 1;
    uint8 private constant PHASE_BASE = 2;
    uint8 private constant PHASE_VERIFIED = 3;

    error InvalidPhase();
    error InvalidPhaseData();
    error SessionExpired();
    error SessionOwnerMismatch();
    error TranscriptMismatch();
    error VerificationFailed();

    struct Session {
        address owner;
        uint64 expiryBlock;
        uint8 phase;
        bytes32 baseContextHash;
        bytes32 friContextHash;
        bytes32 baseValuesHash;
        bytes packedCheckpoints;
    }

    mapping(bytes32 => Session) public sessions;
    mapping(address => uint256) public nextNonce;
    IZKStarkOodPhaseVerifier public immutable oodPhaseVerifier;
    IZKStarkFriPhaseVerifier public immutable friPhaseVerifier;
    IZKStarkBasePhaseVerifier public immutable basePhaseVerifier;

    event VerificationBegun(bytes32 indexed sessionId, address indexed owner, uint64 expiryBlock);
    event BaseOpeningsVerified(bytes32 indexed sessionId, bytes32 baseValuesHash);
    event BaseQueryCheckpoint(
        bytes32 indexed sessionId,
        uint256 indexed queryOrdinal,
        uint256 layer0Value,
        uint256 splitValue,
        uint256 partialDeep
    );
    event VerificationCompleted(bytes32 indexed sessionId, address indexed owner);
    event SessionDeleted(bytes32 indexed sessionId);

    constructor(
        address rescueData_,
        uint256 sqrtQ_,
        uint32 M_,
        uint32 K_,
        uint32 d_,
        uint32 blowup_,
        uint32 capHeight_,
        address oodPhaseVerifier_,
        address basePhaseVerifier_,
        address friPhaseVerifier_
    ) ZKStarkUpdateRangeHashCore(
        rescueData_, sqrtQ_, M_, K_, d_, blowup_, capHeight_
    ) {
        if (oodPhaseVerifier_ == address(0) || oodPhaseVerifier_.code.length == 0
            || basePhaseVerifier_ == address(0) || basePhaseVerifier_.code.length == 0
            || friPhaseVerifier_ == address(0) || friPhaseVerifier_.code.length == 0) {
            revert InvalidPhaseData();
        }
        oodPhaseVerifier = IZKStarkOodPhaseVerifier(oodPhaseVerifier_);
        basePhaseVerifier = IZKStarkBasePhaseVerifier(basePhaseVerifier_);
        friPhaseVerifier = IZKStarkFriPhaseVerifier(friPhaseVerifier_);
    }

    event ProofSchema(ZKProofRange proof);

    function beginVerification(
        bytes calldata proofData,
        bytes calldata cVecPacked,
        bytes32 aOracleHashExpected
    ) external returns (bytes32 sessionId) {
        ZKProofRange calldata proof = _proofFromBytes(proofData);
        if (!_allBaseOpeningsEmpty(proof) || !_friOpeningsEmpty(proof)) revert InvalidPhaseData();
        if (cVecPacked.length != uint256(_matM) * uint256(_matD) * 16) revert InvalidPhaseData();

        (VerifyCtx memory ctx, bytes32 checkpoint) =
            _prepareTranscript(proof, keccak256(cVecPacked), aOracleHashExpected);
        if (!oodPhaseVerifier.verifyOodPhase(proofData, cVecPacked, ctx)) {
            revert VerificationFailed();
        }
        ctx.rescueParamsPtr = 0;
        (bytes memory baseContext, bytes memory friContext) =
            _encodePhaseContexts(proof, ctx);

        uint256 nonce = nextNonce[msg.sender]++;
        sessionId = keccak256(abi.encodePacked(
            block.chainid, address(this), msg.sender, nonce, checkpoint
        ));
        Session storage session = sessions[sessionId];
        session.owner = msg.sender;
        session.expiryBlock = uint64(block.number + SESSION_LIFETIME);
        session.phase = PHASE_HEADER;
        session.baseContextHash = keccak256(baseContext);
        session.friContextHash = keccak256(friContext);

        emit VerificationBegun(sessionId, msg.sender, session.expiryBlock);
    }


    function verifyBaseOpenings(
        bytes32 sessionId,
        bytes calldata proofData,
        bytes calldata contextPackage
    ) external {
        Session storage active = _activeSession(sessionId, PHASE_HEADER);
        if (keccak256(contextPackage) != active.baseContextHash) revert TranscriptMismatch();
        ZKProofRange calldata proof = _proofFromBytes(proofData);
        if (_primaryBaseOpeningsEmpty(proof) || !_deferredBaseOpeningsEmpty(proof)
            || !_friOpeningsEmpty(proof)) revert InvalidPhaseData();

        (VerifyCtx memory ctx, bytes32 baseBinding) =
            abi.decode(contextPackage, (VerifyCtx, bytes32));
        if (_baseProofBinding(proof) != baseBinding) revert TranscriptMismatch();
        (bytes32 baseValuesHash, bytes memory packedCheckpoints) =
            basePhaseVerifier.verifyBasePhase(sessionId, proofData, ctx);
        Session storage session = sessions[sessionId];
        session.baseValuesHash = baseValuesHash;
        session.packedCheckpoints = packedCheckpoints;
        session.phase = PHASE_BASE;
        emit BaseOpeningsVerified(sessionId, baseValuesHash);
    }

    function verifyFriAndFinalize(
        bytes32 sessionId,
        bytes calldata proofData,
        bytes calldata contextPackage
    ) external {
        Session storage active = _activeSession(sessionId, PHASE_BASE);
        if (keccak256(contextPackage) != active.friContextHash) revert TranscriptMismatch();
        bytes32 expectedBaseHash = active.baseValuesHash;
        (uint256[] memory expectedLayer0, uint256[] memory expectedSplit,
            uint256[] memory partialDeep) = _unpackBaseCheckpoints(active.packedCheckpoints);
        ZKProofRange calldata proof = _proofFromBytes(proofData);
        if (!_primaryBaseOpeningsEmpty(proof) || _deferredBaseOpeningsEmpty(proof)
            || _friOpeningsEmpty(proof)) revert InvalidPhaseData();
        if (_hashBaseCheckpoints(expectedLayer0, expectedSplit, partialDeep) != expectedBaseHash) {
            revert TranscriptMismatch();
        }

        (VerifyCtx memory ctx, bytes32 friBinding) =
            abi.decode(contextPackage, (VerifyCtx, bytes32));
        if (_friProofBinding(proof) != friBinding) revert TranscriptMismatch();
        if (!friPhaseVerifier.verifyFriPhase(
            proofData, ctx, expectedLayer0, expectedSplit, partialDeep
        )) revert VerificationFailed();

        Session storage session = sessions[sessionId];
        session.phase = PHASE_VERIFIED;
        delete session.baseContextHash;
        delete session.friContextHash;
        delete session.baseValuesHash;
        delete session.packedCheckpoints;
        emit VerificationCompleted(sessionId, session.owner);
    }

    function deleteSession(bytes32 sessionId) external {
        Session storage session = sessions[sessionId];
        if (session.owner == address(0)) revert InvalidPhase();
        if (msg.sender != session.owner && block.number <= session.expiryBlock) {
            revert SessionOwnerMismatch();
        }
        delete sessions[sessionId];
        emit SessionDeleted(sessionId);
    }

    function isVerified(bytes32 sessionId) external view returns (bool) {
        return sessions[sessionId].phase == PHASE_VERIFIED;
    }


    function prepareVerificationContext(
        bytes calldata proofData,
        bytes32 cVecHash,
        bytes32 aOracleHashExpected
    ) external view returns (bytes memory baseContext, bytes memory friContext) {
        ZKProofRange calldata proof = _proofFromBytes(proofData);
        if (!_allBaseOpeningsEmpty(proof) || !_friOpeningsEmpty(proof)) revert InvalidPhaseData();
        (VerifyCtx memory ctx,) = _prepareTranscript(proof, cVecHash, aOracleHashExpected);
        ctx.rescueParamsPtr = 0;
        return _encodePhaseContexts(proof, ctx);
    }

    function _activeSession(bytes32 sessionId, uint8 expectedPhase)
        internal view returns (Session storage session)
    {
        session = sessions[sessionId];
        if (session.phase != expectedPhase) revert InvalidPhase();
        if (session.owner != msg.sender) revert SessionOwnerMismatch();
        if (block.number > session.expiryBlock) revert SessionExpired();
    }

    function _encodePhaseContexts(ZKProofRange calldata proof, VerifyCtx memory ctx)
        internal pure returns (bytes memory baseContext, bytes memory friContext)
    {
        uint256[] memory empty = new uint256[](0);
        ctx.alphaPows = empty;
        ctx.rhos = empty;
        ctx.lamK = empty;
        ctx.friInverses = empty;
        ctx.queryPoints = empty;

        uint256[] memory gAZ = ctx.gAZ;
        uint256[] memory friBetas = ctx.friBetas;
        ctx.gAZ = empty;
        ctx.friBetas = empty;
        baseContext = abi.encode(ctx, _baseProofBinding(proof));

        ctx.gAZ = gAZ;
        ctx.friBetas = friBetas;
        ctx.gBNttZ = empty;
        ctx.gGHatZ = empty;
        ctx.gGloZ = empty;
        ctx.gGhiZ = empty;
        ctx.gPrZ = empty;
        ctx.gCpChunk = empty;
        ctx.gHashStateZ = empty;
        ctx.gHashStateOmegaZ = empty;
        ctx.gHashSigmaZ = empty;
        ctx.gSourceShifts = empty;
        friContext = abi.encode(ctx, _friProofBinding(proof));
    }

    function _baseProofBinding(ZKProofRange calldata proof)
        internal pure returns (bytes32)
    {
        return keccak256(abi.encode(
            proof.capHeight,
            proof.queryIndices,
            proof.traceCap,
            proof.interCap,
            proof.auxCap,
            proof.cpChunkCap,
            proof.splitCap,
            proof.tokenM,
            proof.tokenS,
            proof.tokenO,
            _oodProofBinding(proof)
        ));
    }

    function _friProofBinding(ZKProofRange calldata proof)
        internal pure returns (bytes32)
    {
        return keccak256(abi.encode(
            proof.capHeight,
            proof.queryIndices,
            proof.maskCap,
            proof.aCap,
            proof.friCaps,
            proof.friFinalPoly,
            proof.grindingNonce,
            proof.oodAZ,
            proof.oodTZ,
            proof.tokenM,
            proof.tokenS,
            proof.tokenO
        ));
    }

    function _oodProofBinding(ZKProofRange calldata proof)
        internal pure returns (bytes32 binding)
    {
        binding = keccak256(abi.encode(
            proof.oodBNttZ, proof.oodGHatZ, proof.oodGloZ, proof.oodGhiZ,
            proof.oodAZ, proof.oodTZ, proof.oodMZ, proof.oodMOrigZ,
            proof.oodMSenderZ, proof.oodDmZ, proof.oodDsZ
        ));
        binding = keccak256(abi.encode(
            binding, proof.oodPmZ, proof.oodPsZ, proof.oodPrZ,
            proof.oodQcolZ, proof.oodMuZ, proof.oodZlupZ, proof.oodZlupOmegaZ,
            proof.oodRAurZ, proof.oodRZ, proof.oodQZ, proof.oodQ1Z
        ));
        return keccak256(abi.encode(
            binding, proof.oodCpChunkZ, proof.oodHashStateZ,
            proof.oodHashStateOmegaZ, proof.oodHashSigmaZ, proof.oodSourceShifts
        ));
    }

    function _prepareTranscript(
        ZKProofRange calldata proof,
        bytes32 cVecHash,
        bytes32 aOracleHashExpected
    ) internal view returns (VerifyCtx memory ctx, bytes32 state) {
        uint256 N = uint256(_matD);
        uint256 K = uint256(_matK);
        uint256 M = uint256(_matM);
        if (M < 2 || K == 0 || N == 0) revert InvalidPhaseData();
        if (uint256(proof.numColumns) != K || uint256(proof.traceLength) != N) revert InvalidPhaseData();
        if (uint256(proof.blowup) != uint256(_aBlowup)) revert InvalidPhaseData();
        if (uint256(proof.capHeight) != uint256(_aCapHeight)) revert InvalidPhaseData();
        if (proof.queryIndices.length != NUM_QUERIES) revert InvalidPhaseData();
        if (proof.oodBNttZ.length != K * 16 || proof.oodGHatZ.length != K * 16) revert InvalidPhaseData();
        if (proof.oodGloZ.length != K * 16 || proof.oodGhiZ.length != K * 16) revert InvalidPhaseData();
        if (proof.oodDmZ.length != NUM_BYTES * 16 || proof.oodDsZ.length != NUM_BYTES * 16) revert InvalidPhaseData();
        if (proof.oodPmZ.length != NUM_BYTES * 16 || proof.oodPsZ.length != NUM_BYTES * 16) revert InvalidPhaseData();
        if (proof.oodPrZ.length != 2 * K * 16 || proof.oodAZ.length != M * K * 16) revert InvalidPhaseData();
        if (proof.oodHashStateZ.length != NUM_HASHES * HASH_STATE_WIDTH * 16) revert InvalidPhaseData();
        if (proof.oodHashStateOmegaZ.length != NUM_HASHES * HASH_STATE_WIDTH * 16) revert InvalidPhaseData();
        if (proof.oodHashSigmaZ.length != NUM_HASHES * HASH_RATE * 16) revert InvalidPhaseData();
        if (proof.oodSourceShifts.length != NUM_HASHES * (HASH_RATE - 1) * 16) revert InvalidPhaseData();
        if (proof.traceCap.length == 0 || proof.interCap.length == 0 || proof.auxCap.length == 0) revert InvalidPhaseData();
        if (proof.cpChunkCap.length == 0 || proof.maskCap.length == 0 || proof.splitCap.length == 0) revert InvalidPhaseData();
        if (proof.aCap.length == 0 || proof.friCaps.length == 0) revert InvalidPhaseData();

        ctx.rescueParamsPtr = _loadRescueParams();
        ctx.N = N;
        ctx.K = K;
        ctx.M = M;
        ctx.MK = M * K;
        ctx.traceCols = 4 * K + 81;
        ctx.ldeSize = N * uint256(proof.blowup);
        ctx.b = _blindingBudget(N, NUM_QUERIES);
        ctx.bSource = NUM_QUERIES + 8;
        ctx.bState = NUM_QUERIES + 2;
        ctx.bSigma = NUM_QUERIES + 1;
        ctx.hBlind = NUM_QUERIES + 1;
        ctx.dChunks = _cpNumChunksHash(N, ctx.bState);
        ctx.w = N;
        if (uint256(proof.blindB) != ctx.b || uint256(proof.blindBSource) != ctx.bSource) revert InvalidPhaseData();
        if (uint256(proof.blindBState) != ctx.bState || uint256(proof.blindBSigma) != ctx.bSigma) revert InvalidPhaseData();
        if (uint256(proof.cpBlindH) != ctx.hBlind || uint256(proof.numChunks) != ctx.dChunks) revert InvalidPhaseData();
        if (uint256(proof.cpChunkWidth) != N || proof.oodCpChunkZ.length != ctx.dChunks * 16) revert InvalidPhaseData();

        ctx.numFriLayers = proof.friCaps.length;
        ctx.omega = _pow(G_PRIM, (P - 1) / N);
        ctx.psi = _pow(G_PRIM, (P - 1) / (2 * N));
        ctx.ldeOmega = _pow(G_PRIM, (P - 1) / ctx.ldeSize);
        ctx.cosetGen = _pow(G_PRIM, (P - 1) / (2 * ctx.ldeSize));
        ctx.omegaNm1 = _pow(ctx.omega, N - 1);
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

        bytes32 capHash;
        bytes32[] calldata aCap = proof.aCap;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            let size := mul(aCap.length, 32)
            calldatacopy(ptr, aCap.offset, size)
            capHash := keccak256(ptr, size)
        }
        if (capHash != aOracleHashExpected) revert InvalidPhaseData();

        state = _initTranscript();
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
        state = _absorbHash(state, cVecHash);
        state = _absorbField(state, proof.tokenM[0]);
        state = _absorbField(state, proof.tokenM[1]);
        state = _absorbField(state, proof.tokenS[0]);
        state = _absorbField(state, proof.tokenS[1]);
        state = _absorbField(state, proof.tokenO[0]);
        state = _absorbField(state, proof.tokenO[1]);
        state = _absorbHashArray(state, proof.traceCap);

        uint256 rho0;
        (state, rho0) = _challenge(state);
        ctx.rhos = new uint256[](M);
        uint256 rhoAcc = rho0;
        for (uint256 i = 0; i < M; i++) {
            ctx.rhos[i] = rhoAcc;
            rhoAcc = mulmod(rhoAcc, rho0, P);
        }
        ctx.rhoMsg = addmod(ctx.rhos[M - 2], mulmod(ctx.rhos[M - 1], _sqrtQ, P), P);

        (state, ctx.alpha) = _challenge(state);
        ctx.alphaPows = new uint256[](3 * K + 124);
        ctx.alphaPows[0] = ctx.alpha;
        for (uint256 i = 1; i < ctx.alphaPows.length; i++) {
            ctx.alphaPows[i] = mulmod(ctx.alphaPows[i - 1], ctx.alpha, P);
        }
        ctx.lamK = new uint256[](K);
        for (uint256 i = 0; i < K; i++) (state, ctx.lamK[i]) = _challenge(state);
        (state, ctx.betaLup) = _challenge(state);

        state = _absorbHashArray(state, proof.interCap);
        ctx.betaAur = proof.betaAur % P;
        state = _absorbField(state, proof.betaAur);
        (state, ctx.rhoAurora) = _challenge(state);
        state = _absorbHashArray(state, proof.auxCap);
        state = _absorbHashArray(state, proof.cpChunkCap);
        (state, ctx.z) = _challenge(state);
        ctx.omegaZ = mulmod(ctx.omega, ctx.z, P);
        state = _absorbOodClaims(state, proof, ctx);
        state = _absorbHashArray(state, proof.maskCap);
        state = _squeezeDeepChallenges(state, ctx);
        state = _absorbHashArray(state, proof.splitCap);
        (state, ctx.lambda) = _challenge(state);

        uint256 shift = 2 * ctx.numFriLayers;
        if (shift >= 256 || N % (uint256(1) << shift) != 0) revert InvalidPhaseData();
        uint256 finalBound = N / (uint256(1) << shift);
        if (finalBound == 0 || finalBound > FINAL_POLY_BOUND) revert InvalidPhaseData();
        if (proof.friFinalPoly.length != finalBound * 16) revert InvalidPhaseData();

        state = _absorbHashArray(state, proof.friCaps[0]);
        ctx.friBetas = new uint256[](ctx.numFriLayers);
        for (uint256 r = 0; r < ctx.numFriLayers; r++) {
            (state, ctx.friBetas[r]) = _challenge(state);
            if (r + 1 < ctx.numFriLayers) state = _absorbHashArray(state, proof.friCaps[r + 1]);
        }
        state = _absorbPackedFieldArray(state, proof.friFinalPoly);
        state = _absorbU64Long(state, proof.grindingNonce);
        if (_leadingZeroBits(state) < GRINDING_BITS) revert VerificationFailed();

        ctx.quarter0 = ctx.ldeSize / FRI_ARITY;
        for (uint256 i = 0; i < NUM_QUERIES; i++) {
            uint256 queryIndex;
            (state, queryIndex) = _challengeIndex(state, ctx.quarter0);
            if (uint256(proof.queryIndices[i]) != queryIndex) revert VerificationFailed();
        }
    }

    function _verifyPrimaryBaseMerkle(ZKProofRange calldata proof, VerifyCtx memory ctx)
        internal pure returns (bool)
    {
        uint256 capH = _capHeightForLayer(uint256(proof.capHeight), ctx.ldeSize);
        uint256 capSize = uint256(1) << capH;
        uint256 count = proof.tracePositions.length;
        if (count == 0) return false;

        if (!_verifyPackedTree(proof.traceCap, proof.tracePositions, proof.traceColValues,
            proof.traceSalts, proof.traceBatchProof, capSize, ctx.ldeSize, ctx.traceCols, true)) return false;
        if (!_verifyPackedTree(proof.interCap, proof.tracePositions, proof.interColValues,
            proof.interSalts, proof.interBatchProof, capSize, ctx.ldeSize, 18 + 2 * ctx.K, true)) return false;
        if (!_verifyPackedTree(proof.auxCap, proof.tracePositions, proof.auxColValues,
            proof.auxSalts, proof.auxBatchProof, capSize, ctx.ldeSize, 3, true)) return false;
        if (!_verifyPackedTree(proof.cpChunkCap, proof.tracePositions, proof.cpChunkColValues,
            proof.cpChunkSalts, proof.cpChunkBatchProof, capSize, ctx.ldeSize, ctx.dChunks, true)) return false;
        if (!_verifyPackedTree(proof.splitCap, proof.tracePositions, proof.splitColValues,
            proof.splitSalts, proof.splitBatchProof, capSize, ctx.ldeSize, 2, true)) return false;
        return true;
    }

    function _verifyDeferredBaseMerkle(ZKProofRange calldata proof, VerifyCtx memory ctx)
        internal pure returns (bool)
    {
        uint256 capH = _capHeightForLayer(uint256(proof.capHeight), ctx.ldeSize);
        uint256 capSize = uint256(1) << capH;
        if (proof.tracePositions.length == 0) return false;
        if (!_verifyMerkleSingleValueSalted(proof.maskCap, proof.tracePositions, proof.maskValues,
            proof.maskSalts, proof.maskBatchProof, uint256(proof.capHeight), ctx.ldeSize)) return false;
        return _verifyPackedTree(proof.aCap, proof.tracePositions, proof.aColValues,
            proof.traceSalts, proof.aBatchProof, capSize, ctx.ldeSize, ctx.MK + 1, false);
    }

    function _verifyPackedTree(
        bytes32[] calldata cap,
        uint32[] calldata positions,
        bytes[] calldata values,
        bytes16[] calldata salts,
        bytes32[] calldata proofPath,
        uint256 capSize,
        uint256 layerSize,
        uint256 width,
        bool salted
    ) internal pure returns (bool) {
        uint256 count = positions.length;
        if (cap.length != capSize || values.length != count) return false;
        if (salted && salts.length != count) return false;
        bytes32[] memory leaves = new bytes32[](count);
        for (uint256 i = 0; i < count; i++) {
            if (values[i].length != width * 16) return false;
            leaves[i] = salted
                ? _hashBundledLeafPackedSalt(values[i], width, salts[i])
                : _hashBundledLeafPacked(values[i], width);
        }
        return _verifyBatch(cap, capSize, layerSize, positions, leaves, proofPath);
    }

    function _computeBaseCheckpoints(
        bytes32 sessionId,
        ZKProofRange calldata proof,
        VerifyCtx memory ctx
    ) internal returns (bytes32 valuesHash, bytes memory packed)
    {
        uint256 queryCount = proof.queryIndices.length;
        packed = new bytes(queryCount * 48);
        uint256[] memory denominators = new uint256[](queryCount * 9);
        ctx.queryPoints = new uint256[](queryCount);
        uint256[7] memory shiftedZ;
        uint256 omegaPower = ctx.omega;
        for (uint256 j = 0; j < 7; j++) {
            shiftedZ[j] = mulmod(omegaPower, ctx.z, P);
            omegaPower = mulmod(omegaPower, ctx.omega, P);
        }
        for (uint256 qi = 0; qi < queryCount; qi++) {
            uint256 i0 = uint256(proof.queryIndices[qi]) % ctx.quarter0;
            uint256 x = mulmod(ctx.cosetGen, _pow(ctx.ldeOmega, i0), P);
            ctx.queryPoints[qi] = x;
            uint256 offset = qi * 9;
            denominators[offset] = addmod(x, P - ctx.z, P);
            denominators[offset + 1] = addmod(x, P - ctx.omegaZ, P);
            for (uint256 j = 0; j < 7; j++) {
                denominators[offset + 2 + j] = addmod(x, P - shiftedZ[j], P);
            }
        }
        ctx.friInverses = _batchInv(denominators);
        ctx.friInvStride = 9;

        for (uint256 qi = 0; qi < queryCount; qi++) {
            uint256 i0 = uint256(proof.queryIndices[qi]) % ctx.quarter0;
            (bool found, uint256 traceIndex) = _binarySearch(proof.tracePositions, i0);
            if (!found) revert VerificationFailed();
            (uint256 layer0Value, uint256 splitValue, uint256 partialDeep) =
                _computeOneBaseCheckpoint(proof, ctx, qi, traceIndex);
            valuesHash = keccak256(abi.encodePacked(
                valuesHash, layer0Value, splitValue, partialDeep
            ));
            assembly ("memory-safe") {
                let ptr := add(add(packed, 32), mul(qi, 48))
                mstore(ptr, shl(128, layer0Value))
                mstore(add(ptr, 16), shl(128, splitValue))
                mstore(add(ptr, 32), shl(128, partialDeep))
            }
            emit BaseQueryCheckpoint(sessionId, qi, layer0Value, splitValue, partialDeep);
        }
    }

    function _unpackBaseCheckpoints(bytes storage packed)
        internal view returns (
            uint256[] memory layer0Values,
            uint256[] memory splitValues,
            uint256[] memory partialDeepValues
        )
    {
        bytes memory data = packed;
        if (data.length != NUM_QUERIES * 48) revert InvalidPhaseData();
        layer0Values = new uint256[](NUM_QUERIES);
        splitValues = new uint256[](NUM_QUERIES);
        partialDeepValues = new uint256[](NUM_QUERIES);
        for (uint256 i = 0; i < NUM_QUERIES; i++) {
            assembly ("memory-safe") {
                let ptr := add(add(data, 32), mul(i, 48))
                mstore(add(add(layer0Values, 32), mul(i, 32)), shr(128, mload(ptr)))
                mstore(add(add(splitValues, 32), mul(i, 32)), shr(128, mload(add(ptr, 16))))
                mstore(add(add(partialDeepValues, 32), mul(i, 32)), shr(128, mload(add(ptr, 32))))
            }
        }
    }

    function _hashBaseCheckpoints(
        uint256[] memory layer0Values,
        uint256[] memory splitValues,
        uint256[] memory partialDeepValues
    )
        internal pure returns (bytes32 valuesHash)
    {
        for (uint256 i = 0; i < layer0Values.length; i++) {
            valuesHash = keccak256(abi.encodePacked(
                valuesHash, layer0Values[i], splitValues[i], partialDeepValues[i]
            ));
        }
    }

    function _computeOneBaseCheckpoint(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx,
        uint256 queryIndex,
        uint256 traceIndex
    ) internal pure returns (uint256 layer0Value, uint256 splitValue, uint256 partialDeep) {
        uint256 x = ctx.queryPoints[queryIndex];
        partialDeep = _combinePrimaryDeep(proof, ctx, traceIndex, queryIndex * 9);
        bytes calldata splitValues = proof.splitColValues[traceIndex];
        uint256 g0 = _packedFieldAt(splitValues, 0);
        uint256 g1 = _packedFieldAt(splitValues, 1);
        splitValue = addmod(g0, mulmod(_pow(x, ctx.N), g1, P), P);

        bytes calldata auxValues = proof.auxColValues[traceIndex];
        uint256 batched = mulmod(
            _pow(x, ctx.N - ctx.b + 1), _packedFieldAt(auxValues, 2), P
        );
        batched = addmod(
            _packedFieldAt(auxValues, 1), mulmod(ctx.lambda, batched, P), P
        );
        batched = addmod(
            mulmod(x, _packedFieldAt(auxValues, 0), P),
            mulmod(ctx.lambda, batched, P),
            P
        );
        batched = addmod(g1, mulmod(ctx.lambda, batched, P), P);
        layer0Value = addmod(g0, mulmod(ctx.lambda, batched, P), P);
    }

    function _combinePrimaryDeep(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx,
        uint256 traceIndex,
        uint256 invOff
    ) internal pure returns (uint256 deep) {
        uint256 numerator = _deepTraceColumns(proof, ctx, traceIndex);
        numerator = addmod(numerator, _deepInterColumnsAtZ(proof, ctx, traceIndex), P);
        numerator = addmod(numerator, _deepAuxAndCp(proof, ctx, traceIndex), P);
        deep = mulmod(numerator, ctx.friInverses[invOff], P);
        bytes calldata interactionValues = proof.interColValues[traceIndex];
        uint256 zValue = _packedFieldAt(interactionValues, 17 + 2 * ctx.K);
        uint256 omegaNumerator = mulmod(
            ctx.gZlupOmega, addmod(zValue, P - ctx.oodZlupOmega, P), P
        );
        deep = addmod(deep, mulmod(omegaNumerator, ctx.friInverses[invOff + 1], P), P);
        return addmod(
            deep,
            _deepHashOmegaAndShifts(
                proof, ctx, traceIndex, ctx.friInverses[invOff + 1], invOff
            ),
            P
        );
    }

    function _verifyDeferredBaseQueries(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx,
        uint256[] memory expectedSplit,
        uint256[] memory partialDeep
    ) internal pure returns (bool) {
        uint256[] memory denominators = new uint256[](proof.queryIndices.length);
        for (uint256 qi = 0; qi < proof.queryIndices.length; qi++) {
            uint256 i0 = uint256(proof.queryIndices[qi]) % ctx.quarter0;
            uint256 x = mulmod(ctx.cosetGen, _pow(ctx.ldeOmega, i0), P);
            denominators[qi] = addmod(x, P - ctx.z, P);
        }
        uint256[] memory inverses = _batchInv(denominators);
        for (uint256 qi = 0; qi < proof.queryIndices.length; qi++) {
            uint256 i0 = uint256(proof.queryIndices[qi]) % ctx.quarter0;
            (bool found, uint256 traceIndex) = _binarySearch(proof.tracePositions, i0);
            if (!found) return false;
            uint256 deferred = mulmod(_deepAOracle(proof, ctx, traceIndex), inverses[qi], P);
            deferred = addmod(deferred, _packedFieldAt(proof.maskValues, traceIndex), P);
            if (addmod(partialDeep[qi], deferred, P) != expectedSplit[qi]) return false;
        }
        return true;
    }

    function _verifyFriMerkle(ZKProofRange calldata proof, VerifyCtx memory ctx)
        internal pure returns (bool)
    {
        uint256 layers = ctx.numFriLayers;
        if (proof.friLayerPositions.length != layers || proof.friLayerValues.length != layers) return false;
        if (proof.friLayerSalts.length != layers || proof.friLayerProofs.length != layers) return false;
        for (uint256 r = 0; r < layers; r++) {
            uint256 layerSize = ctx.ldeSize >> (2 * r);
            if (!_verifyMerkleSingleValueSalted(
                proof.friCaps[r], proof.friLayerPositions[r], proof.friLayerValues[r],
                proof.friLayerSalts[r], proof.friLayerProofs[r], uint256(proof.capHeight), layerSize
            )) return false;
        }
        return true;
    }

    function _verifyFriQueries(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx,
        uint256[] memory expectedLayer0
    ) internal pure returns (bool) {
        uint256 queryCount = proof.queryIndices.length;
        uint256 layers = ctx.numFriLayers;
        uint256[] memory denominators = new uint256[](queryCount * layers);
        ctx.queryPoints = new uint256[](queryCount);
        ctx.inv4 = _inv(FRI_ARITY);
        ctx.mu = _pow(ctx.ldeOmega, ctx.quarter0);
        for (uint256 qi = 0; qi < queryCount; qi++) {
            uint256 q = uint256(proof.queryIndices[qi]);
            uint256 i0 = q % ctx.quarter0;
            uint256 point = mulmod(ctx.cosetGen, _pow(ctx.ldeOmega, i0), P);
            ctx.queryPoints[qi] = point;
            uint256 quarter = ctx.quarter0;
            for (uint256 r = 0; r < layers; r++) {
                uint256 iR = q % quarter;
                denominators[qi * layers + r] = point;
                if (r + 1 < layers) {
                    uint256 nextQuarter = quarter >> 2;
                    point = _friNextPoint(point, iR / nextQuarter, ctx.mu);
                }
                quarter >>= 2;
            }
        }
        ctx.friInverses = _batchInv(denominators);
        ctx.friInvStride = layers;

        for (uint256 qi = 0; qi < queryCount; qi++) {
            if (!_verifyOneFriQuery(proof, ctx, expectedLayer0[qi], qi)) return false;
        }
        return true;
    }

    function _verifyOneFriQuery(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx,
        uint256 expectedLayer0,
        uint256 queryIndex
    ) internal pure returns (bool) {
        uint256 query = uint256(proof.queryIndices[queryIndex]);
        uint256 i0 = query % ctx.quarter0;
        (bool found, uint256 layer0Value) = _lookupFri(proof, 0, i0);
        if (!found || layer0Value != expectedLayer0) return false;
        return _verifyFriFolds(
            proof,
            ctx,
            query,
            ctx.queryPoints[queryIndex],
            queryIndex * ctx.numFriLayers
        );
    }

    function _primaryBaseOpeningsEmpty(ZKProofRange calldata proof) internal pure returns (bool) {
        return proof.traceColValues.length == 0 && proof.traceSalts.length == 0 && proof.traceBatchProof.length == 0
            && proof.interColValues.length == 0 && proof.interSalts.length == 0 && proof.interBatchProof.length == 0
            && proof.auxColValues.length == 0 && proof.auxSalts.length == 0 && proof.auxBatchProof.length == 0
            && proof.cpChunkColValues.length == 0 && proof.cpChunkSalts.length == 0 && proof.cpChunkBatchProof.length == 0
            && proof.splitColValues.length == 0 && proof.splitSalts.length == 0 && proof.splitBatchProof.length == 0;
    }

    function _deferredBaseOpeningsEmpty(ZKProofRange calldata proof) internal pure returns (bool) {
        return proof.maskValues.length == 0 && proof.maskSalts.length == 0
            && proof.maskBatchProof.length == 0 && proof.aColValues.length == 0
            && proof.aBatchProof.length == 0;
    }

    function _allBaseOpeningsEmpty(ZKProofRange calldata proof) internal pure returns (bool) {
        return proof.tracePositions.length == 0 && _primaryBaseOpeningsEmpty(proof)
            && _deferredBaseOpeningsEmpty(proof);
    }

    function _friOpeningsEmpty(ZKProofRange calldata proof) internal pure returns (bool) {
        return proof.friLayerPositions.length == 0
            && proof.friLayerValues.length == 0
            && proof.friLayerSalts.length == 0
            && proof.friLayerProofs.length == 0;
    }
}

contract ZKStarkOodPhaseVerifier is ZKStarkUpdateRangeHashCore {
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

    function verifyOodPhase(
        bytes calldata proofData,
        bytes calldata cVecPacked,
        VerifyCtx calldata suppliedCtx
    ) external view returns (bool) {
        ZKProofRange calldata proof = _proofFromBytes(proofData);
        VerifyCtx memory ctx = suppliedCtx;
        ctx.rescueParamsPtr = _loadRescueParams();
        return _checkOodConstraint(proof, cVecPacked, ctx);
    }
}

contract ZKStarkBasePhaseVerifier is ZKStarkUpdateRangeHashCore {
    event BaseQueryCheckpoint(
        bytes32 indexed sessionId,
        uint256 indexed queryOrdinal,
        uint256 layer0Value,
        uint256 splitValue,
        uint256 partialDeep
    );

    constructor(
        address rescueData_, uint256 sqrtQ_, uint32 M_, uint32 K_, uint32 d_,
        uint32 blowup_, uint32 capHeight_
    ) ZKStarkUpdateRangeHashCore(
        rescueData_, sqrtQ_, M_, K_, d_, blowup_, capHeight_
    ) {}

    function verifyBasePhase(
        bytes32 sessionId,
        bytes calldata proofData,
        VerifyCtx calldata suppliedCtx
    ) external returns (bytes32 valuesHash, bytes memory packed) {
        ZKProofRange calldata proof = _proofFromBytes(proofData);
        VerifyCtx memory ctx = suppliedCtx;
        if (!_verifyPrimaryMerkle(proof, ctx)) revert InvalidParam();
        return _computeCheckpoints(sessionId, proof, ctx);
    }

    function _verifyPrimaryMerkle(ZKProofRange calldata proof, VerifyCtx memory ctx)
        internal pure returns (bool)
    {
        uint256 capH = _capHeightForLayer(uint256(proof.capHeight), ctx.ldeSize);
        uint256 capSize = uint256(1) << capH;
        if (proof.tracePositions.length == 0) return false;
        if (!_verifySaltedTree(proof.traceCap, proof.tracePositions, proof.traceColValues,
            proof.traceSalts, proof.traceBatchProof, capSize, ctx.ldeSize, ctx.traceCols)) return false;
        if (!_verifySaltedTree(proof.interCap, proof.tracePositions, proof.interColValues,
            proof.interSalts, proof.interBatchProof, capSize, ctx.ldeSize, 18 + 2 * ctx.K)) return false;
        if (!_verifySaltedTree(proof.auxCap, proof.tracePositions, proof.auxColValues,
            proof.auxSalts, proof.auxBatchProof, capSize, ctx.ldeSize, 3)) return false;
        if (!_verifySaltedTree(proof.cpChunkCap, proof.tracePositions, proof.cpChunkColValues,
            proof.cpChunkSalts, proof.cpChunkBatchProof, capSize, ctx.ldeSize, ctx.dChunks)) return false;
        return _verifySaltedTree(proof.splitCap, proof.tracePositions, proof.splitColValues,
            proof.splitSalts, proof.splitBatchProof, capSize, ctx.ldeSize, 2);
    }

    function _verifySaltedTree(
        bytes32[] calldata cap, uint32[] calldata positions, bytes[] calldata values,
        bytes16[] calldata salts, bytes32[] calldata proofPath, uint256 capSize,
        uint256 layerSize, uint256 width
    ) internal pure returns (bool) {
        uint256 count = positions.length;
        if (cap.length != capSize || values.length != count || salts.length != count) return false;
        bytes32[] memory leaves = new bytes32[](count);
        for (uint256 i = 0; i < count; i++) {
            if (values[i].length != width * 16) return false;
            leaves[i] = _hashBundledLeafPackedSalt(values[i], width, salts[i]);
        }
        return _verifyBatch(cap, capSize, layerSize, positions, leaves, proofPath);
    }

    function _computeCheckpoints(
        bytes32 sessionId, ZKProofRange calldata proof, VerifyCtx memory ctx
    ) internal returns (bytes32 valuesHash, bytes memory packed) {
        uint256 count = proof.queryIndices.length;
        packed = new bytes(count * 48);
        uint256[] memory denominators = new uint256[](count * 9);
        ctx.queryPoints = new uint256[](count);
        uint256[7] memory shiftedZ;
        uint256 omegaPower = ctx.omega;
        for (uint256 j = 0; j < 7; j++) {
            shiftedZ[j] = mulmod(omegaPower, ctx.z, P);
            omegaPower = mulmod(omegaPower, ctx.omega, P);
        }
        for (uint256 qi = 0; qi < count; qi++) {
            uint256 i0 = uint256(proof.queryIndices[qi]) % ctx.quarter0;
            uint256 x = mulmod(ctx.cosetGen, _pow(ctx.ldeOmega, i0), P);
            ctx.queryPoints[qi] = x;
            uint256 offset = qi * 9;
            denominators[offset] = addmod(x, P - ctx.z, P);
            denominators[offset + 1] = addmod(x, P - ctx.omegaZ, P);
            for (uint256 j = 0; j < 7; j++) {
                denominators[offset + 2 + j] = addmod(x, P - shiftedZ[j], P);
            }
        }
        ctx.friInverses = _batchInv(denominators);
        ctx.friInvStride = 9;
        for (uint256 qi = 0; qi < count; qi++) {
            uint256 i0 = uint256(proof.queryIndices[qi]) % ctx.quarter0;
            (bool found, uint256 traceIndex) = _binarySearch(proof.tracePositions, i0);
            if (!found) revert InvalidParam();
            (uint256 layer0Value, uint256 splitValue, uint256 partialDeep) =
                _computeCheckpoint(proof, ctx, qi, traceIndex);
            valuesHash = keccak256(abi.encodePacked(valuesHash, layer0Value, splitValue, partialDeep));
            assembly ("memory-safe") {
                let ptr := add(add(packed, 32), mul(qi, 48))
                mstore(ptr, shl(128, layer0Value))
                mstore(add(ptr, 16), shl(128, splitValue))
                mstore(add(ptr, 32), shl(128, partialDeep))
            }
            emit BaseQueryCheckpoint(sessionId, qi, layer0Value, splitValue, partialDeep);
        }
    }

    function _computeCheckpoint(
        ZKProofRange calldata proof, VerifyCtx memory ctx,
        uint256 queryIndex, uint256 traceIndex
    ) internal pure returns (uint256 layer0Value, uint256 splitValue, uint256 partialDeep) {
        uint256 x = ctx.queryPoints[queryIndex];
        partialDeep = _combinePrimary(proof, ctx, traceIndex, queryIndex * 9);
        bytes calldata split = proof.splitColValues[traceIndex];
        uint256 g0 = _packedFieldAt(split, 0);
        uint256 g1 = _packedFieldAt(split, 1);
        splitValue = addmod(g0, mulmod(_pow(x, ctx.N), g1, P), P);
        bytes calldata aux = proof.auxColValues[traceIndex];
        uint256 batched = mulmod(_pow(x, ctx.N - ctx.b + 1), _packedFieldAt(aux, 2), P);
        batched = addmod(_packedFieldAt(aux, 1), mulmod(ctx.lambda, batched, P), P);
        batched = addmod(mulmod(x, _packedFieldAt(aux, 0), P), mulmod(ctx.lambda, batched, P), P);
        batched = addmod(g1, mulmod(ctx.lambda, batched, P), P);
        layer0Value = addmod(g0, mulmod(ctx.lambda, batched, P), P);
    }

    function _combinePrimary(
        ZKProofRange calldata proof, VerifyCtx memory ctx, uint256 traceIndex, uint256 invOff
    ) internal pure returns (uint256 deep) {
        uint256 numerator = _deepTraceColumns(proof, ctx, traceIndex);
        numerator = addmod(numerator, _deepInterColumnsAtZ(proof, ctx, traceIndex), P);
        numerator = addmod(numerator, _deepAuxAndCp(proof, ctx, traceIndex), P);
        deep = mulmod(numerator, ctx.friInverses[invOff], P);
        bytes calldata interaction = proof.interColValues[traceIndex];
        uint256 zValue = _packedFieldAt(interaction, 17 + 2 * ctx.K);
        uint256 omegaNumerator = mulmod(
            ctx.gZlupOmega, addmod(zValue, P - ctx.oodZlupOmega, P), P
        );
        deep = addmod(deep, mulmod(omegaNumerator, ctx.friInverses[invOff + 1], P), P);
        return addmod(deep, _deepHashOmegaAndShifts(
            proof, ctx, traceIndex, ctx.friInverses[invOff + 1], invOff
        ), P);
    }
}

contract ZKStarkFriPhaseVerifier is ZKStarkUpdateRangeHashCore {
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

    function verifyFriPhase(
        bytes calldata proofData,
        VerifyCtx calldata suppliedCtx,
        uint256[] calldata expectedLayer0,
        uint256[] calldata expectedSplit,
        uint256[] calldata partialDeep
    ) external view returns (bool) {
        ZKProofRange calldata proof = _proofFromBytes(proofData);
        VerifyCtx memory ctx = suppliedCtx;
        if (!_verifyDeferredMerkle(proof, ctx)) return false;
        if (!_verifyDeferredQueries(proof, ctx, expectedSplit, partialDeep)) return false;
        if (!_verifyFriMerklePhase(proof, ctx)) return false;
        return _verifyFriQueriesPhase(proof, ctx, expectedLayer0);
    }

    function _verifyDeferredMerkle(ZKProofRange calldata proof, VerifyCtx memory ctx)
        internal pure returns (bool)
    {
        uint256 capH = _capHeightForLayer(uint256(proof.capHeight), ctx.ldeSize);
        uint256 capSize = uint256(1) << capH;
        if (proof.tracePositions.length == 0) return false;
        if (!_verifyMerkleSingleValueSalted(proof.maskCap, proof.tracePositions, proof.maskValues,
            proof.maskSalts, proof.maskBatchProof, uint256(proof.capHeight), ctx.ldeSize)) return false;
        return _verifyPackedTreePhase(proof.aCap, proof.tracePositions, proof.aColValues,
            proof.aBatchProof, capSize, ctx.ldeSize, ctx.MK + 1);
    }

    function _verifyPackedTreePhase(
        bytes32[] calldata cap,
        uint32[] calldata positions,
        bytes[] calldata values,
        bytes32[] calldata proofPath,
        uint256 capSize,
        uint256 layerSize,
        uint256 width
    ) internal pure returns (bool) {
        uint256 count = positions.length;
        if (cap.length != capSize || values.length != count) return false;
        bytes32[] memory leaves = new bytes32[](count);
        for (uint256 i = 0; i < count; i++) {
            if (values[i].length != width * 16) return false;
            leaves[i] = _hashBundledLeafPacked(values[i], width);
        }
        return _verifyBatch(cap, capSize, layerSize, positions, leaves, proofPath);
    }

    function _verifyDeferredQueries(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx,
        uint256[] calldata expectedSplit,
        uint256[] calldata partialDeep
    ) internal pure returns (bool) {
        uint256 count = proof.queryIndices.length;
        if (expectedSplit.length != count || partialDeep.length != count) return false;
        uint256[] memory denominators = new uint256[](count);
        for (uint256 qi = 0; qi < count; qi++) {
            uint256 i0 = uint256(proof.queryIndices[qi]) % ctx.quarter0;
            uint256 x = mulmod(ctx.cosetGen, _pow(ctx.ldeOmega, i0), P);
            denominators[qi] = addmod(x, P - ctx.z, P);
        }
        uint256[] memory inverses = _batchInv(denominators);
        for (uint256 qi = 0; qi < count; qi++) {
            uint256 i0 = uint256(proof.queryIndices[qi]) % ctx.quarter0;
            (bool found, uint256 traceIndex) = _binarySearch(proof.tracePositions, i0);
            if (!found) return false;
            uint256 deferred = mulmod(_deepAOracle(proof, ctx, traceIndex), inverses[qi], P);
            deferred = addmod(deferred, _packedFieldAt(proof.maskValues, traceIndex), P);
            if (addmod(partialDeep[qi], deferred, P) != expectedSplit[qi]) return false;
        }
        return true;
    }

    function _verifyFriMerklePhase(ZKProofRange calldata proof, VerifyCtx memory ctx)
        internal pure returns (bool)
    {
        uint256 layers = ctx.numFriLayers;
        if (proof.friLayerPositions.length != layers || proof.friLayerValues.length != layers) return false;
        if (proof.friLayerSalts.length != layers || proof.friLayerProofs.length != layers) return false;
        for (uint256 r = 0; r < layers; r++) {
            uint256 layerSize = ctx.ldeSize >> (2 * r);
            if (!_verifyMerkleSingleValueSalted(
                proof.friCaps[r], proof.friLayerPositions[r], proof.friLayerValues[r],
                proof.friLayerSalts[r], proof.friLayerProofs[r], uint256(proof.capHeight), layerSize
            )) return false;
        }
        return true;
    }

    function _verifyFriQueriesPhase(
        ZKProofRange calldata proof,
        VerifyCtx memory ctx,
        uint256[] calldata expectedLayer0
    ) internal pure returns (bool) {
        uint256 queryCount = proof.queryIndices.length;
        uint256 layers = ctx.numFriLayers;
        if (expectedLayer0.length != queryCount) return false;
        uint256[] memory denominators = new uint256[](queryCount * layers);
        ctx.queryPoints = new uint256[](queryCount);
        ctx.inv4 = _inv(FRI_ARITY);
        ctx.mu = _pow(ctx.ldeOmega, ctx.quarter0);
        for (uint256 qi = 0; qi < queryCount; qi++) {
            uint256 query = uint256(proof.queryIndices[qi]);
            uint256 i0 = query % ctx.quarter0;
            uint256 point = mulmod(ctx.cosetGen, _pow(ctx.ldeOmega, i0), P);
            ctx.queryPoints[qi] = point;
            uint256 quarter = ctx.quarter0;
            for (uint256 r = 0; r < layers; r++) {
                uint256 iR = query % quarter;
                denominators[qi * layers + r] = point;
                if (r + 1 < layers) {
                    uint256 nextQuarter = quarter >> 2;
                    point = _friNextPoint(point, iR / nextQuarter, ctx.mu);
                }
                quarter >>= 2;
            }
        }
        ctx.friInverses = _batchInv(denominators);
        ctx.friInvStride = layers;
        for (uint256 qi = 0; qi < queryCount; qi++) {
            uint256 query = uint256(proof.queryIndices[qi]);
            uint256 i0 = query % ctx.quarter0;
            (bool found, uint256 layer0Value) = _lookupFri(proof, 0, i0);
            if (!found || layer0Value != expectedLayer0[qi]) return false;
            if (!_verifyFriFolds(
                proof, ctx, query, ctx.queryPoints[qi], qi * ctx.numFriLayers
            )) return false;
        }
        return true;
    }
}
