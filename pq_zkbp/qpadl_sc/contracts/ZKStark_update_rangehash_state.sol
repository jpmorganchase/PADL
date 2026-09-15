pragma solidity ^0.8.26;

import "./ZKStark_update_rangehash.sol";

interface IZKStarkUpdateRangeHashVerifier {
    function verifyZKNttMatVecRangeHashMsg(
        bytes calldata proofData,
        bytes calldata cVecPacked,
        bytes32 aOracleHashExpected
    ) external view returns (bool);
}

contract ZKStarkRangeHashState {

    error InvalidVerifier();
    error NotAdmin();
    error TokenNotFound();
    error ProofRejected();
    error RecipientNotRegistered();
    error NoPendingEnc();

    struct TokenEntry {
        uint256 h0;       // H(M)[0] — Rescue output lane 0
        uint256 h1;       // H(M)[1] — Rescue output lane 1
    }

    address private immutable _stateAdmin;
    IZKStarkUpdateRangeHashVerifier private immutable _verifier;

    // address → dynamic array of token entries
    mapping(address => TokenEntry[]) private _tokens;

    // Per-recipient commitment key: A-oracle hash of A_R = [A_sis ; B_R ; B'_R]
    // and the raw B, B' rows (for senders to fetch and rebuild A_R).
    mapping(address => bytes32) public aHashOf;
    mapping(address => bytes) public pubKeyB;

    // token_s entries flagged by a successful `processTransfer`, awaiting their
    // (unverified) ciphertext blob via `attachSenderEncData`.
    mapping(bytes32 => bool) private _pendingEnc;

    event PubKeyRegistered(address indexed owner, bytes32 aHash);
    event TokenAdded(address indexed owner, uint256 h0, uint256 h1);
    event TokenRemoved(address indexed owner, uint256 h0, uint256 h1);
    event TransferProcessed(address indexed sender, uint256 tokenOH0, uint256 tokenOH1);
    // Ciphertext is emitted (not stored) so it can be recovered off-chain.
    event TokenEncData(address indexed owner, uint256 h0, uint256 h1, bytes encData);

    constructor(address verifier_) {
        if (verifier_ == address(0) || verifier_.code.length == 0) revert InvalidVerifier();
        _stateAdmin = msg.sender;
        _verifier = IZKStarkUpdateRangeHashVerifier(verifier_);
    }

    /// @notice Register the caller's lattice commitment key: `aHash` is the
    ///         A-oracle hash of A_R (shared A_sis + the caller's B, B' rows);
    ///         `bRows` are the raw B, B' rows so senders can rebuild A_R.
    function registerPubKey(bytes32 aHash, bytes calldata bRows) external {
        aHashOf[msg.sender] = aHash;
        pubKeyB[msg.sender] = bRows;
        emit PubKeyRegistered(msg.sender, aHash);
    }

    function preissue(
        address owner, uint256 h0, uint256 h1, bytes calldata enc
    ) external {
        if (msg.sender != _stateAdmin) revert NotAdmin();
        // Ciphertext (lattice commitment) is emitted, not stored.
        _tokens[owner].push(TokenEntry(h0, h1));
        emit TokenAdded(owner, h0, h1);
        emit TokenEncData(owner, h0, h1, enc);
    }

    function processTransfer(
        bytes calldata proofData,
        bytes calldata cVecPacked,
        address recipient
    ) external {
        bytes32 rHash = aHashOf[recipient];
        if (rHash == bytes32(0)) revert RecipientNotRegistered();
        if (!_verifier.verifyZKNttMatVecRangeHashMsg(proofData, cVecPacked, rHash)) {
            revert ProofRejected();
        }

        ZKStarkUpdateRangeHashVerifier.ZKProofRange calldata proof;
        assembly ("memory-safe") { proof := add(proofData.offset, 32) }
        uint256 toH0 = proof.tokenO[0]; // original balance (consumed)
        uint256 toH1 = proof.tokenO[1];
        uint256 tsH0 = proof.tokenS[0]; // sender remaining
        uint256 tsH1 = proof.tokenS[1];
        uint256 tmH0 = proof.tokenM[0]; // transfer amount
        uint256 tmH1 = proof.tokenM[1];

        // Remove token_o from sender
        _removeToken(msg.sender, toH0, toH1);

        // Add token_s (sender remaining balance) — ciphertext emitted, not stored.
        // Its (unverified) blob is supplied separately via `attachSenderEncData`,
        // gated on this flag so it can't be emitted without a successful verify.
        _tokens[msg.sender].push(TokenEntry(tsH0, tsH1));
        emit TokenAdded(msg.sender, tsH0, tsH1);
        _pendingEnc[_encKey(msg.sender, tsH0, tsH1)] = true;

        // Add token_m (transfer amount) to recipient — its ciphertext IS the
        // transfer commitment cVecPacked, which the recipient extracts off-chain.
        _tokens[recipient].push(TokenEntry(tmH0, tmH1));
        emit TokenAdded(recipient, tmH0, tmH1);

        emit TransferProcessed(msg.sender, toH0, toH1);
    }

    function attachSenderEncData(uint256 h0, uint256 h1, bytes calldata enc) external {
        bytes32 key = _encKey(msg.sender, h0, h1);
        if (!_pendingEnc[key]) revert NoPendingEnc();
        delete _pendingEnc[key];
        emit TokenEncData(msg.sender, h0, h1, enc);
    }

    function _encKey(address owner, uint256 h0, uint256 h1) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(owner, h0, h1));
    }

    function tokenCount(address owner) external view returns (uint256) {
        return _tokens[owner].length;
    }

    function getToken(address owner, uint256 idx)
        external view returns (uint256 h0, uint256 h1)
    {
        TokenEntry storage e = _tokens[owner][idx];
        return (e.h0, e.h1);
    }

    function _removeToken(address owner, uint256 h0, uint256 h1) internal {
        TokenEntry[] storage arr = _tokens[owner];
        uint256 n = arr.length;
        for (uint256 i = 0; i < n; i++) {
            if (arr[i].h0 == h0 && arr[i].h1 == h1) {
                // Swap with last and pop
                arr[i] = arr[n - 1];
                arr.pop();
                emit TokenRemoved(owner, h0, h1);
                return;
            }
        }
        revert TokenNotFound();
    }
}
