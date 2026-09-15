pragma solidity ^0.8.26;

/// @dev Immutable bytecode container for the 480 Rescue-Prime parameters.
///      Runtime layout: one STOP byte followed by 480 canonical uint256 words.
contract RescueParamsData {
    error BadRescueParams();

    uint256 private constant PARAM_BYTES = 480 * 32;
    bytes32 private constant PARAMS_HASH =
        0x6028ed518a9cb36421a5dab2193a686cb4a0d708d4f1a47fa80d671a7b5f2d74;

    constructor(bytes memory params) {
        if (params.length != PARAM_BYTES || keccak256(params) != PARAMS_HASH) {
            revert BadRescueParams();
        }

        bytes memory runtime = new bytes(PARAM_BYTES + 1);
        assembly ("memory-safe") {
            let source := add(params, 32)
            let destination := add(runtime, 33)
            mcopy(destination, source, PARAM_BYTES)
            return(add(runtime, 32), add(PARAM_BYTES, 1))
        }
    }
}