// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
/// @title Verification for proof of equivalence in transaction
/// @author Applied research, Global Tech., JPMorgan Chase, London
/// @notice This is an code for research and experimentation.
//import "./bn254.sol";
import  "../Interfaces/BNInterface.sol";
//import {BN254} from "./bn254.sol";

struct Rangeproof{
    BN254Point A;
    BN254Point S;
    BN254Point T1;
    BN254Point T2;
    uint256 tau_x;
    uint256 miu;
    uint256 tx;
    uint256 a_tag;
    uint256 b_tag;
    BN254Point G;
    BN254Point H;
    BN254Point Com;
    BN254Point[5] L;
    BN254Point[5] R;
    BN254Point[32] g_vec;
    BN254Point[32] h_vec;
    // BN254Point[32] yi_vec;
}

abstract contract RangeProofInterface {
    function verify_range_proof(Rangeproof calldata proof) public virtual returns (bool);
}