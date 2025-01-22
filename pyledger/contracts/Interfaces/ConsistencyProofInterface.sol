pragma solidity ^0.8.28;

//import "./bn254.sol";
//import {BN254} from "./bn254.sol";
import "../Interfaces/BNInterface.sol";

/// @title For Verification of proof of consistency of transaction
/// @author Applied research, Global Tech., JPMorgan Chase, London
/// @notice This is an code for research and experimentation.

//BN254Point g;
//    g.x = gx;
//    g.y = gy;
//
//BN254Point h
//    h.x = hx;
//    h.y = hy;


struct consistencyProofSolR{
    BN254Point t1;
    BN254Point t2;
    uint256 s1;
    uint256 s2;
    uint256 challenge;
    BN254Point pubkey;
    BN254Point cm;
    BN254Point tk;
    BN254Point chalcm;
    BN254Point chaltk;
    BN254Point s2pubkey;
    BN254Point s1g;
    BN254Point s2h;
}

abstract contract ConsistencyProofInterface {

    function getConsistencyHash(consistencyProofSolR memory prsol) public virtual returns(uint256);
    function pushPointToHash(bytes memory b, uint256 x, uint256 y) public virtual returns(bytes memory);
    function closeHash(bytes memory b) public virtual returns (uint256);
    function verify(consistencyProofSolR memory prsol) public virtual returns(bool);
}