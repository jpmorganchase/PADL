pragma solidity ^0.8.20;
/// @title Verification for proof of equivalence in transaction
/// @author Applied research, Global Tech., JPMorgan Chase, London
/// @notice This is an code for research and experimentation.
import "../Interfaces/BNInterface.sol";

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
    function pushPointToHash(bytes memory b, uint256 x, uint256 y) public view virtual returns(bytes memory);
    function closeHash(bytes memory b) public view virtual returns (uint256);
    function verify(consistencyProofSolR memory prsol) public virtual returns(bool);
}