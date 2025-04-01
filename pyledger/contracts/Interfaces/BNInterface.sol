pragma solidity ^0.8.19;
/// @title Verification for proof of equivalence in transaction
/// @author Applied research, Global Tech., JPMorgan Chase, London
/// @notice This is an code for research and experimentation.

struct BN254Point{
    uint256 x;
    uint256 y;
}

abstract contract BNInterface {

    function add(BN254Point calldata point1, BN254Point calldata point2) public view virtual returns (BN254Point memory ret);
    function mul(BN254Point calldata point1, uint256 scalar) public view virtual returns (BN254Point memory ret);
    function neg(BN254Point calldata p) public pure virtual returns (BN254Point memory);
}