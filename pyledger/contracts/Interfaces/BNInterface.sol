// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

struct BN254Point{
    uint256 x;
    uint256 y;
}

abstract contract BNInterface {

    function add(BN254Point calldata point1, BN254Point calldata point2) public virtual returns (BN254Point memory ret);
    function mul(BN254Point calldata point1, uint256 scalar) public virtual returns (BN254Point memory ret);
    function neg(BN254Point calldata p) public virtual returns (BN254Point memory);
}