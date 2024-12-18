// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

struct BN254Point{
    uint256 x;
    uint256 y;
}

contract BN254 {

    function add(BN254Point calldata point1, BN254Point calldata point2) public returns (BN254Point memory ret){
        uint256[4] memory data=[point1.x,point1.y,point2.x,point2.y];
        // bytes memory data = abi.encodePacked(point1.x,point1.y,point2.x,point2.y);
        bool success;

        assembly{
            // 0x6 is BNG1 Add, 0x80 128 bytes
            success := staticcall(500000, 6, data, 0x80, ret, 0x40)
        }
        return ret;
    }

    function mul(BN254Point calldata point1, uint256 scalar) public returns (BN254Point memory ret){
        uint256[3] memory data= [point1.x, point1.y, scalar];
        // bytes memory data = abi.encodePacked(point1.x,point1.y,point2.x,point2.y);
        bool success;

        assembly{
            // 0x7 is BNG1 scalarmul
            success := staticcall(500000, 7, data, 0x60, ret, 0x40)
        }
        return ret;
    }

    function neg(BN254Point calldata p) public returns (BN254Point memory) {
        if (p.x == 0 && p.y == 0)
            return BN254Point(0, 0);
        uint256 n = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        return  BN254Point(p.x, n - p.y);
    }
}