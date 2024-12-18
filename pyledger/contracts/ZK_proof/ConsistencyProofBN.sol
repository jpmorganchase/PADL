pragma solidity ^0.8.28;

import "./bn254.sol";
import {BN254} from "./bn254.sol";

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

contract ConsistencyProofBN {
    BN254 bn = new BN254();
    BN254Point s1g;
    BN254Point s2h;
    BN254Point s1gs2h;
    BN254Point t2chal;
    BN254Point s2pk;
    BN254Point chal;
    BN254Point t1ccm;
    bool b1 = true;
    bool b2 = true;
    bool b3 = true;

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

    uint256 gy = 0x20c46e64eb93040ffce510d4fc21d14305a582ec48498a131b22c503abf16232;
    uint256 gx = 0x298c855b781e6bdab88acdcc0a4fed6fa0d89d65a3aebad9ceec83d6b08fca71;

    uint256 hx = 0x01;
    uint256 hy = 0x02;

    BN254Point public g = BN254Point(gx,gy);
    BN254Point public h = BN254Point(hx,hy);

    uint8 pre = 0x04;
    uint32 zerobytes = 0x00;
    uint256 order = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    bytes b;


    /// @dev function to generate a consistency hash by concatenating several variables from a consistencyProofSolR structure, including public key, commitment, token.
    /// @param  prsol is a structure of consistencyProofSolR type that contains various fields.
    function getConsistencyHash(consistencyProofSolR memory prsol) public returns(uint256){
        //b = pushPointToHash(b,gx,gy);
        b = "";
        b = pushPointToHash(b,gx,gy);
        b = pushPointToHash(b,hx,hy);
        b = pushPointToHash(b, prsol.t1.x,prsol.t1.y);
        b = pushPointToHash(b, prsol.t2.x, prsol.t2.y);
        b = pushPointToHash(b ,prsol.pubkey.x, prsol.pubkey.y);
        b = pushPointToHash(b, prsol.cm.x, prsol.cm.y);
        b = pushPointToHash(b, prsol.tk.x, prsol.tk.y);
        //b = closeHash(b);
        //b = abi.encodePacked(b, zerobytes,zerobytes,zerobytes,zerobytes);
        return closeHash(b);
    }

    /// @dev function to creat a compact representation of concatenated data, by appending the provided x and y values to the byte array b, along with a prefix pre.
    /// @param b  is an initial byte variable to which additional data can be concatenated.
    /// @param x  is the first 256-bit unsigned integer to be concatenated.
    /// @param y  is the second 256-bit unsigned integer to be concatenated.
    function pushPointToHash(bytes memory b, uint256 x, uint256 y) public returns(bytes memory) {
        return abi.encodePacked(b, y,x);
    }

    function closeHash(bytes memory b) public returns (uint256){
        return uint256(sha256(abi.encodePacked(b, zerobytes)))  % order;
    }

    function testHash(uint256[14] memory points) public returns(uint256){
        bytes memory bd = "";
        //return uint256(sha256(abi.encodePacked(bd,x,y,zerobytes,zerobytes,zerobytes,zerobytes)));
        for (uint i=0; i <14; i=i+2) {
            bd = pushPointToHash(bd, points[i], points[i+1]);
        }
        return closeHash(bd);
    }

    /// @dev function to verifies the proof of consistency by performing a series of elliptic curve operations and checks.
    /// @param prsol is a structure of consistencyProofSolR type that contains various fields.
    function verify(consistencyProofSolR memory prsol) public returns(bool){

       uint256 hchal = getConsistencyHash(prsol);
       s1g  = bn.mul(g, prsol.s1);

       s2h = bn.mul(h, prsol.s2 );
       s1gs2h = bn.add(s1g, s2h);

       BN254Point memory chal = bn.mul(prsol.cm, prsol.challenge);
       BN254Point memory t1ccm = bn.add(prsol.t1, chal);

       BN254Point memory s2pk = bn.mul(prsol.pubkey, prsol.s2);
       chal = bn.mul( prsol.tk, prsol.challenge);
       BN254Point memory t2chal = bn.add(prsol.t2, chal);

       if (s1gs2h.x==t1ccm.x && s1gs2h.y==t1ccm.y){// && s2pk.x==t2chal.x && s2pk.y==t2chal.y && hchal==prsol.challenge){
           return true;
       }

       return false;
    }
}
