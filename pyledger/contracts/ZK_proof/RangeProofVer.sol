pragma solidity ^0.8.20;

import "./Secp256k.sol";

/// @title Verification for Range proof of transaction
/// @author Applied research, Global Tech., JPMorgan Chase, London
/// @notice This is an code for research and experimentation.

contract RangeProofVer{

    Secp256k public secp = new Secp256k();
    uint256 gx =  g;
    uint8 gpref = preg;
    uint256 hx = GX;
    uint8 hpref = preg;
    uint8 pre = 0x04;
    uint8 zerobytes = 0x00;
    uint256 gy = secp.getY(gpref,gx);
    uint256 hy = secp.getY(hpref,hx);
    bytes b = abi.encodePacked(pre,gx,gy);


    solpoint gd;
    solpoint hd1;
    solpoint cm1c;
    solpoint cm2c;
    solpoint w1;
    solpoint w2;

    struct solpoint{
        uint256 x;
        uint256 y;
    }


    struct rangeProofR{
        solpoint cm;
        dlogEqProofSolR pr1;
        dlogEqProofSolR pr2;
        dlogEqProofSolR pr3;
        dlogEqProofSolR pr4;
    }

    struct dlogEqProofR{
        solpoint cm1;
        solpoint cm2;
        solpoint cm3;
        uint256 challenge;
        uint256 chalRspD;
        uint256 chalRspD1;
        uint256 chalRspD2;
        solpoint chalRspDg;
        solpoint chalRspD1h;
        solpoint challengecm2;
        solpoint chalRspDcm2;
        solpoint chalRspD2h;
        solpoint challengecm3;
    }

    struct dlogEqProofSol{
        solpoint cm1;
        solpoint cm2;
        solpoint cm3;
        uint256 challenge;
        uint256 chalRspD;
        uint256 chalRspD1;
        uint256 chalRspD2;
    }

    struct dlogEqProofSolR{
        solpoint cm1;
        solpoint cm2;
        solpoint cm3;
        uint256 challenge;
        uint256 chalRspD;
        uint256 chalRspD1;
        uint256 chalRspD2;
        solpoint chalRspDg;
        solpoint chalRspD1h;
        solpoint challengecm2;
        solpoint chalRspDcm2;
        solpoint chalRspD2h;
        solpoint challengecm3;
    }
    
    /// @dev function to creat a compact representation of concatenated data, by appending the provided x and y values to the byte array b, along with a prefix pre.
    /// @param b  is an initial byte variable to which additional data can be concatenated.
    /// @param x  is the first 256-bit unsigned integer to be concatenated.
    /// @param y  is the second 256-bit unsigned integer to be concatenated.
    function pushToHash(bytes memory b, uint256 x, uint256 y) public returns(bytes memory) {
        return abi.encodePacked(b,pre,x,y);
    }
      
    /// @dev function to compute intermediate elliptic curve points for a the prrof of positive commitment, by performing scalar multiplications and point additions/subtractions on elliptic curve points.
    /// @param pr is a structure of dlogEqProofSolR type that contains various fields.
    function getW(dlogEqProofSolR memory pr) public returns (bool, solpoint memory, solpoint memory){
        bool b_running = true;
        bool btmp = false;

        (btmp,gd.x, gd.y) = secp.scalMulR(pr.chalRspD, gx, gy, pr.chalRspDg.x, pr.chalRspDg.y);
        b_running = b_running&&btmp;
        (btmp,hd1.x, hd1.y) = secp.scalMulR(pr.chalRspD1, hx, hy, pr.chalRspD1h.x, pr.chalRspD1h.y);
        b_running = b_running&&btmp;
        (btmp,cm1c.x, cm1c.y) = secp.scalMulR(pr.challenge, pr.cm2.x, pr.cm2.y, pr.challengecm2.x, pr.challengecm2.y);
        b_running = b_running&&btmp;
        (uint256 wxx, uint256 wyy) = secp.add(gd.x, gd.y, hd1.x, hd1.y);
        (w1.x, w1.y) = secp.subtract(wxx, wyy, cm1c.x, cm1c.y);

        (btmp,gd.x, gd.y) = secp.scalMulR(pr.chalRspD, pr.cm2.x, pr.cm2.y, pr.chalRspDcm2.x, pr.chalRspDcm2.y);
        b_running = b_running&&btmp;
        (btmp,hd1.x, hd1.y) = secp.scalMulR(pr.chalRspD2, hx, hy, pr.chalRspD2h.x, pr.chalRspD2h.y);
        b_running = b_running&&btmp;
        (btmp,cm1c.x, cm1c.y)  = secp.scalMulR(pr.challenge, pr.cm3.x, pr.cm3.y, pr.challengecm3.x, pr.challengecm3.y);
        b_running = b_running&&btmp;
        (wxx, wyy) = secp.add(gd.x, gd.y, hd1.x, hd1.y);
        (w2.x, w2.y) = secp.subtract(wxx, wyy, cm1c.x, cm1c.y);
        return (b_running, w1, w2);
    }
    
    /// @dev function to verify the discrete logarithm equality proof by computes intermediate points using getW, concatenates them into a byte array, hashes the result, and checks if the hash matches the challenge.
    /// @param prsol is a structure of dlogEqProofSolR type that contains various fields.
    function verifyDlogEqProof(dlogEqProofSolR memory prsol) public returns(bool){
        bool b1= false;
        //dlogEqProofSolR memory prsol = convertDlogEqPy2Sol(pr);
        (b1, w1, w2) = getW(prsol);

        bytes memory b;
        b = pushToHash(b, w1.x, w1.y);
        b = pushToHash(b, w2.x, w2.y);
        b = abi.encodePacked(b, zerobytes,zerobytes,zerobytes,zerobytes);
        if (uint256(sha256(b)) == prsol.challenge && b1) {
            return true;
        }
        return false;
    }

    /// @dev function to check the Proof of positive commitment and return the checking result which is a bool type.
    /// @param rpr is a structure of rangeProofR type that contains various fields.
    function verifyRangeProof(rangeProofR memory rpr) public returns (bool){
        bool a = verifyDlogEqProof(rpr.pr1);
        bool b = verifyDlogEqProof(rpr.pr2);
        bool c = verifyDlogEqProof(rpr.pr3);
        bool d = verifyDlogEqProof(rpr.pr4);


        return (a && b && c && d);
    }

}


