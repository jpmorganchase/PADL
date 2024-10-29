pragma solidity ^0.8.20;

import "./Secp256k.sol";

/// @title Verification for proof of equivalence in transaction
/// @author Applied research, Global Tech., JPMorgan Chase, London
/// @notice This is an code for research and experimentation.

contract EquivalenceProof{

    Secp256k public secp = new Secp256k();
    uint8 pre = 0x04;
    uint8 zerobytes = 0x00;

    struct solpoint{
        uint256 x;
        uint256 y;
    }

      struct eqProofSolR{
        solpoint pk;
        solpoint pktrand;
        uint256 chalrsp;
        solpoint chalrsph2r;
        solpoint challengepk;
    }
    
    /// @dev function to creat a compact representation of concatenated data, by appending the provided x and y values to the byte array b, along with a prefix pre.
    /// @param b  is an initial byte variable to which additional data can be concatenated.
    /// @param x  is the first 256-bit unsigned integer to be concatenated.
    /// @param y  is the second 256-bit unsigned integer to be concatenated.
    function pushToHash(bytes memory b, uint256 x, uint256 y) public returns(bytes memory) {
        return abi.encodePacked(b,pre,x,y);
    }

    /// @dev function to generate a challenge hash by concatenating several fields from the eqProofSolR structure and the solpoint point into a byte array, hashes the result, and returns the hash.
    /// @param  prsol is a structure of eqProofSolR type that contains various fields.
    /// @param  h2r  is a structure of solpoint type that x and y coordinates.
    function getChallenge(eqProofSolR memory prsol, solpoint memory h2r) public returns (uint256){
        bytes memory b;
        b = pushToHash(b,prsol.pktrand.x, prsol.pktrand.y);
        b = pushToHash(b,h2r.x,h2r.y);
        b = pushToHash(b,prsol.pk.x,prsol.pk.y);
        b = abi.encodePacked(b, zerobytes,zerobytes,zerobytes,zerobytes);
        return uint256(sha256(b));
    }

    /// @dev function to verify the prrof of equivalence by computing a challenge hash, performs scalar multiplications and point additions on elliptic curve points, and checks if the resulting point matches the expected point.
    /// @param  prsol is a structure of eqProofSolR type that contains various fields.
    /// @param  h2r is a structure of solpoint type that x and y coordinates.    
    function verifyEqProof(uint256 sval, eqProofSolR memory prsol, solpoint memory h2r) public returns (bool){

        uint256 challenge = getChallenge(prsol, h2r);
        (bool b1, uint256 firstx,uint256 firsty) = secp.scalMulR(prsol.chalrsp, h2r.x,h2r.y, prsol.chalrsph2r.x, prsol.chalrsph2r.y);
        (bool b2, uint256 secondx,uint256 secondy) = secp.scalMulR(challenge, prsol.pk.x, prsol.pk.y, prsol.challengepk.x,prsol.challengepk.y);
        (uint256 resx, uint resy) =  secp.add(firstx, firsty, secondx,secondy);
        if (resx == prsol.pktrand.x && resy == prsol.pktrand.y && b1 && b2) {
            return true;
        }
        return false;
    }
}

