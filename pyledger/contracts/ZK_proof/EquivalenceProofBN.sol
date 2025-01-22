pragma solidity ^0.8.20;

import "../Interfaces/BNInterface.sol";
import "../Interfaces/EquivalenceProofInterface.sol";

/// @title Verification for proof of equivalence in transaction
/// @author Applied research, Global Tech., JPMorgan Chase, London
/// @notice This is an code for research and experimentation.

contract EquivalenceProofBN is EquivalenceProofInterface{

    BNInterface bn;
    constructor(address _bnaddress){
        bn = BNInterface(_bnaddress);
    }

    uint8 pre = 0x04;
    uint32 zerobytes = 0x00;
    uint256 order = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function pushPointToHash(bytes memory b, uint256 x, uint256 y) public override returns(bytes memory) {
        return abi.encodePacked(b, y,x);
    }

    function closeHash(bytes memory b) public override returns (uint256){
        return uint256(sha256(abi.encodePacked(b, zerobytes)))  % order;
    }
    /// @dev function to generate a challenge hash by concatenating several fields from the eqProofSolR structure and the solpoint point into a byte array, hashes the result, and returns the hash.
    /// @param  prsol is a structure of eqProofSolR type that contains various fields.
    /// @param  h2r  is a structure of solpoint type that x and y coordinates.
    function getChallenge(eqProofSolR memory prsol, BN254Point memory h2r) public override returns (uint256){
        bytes memory b = "";
        b = pushPointToHash(b,prsol.pktrand.x, prsol.pktrand.y);
        b = pushPointToHash(b,h2r.x,h2r.y);
        b = pushPointToHash(b,prsol.pk.x,prsol.pk.y);
        return closeHash(b);
    }


    /// @dev function to verify the prrof of equivalence by computing a challenge hash, performs scalar multiplications and point additions on elliptic curve points, and checks if the resulting point matches the expected point.
    /// @param  prsol is a structure of eqProofSolR type that contains various fields.
    /// @param  h2r is a structure of solpoint type that x and y coordinates.
    function verify(eqProofSolR memory prsol, BN254Point memory h2r) public override returns (bool){

        uint256 challenge = getChallenge(prsol, h2r);
        BN254Point memory first = bn.mul(h2r, prsol.chalrsp);
        BN254Point memory second = bn.mul(prsol.pk, challenge) ;
        BN254Point memory res =  bn.add(first, second);
        if (res.x == prsol.pktrand.x && res.y == prsol.pktrand.y) {
            return true;
        }
        return false;
    }
}

