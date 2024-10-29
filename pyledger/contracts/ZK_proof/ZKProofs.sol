pragma solidity ^0.8.20;

import "./Secp256k.sol";
import "./EquivalenceProof.sol";
import "./ConsistencyProof.sol";
import "./RangeProofVer.sol";

/// @title A wrapper for verifying proofs including consistency proof, equivalence proof and range proof.
/// @author Applied research, Global Tech., JPMorgan Chase, London
/// @notice This is an code for research and experimentation.

contract ZKProofs{

    Secp256k public secp = new Secp256k();
    EquivalenceProof public eqp = new EquivalenceProof();
    ConsistencyProof public csp = new ConsistencyProof();
    RangeProofVer public rpr = new RangeProofVer();
    
    /// @dev function to retrieve the result of verifying the proof of consistency for transaction
    /// @param pr is a structure of consistencyProofSolR type that contains various fields.
    /// @return  return the result of proof of consistency
    function verifyConsistencyProof(ConsistencyProof.consistencyProofSolR memory pr) public returns (bool){
        return csp.processConsistency(pr);
    }

    /// @dev function to retrieve the result of verifying the proof of equivalence for transaction
    /// @param pr is a structure of eqProofSolR type that contains various fields.
    /// @param h2r is a structure of solpoint type that contains various fields.
    /// @return return the result of proof of eqProofSolR
    function verifyEqProof(uint256 sval, EquivalenceProof.eqProofSolR memory pr, EquivalenceProof.solpoint memory h2r) public returns (bool){
        return eqp.verifyEqProof(sval, pr, h2r);
    }

    /// @dev function to retrieve the result of verifying the range proof 
    /// @param pr  is a structure of rangeProofR type that contains various fields.
    /// @return return the result of range proof 
    function verifyRangeProof(RangeProofVer.rangeProofR memory pr) public returns (bool){
        return rpr.verifyRangeProof(pr);
    }

}