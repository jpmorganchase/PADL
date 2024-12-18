pragma solidity ^0.8.20;

import "./EquivalenceProofBN.sol";
import "./ConsistencyProofBN.sol";
import "./RangeVerifier.sol";

/// @title A wrapper for verifying proofs including consistency proof, equivalence proof and range proof.
/// @author Applied research, Global Tech., JPMorgan Chase, London
/// @notice This is an code for research and experimentation.

contract ZKProofsBN254{
    EquivalenceProofBN public eqp = new EquivalenceProofBN();
    ConsistencyProofBN public csp = new ConsistencyProofBN();
   // RangeProofVer public rpr = new RangeProofVer();
    
    /// @dev function to retrieve the result of verifying the proof of consistency for transaction
    /// @param pr is a structure of consistencyProofSolR type that contains various fields.
    /// @return  return the result of proof of consistency
    function verifyConsistencyProof(ConsistencyProofBN.consistencyProofSolR memory pr) public returns (bool){
        return csp.verify(pr);
    }

    /// @dev function to retrieve the result of verifying the proof of equivalence for transaction
    /// @param pr is a structure of eqProofSolR type that contains various fields.
    /// @param h2r is a structure of solpoint type that contains various fields.
    /// @return return the result of proof of eqProofSolR
    function verifyEqProof(EquivalenceProofBN.eqProofSolR memory pr, BN254Point memory h2r) public returns (bool){
        return eqp.verify(pr, h2r);
    }

    /// @dev function to retrieve the result of verifying the range proof 
    /// @param pr  is a structure of rangeProofR type that contains various fields.
    /// @return return the result of range proof 
//    function verifyRangeProof(RangeProofVer.rangeProofR memory pr) public returns (bool){
//        return rpr.verifyRangeProof(pr);
//    }

}