pragma solidity ^0.8.20;

import "../Interfaces/EquivalenceProofInterface.sol";
import "../Interfaces/RangeProofInterface.sol";
import "../Interfaces/ConsistencyProofInterface.sol";

/// @title A wrapper for verifying proofs including consistency proof, equivalence proof and range proof.
/// @author Applied research, Global Tech., JPMorgan Chase, London
/// @notice This is an code for research and experimentation.

contract ZKProofsBN254{
    address eqaddress;
    address consaddress;
    constructor(address _eqaddress, address _consaddress){
        eqaddress = _eqaddress;
        consaddress = _consaddress;
    }
    EquivalenceProofInterface eqp = EquivalenceProofInterface(eqaddress);
    ConsistencyProofInterface csp = ConsistencyProofInterface(consaddress);

    /// @dev function to retrieve the result of verifying the proof of consistency for transaction
    /// @param pr is a structure of consistencyProofSolR type that contains various fields.
    /// @return  return the result of proof of consistency
    function verifyConsistencyProof(consistencyProofSolR memory pr) public returns (bool){
        return csp.verify(pr);
    }

    /// @dev function to retrieve the result of verifying the proof of equivalence for transaction
    /// @param pr is a structure of eqProofSolR type that contains various fields.
    /// @param h2r is a structure of solpoint type that contains various fields.
    /// @return return the result of proof of eqProofSolR
    function verifyEqProof(eqProofSolR memory pr, BN254Point memory h2r) public returns (bool){
        return eqp.verify(pr, h2r);
    }

}