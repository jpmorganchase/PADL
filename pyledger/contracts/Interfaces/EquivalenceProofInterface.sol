pragma solidity ^0.8.28;
/// @title Verification for proof of equivalence in transaction
/// @author Applied research, Global Tech., JPMorgan Chase, London
/// @notice This is an code for research and experimentation.
import "../Interfaces/BNInterface.sol";
import "../Interfaces/EquivalenceProofInterface.sol";

struct eqProofSolR{
    BN254Point pk;
    BN254Point pktrand;
    uint256 chalrsp;
}

abstract contract EquivalenceProofInterface {

    function pushPointToHash(bytes memory b, uint256 x, uint256 y) public virtual returns(bytes memory);
    function closeHash(bytes memory b) public virtual returns (uint256);
    function getChallenge(eqProofSolR memory prsol, BN254Point memory h2r) public virtual returns (uint256);
    function verify(eqProofSolR memory prsol, BN254Point memory h2r) public virtual  returns (bool);

}