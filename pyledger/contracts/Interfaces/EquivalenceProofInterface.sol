pragma solidity ^0.8.20;

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