/// @title Private and auditable transaction via on-chain verification
/// @author Applied research, Global Tech., JPMorgan Chase, London
/// @notice This is an code for research and experimentation.
pragma solidity ^0.8.20;

import "../ZK_proof/bn254.sol";
import {Bulletproof} from "../ZK_proof/RangeVerifier.sol";
import {ConsistencyProofBN} from "../ZK_proof/ConsistencyProofBN.sol";
import {EquivalenceProofBN} from "../ZK_proof/EquivalenceProofBN.sol";
import {Rangeproof} from "../ZK_proof/RangeVerifier.sol";


abstract contract PADLOnChainInterface {
    struct cmtk {
        BN254Point cm;
        BN254Point tk;
    }

    struct txcell {
        BN254Point cm;
        BN254Point tk;
        BN254Point compcm;
        BN254Point comptk;
        EquivalenceProofBN.eqProofSolR peq;
        ConsistencyProofBN.consistencyProofSolR pc;
        ConsistencyProofBN.consistencyProofSolR pc_;
        Rangeproof ppositive;
    }

    function isPermitted(address _add) public virtual returns (bool);
    function addRequests(address _add, string memory _zl, uint _amt) public virtual;
    function addParticipant(address _add) public virtual;
    function getTotalBalance() public virtual view returns (uint);
    function retrieveParticipant(uint i) public virtual view returns (address);
    function retrieveNumberOfParticipants() public virtual view returns (uint);
    function storePublicKey(string memory _pk, address _add) public virtual;
    function retrievePk(address _add) public virtual view returns (string memory);
    function retrieveAllPks() public virtual view returns (string memory);
    function retrieveZeroLine(address _add) public virtual view returns (string memory);
    function addZeroLine(string memory _zl, address _add) public virtual;
    function retrieveTxnLength() public virtual view returns(uint) ;
    function storeIntCMTK(cmtk[][] memory _p) public virtual;
    function addstorageidentifier(string memory _idnt) public virtual;
    function retrieveCommitsTokens() public virtual returns(cmtk[][] memory);
    function retrieveIdentifier() public virtual returns(string memory);
    function voteTxn() public virtual;
    function checkTxnApproval() public virtual returns(bool);
    function resetVotes() public virtual;
    function updateState() public virtual;
    function approveTxn() public virtual;
    function approveTxnIssuer() virtual public ;
    function clearTxn() public virtual;
    function retrieveTxn(uint i) public virtual returns(string memory);
    function setGovRules(string memory gov) virtual public ;
    function retrieveGovarnenceRules() public virtual returns(string memory);
    function addZeroLineToState(cmtk [] memory zls) public virtual;
    function retrieveStateId(uint256 p) public virtual returns (cmtk[] memory);
    function processTx(txcell[] memory ctx, uint256 asset_id) public virtual returns (bool);
    function checkSenderCell(txcell memory ctxid, address add, BN254Point memory h2rd) public virtual returns (bool);
    function checkReceiverCell(txcell memory ctx) public virtual returns (bool);

}