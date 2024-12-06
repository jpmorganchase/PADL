/// @title Private and auditable transaction via on-chain verification
/// @author Applied research, Global Tech., JPMorgan Chase, London
/// @notice This is an code for research and experimentation.
pragma solidity ^0.8.20;

import "./bn254.sol";
import {Bulletproof} from "./Bulletproof.sol";
import {ConsistencyProofBN} from "./ConsistencyProofBN.sol";
import {EquivalenceProofBN} from "./EquivalenceProofBN.sol";
//import "./ZK_proof/RangeProofVer.sol";

contract PADLOnChainBN {
    struct cmtk {
        BN254Point cm;
        BN254Point tk;
    }
    uint8 public constant totalAsset= 8;
    uint8 public constant default_asset_id = 0;
    cmtk[] public cur_asset_commits_tokens;

    uint256 constant gy = 0x211f2c237d907e6e11073f667fb026085665bb1ba108518ddd23bebfbe896ca5;
    uint256 constant gx = 0x2f9fb7e98cc14aced65e3f4e0871e0a012a699c8f474e2286fce8b97adfad91a;
    uint256 constant hx = 0x1;
    uint256 constant hy = 0x2;

    address Issuer;
    uint256 totalSupply;
    mapping(address => cmtk[]) state; // state of the contract
    mapping(address => cmtk[]) tempzl;
    mapping(address => uint256) allids;
    address[] public allParticipants;
    txcell[] public currenttx;
    BN254Point public newcm;
    BN254Point public newtk;
    BN254Point public sumcm;
    BN254Point public sumtk;
    BN254Point public tempcm;
    BN254Point public updatedstatecm;
    BN254Point public updatedstatetk;
    string public identifier;

    cmtk[] public intzl;
    uint256 public sval = 10;

    cmtk cmtk_temp;
    mapping(address => cmtk) public zlnotuseful;
    mapping(address => string) public zl; // replace zero line to array of ecpoints
    mapping(address => string) public reqs;
    mapping(address => uint) public reqs_amounts;
    mapping(address => bool) public txnApproval;
    mapping(address => string) public zkledgerPks;
    mapping(address => bool) public participants;

    cmtk[][] public commitsTokens;
    bool public majorityvotes;
    string[] public ledger; // ledger will arrays of hashes
    //uint256 public constant g = 0xe4c9192893d7a85eb9793f8748e258e1184448f8092bcdd8b77c9403b65495ce;
    uint8 public constant preg = 0x2;
    string public gov_rules='';

    constructor() {
        Issuer = msg.sender;
        totalSupply = 10;
    }

    /// @dev modifier for functionalities only available to Issuer
    modifier onlyByIssuer{
        require(msg.sender == Issuer, "Only Issuer can add participants");
        _;
    }

    /// @dev modifier for functionalities only available to Participants
    modifier onlyByParticipants{
        require(isPermitted(msg.sender), "Only participants can make txns");
        _;
    }

    BN254 public bn = new BN254();
    EquivalenceProofBN public eqp = new EquivalenceProofBN();
    ConsistencyProofBN public csp = new ConsistencyProofBN();
    Bulletproof public rng = new Bulletproof();
    BN254Point public h2r;

    /// @dev PADL transaction structure consists of a commitment, token, complimentary commitment, complimentary token,
    /// @dev proof of positive commitment, range proof, equivalence proof.
    struct txcell {
        BN254Point cm;
        BN254Point tk;
        BN254Point compcm;
        BN254Point comptk;
        EquivalenceProofBN.eqProofSolR peq;
        ConsistencyProofBN.consistencyProofSolR pc;
        ConsistencyProofBN.consistencyProofSolR pc_;
        Bulletproof.Rangeproof ppositive;
    }

    function isPermitted(address _add) public returns (bool){
        return participants[_add];
    }

        /// @dev function to add initial commit-token (also called zeroline) for a new participant
    /// @param _add ethereum address of participant
    /// @param _zl zero line
    /// @param _amt amount of coins minted (initial balance)
    function addRequests(address _add, string memory _zl, uint _amt) public onlyByIssuer {
        reqs[_add] = _zl;
        reqs_amounts[_add] = _amt;
    }

    /// @dev function to add a participant to contract. Gives access to the functionalities of the contract
    /// @param _add ethereum address of participant
    function addParticipant(address _add) public onlyByIssuer {
        participants[_add] = true;
        txnApproval[_add] = false;
        allParticipants.push(_add);
        allids[_add] = allParticipants.length - 1;
    }

    /// @dev function to find balance deposited in the contract
    /// @return returns balance deposited in the contract
    function getTotalBalance() public view returns (uint) {
        return address(this).balance;
    }

    /// @dev function to retrieve participant by id or index
    /// @param i integer corresponding to participants id or index
    /// @return address of participant corresponding to i
    function retrieveParticipant(uint i) public view returns (address){
        return allParticipants[i];
    }

    /// @dev function to retrieve total number of participants
    /// @return number of participants
    function retrieveNumberOfParticipants() public view returns (uint){
        return allParticipants.length;
    }

    /// @dev function to store participants PADL public key on the contract
    /// @param _pk public key of participant
    /// @param _add ethereum address of participant
    function storePublicKey(string memory _pk, address _add) public {
        zkledgerPks[_add] = _pk;
    }

    /// @dev function to retrieve PADL public key of a participant
    /// @param _add participant's ehtereum address
    /// @return public key of participant with address _add
    function retrievePk(address _add) public view returns (string memory){
        return zkledgerPks[_add];
    }

    /// @dev function to retrieve public key of all participants
    /// @return all PADL public keys
    function retrieveAllPks() public view returns (string memory){
        if (allParticipants.length == 0)
        {
            return "";
        }
        string memory all_pks = zkledgerPks[allParticipants[0]];
        for (uint256 i = 1; i < allParticipants.length; i++) {
            all_pks = string.concat(all_pks, " ", zkledgerPks[allParticipants[i]]);
        }
        return all_pks;
    }

    /// @dev function to retrieve zero line corresponding to address of a participant
    /// @param _add ethereum address
    /// @return returns zero line corresponding to ethereum address _add
    function retrieveZeroLine(address _add) public view returns (string memory){
        return zl[_add];
    }

    /// @dev function to add zero line for a participant
    /// @param _zl zero line in string format
    /// @param _add ethereum address
    function addZeroLine(string memory _zl, address _add) public {
        zl[_add] = _zl;
    }

    function retrieveTxnLength() public view returns(uint){
        return ledger.length;
    }

        function storeIntCMTK(cmtk[][] memory _p) public{
        delete commitsTokens;
        for (uint256 temp_asset_index = 0; temp_asset_index < _p.length; temp_asset_index++){

            commitsTokens.push();
            for (uint256 p = 0; p < _p[0].length; p++){

                cmtk_temp.cm.x = _p[temp_asset_index][p].cm.x;
                cmtk_temp.cm.y = _p[temp_asset_index][p].cm.y;
                cmtk_temp.tk.x = _p[temp_asset_index][p].tk.x;
                cmtk_temp.tk.y = _p[temp_asset_index][p].tk.y;
                commitsTokens[commitsTokens.length-1].push(cmtk_temp);

            }
        }
    }

    function addstorageidentifier(string memory _idnt) public{
        identifier = _idnt;
    }


    function retrieveCommitsTokens() public view returns(cmtk[][] memory){
        return commitsTokens;
    }

    function retrieveIdentifier() public view returns(string memory){
        return identifier;
    }

    function voteTxn() public onlyByParticipants{
        txnApproval[msg.sender] = true;
    }

    function checkTxnApproval() public returns(bool){
        uint256 votescount = 0;
        for(uint256 i = 0; i<allParticipants.length; i++){
            address addr = allParticipants[i];
            if (txnApproval[addr]) {
            votescount = votescount + 1;
            }
        }
        if (votescount > (allParticipants.length - 1)){
            majorityvotes = true;
        }
        else{
            majorityvotes = false;
        }
        return majorityvotes;
    }
    function resetVotes() public{
        for(uint256 i=0; i<allParticipants.length;i++){
            address addr = allParticipants[i];
            txnApproval[addr] = false;
        }
    }

    function updateState() public{
        for (uint256 _loop_asset_id = 0; _loop_asset_id < commitsTokens.length; _loop_asset_id++) {
            for (uint256 p = 0; p < allParticipants.length; p++) {

                updatedstatecm = bn.add(commitsTokens[_loop_asset_id][p].cm, state[allParticipants[p]][_loop_asset_id].cm);
                updatedstatetk = bn.add(commitsTokens[_loop_asset_id][p].tk, state[allParticipants[p]][_loop_asset_id].tk);

                state[allParticipants[p]][_loop_asset_id].cm = updatedstatecm;
                state[allParticipants[p]][_loop_asset_id].tk = updatedstatetk;

            }
        }
        delete commitsTokens;
    }

    function approveTxn() public onlyByParticipants{
        bool a = checkTxnApproval();
        if (majorityvotes){
            ledger.push(identifier);

            updateState();
            clearTxn();
        }
    }
    function approveTxnIssuer() virtual public onlyByIssuer {
        ledger.push(identifier);
        clearTxn();
        updateState();
    }
    function clearTxn() public{
        // delete txn;
    }
    function retrieveTxn(uint i) public view returns(string memory){
        // require(i < ledger.length, "Index out of bounds of ledger length");
        return ledger[i];
    }

    function setGovRules(string memory gov) virtual public onlyByIssuer{
        gov_rules = gov;
    }
    function retrieveGovarnenceRules() public view returns(string memory){
        return gov_rules;
    }



    /// @dev function to store zero line in a temporary mapping that is later changed to state once the deposit is received
    /// @param zls commitment-token tuple
    function addZeroLineToState(cmtk [] memory zls) public {
         //tempzl[msg.sender] = zls;
         for (uint256 index=0;index<zls.length;index++){
             state[msg.sender].push(zls[index]);
         }
    }

    /// @dev function to retrieve state of a participant
    /// @param p participant id
    /// @return state of a participant on the contract (commitment-token tuple)
    function retrieveStateId(uint256 p) public returns (cmtk[] memory){
        return (state[allParticipants[p]]);
    }

    function processTxn(txcell[] memory ctx) public returns (bool){
        BN254Point memory res = bn.add(ctx[0].cm, ctx[1].cm);
        //bool bal = (res.x == 0) && (res.y == 0);
        //bool bal = csp.processConsistency(ctx[1].pc);
        bool bal = rng.verify_range_proof(ctx[0].ppositive);
        return bal;
    }


}
