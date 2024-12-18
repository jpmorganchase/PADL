/// @title Private and auditable transaction via on-chain verification
/// @author Applied research, Global Tech., JPMorgan Chase, London
/// @notice This is an code for research and experimentation.
pragma solidity ^0.8.0;

import "./ZK_proof/Secp256k.sol";
import "./ZK_proof/ZKProofs.sol";
import "./ZK_proof/EquivalenceProof.sol";
import "./ZK_proof/ConsistencyProof.sol";
import "./ZK_proof/RangeProofVer.sol";

contract PADLOnChain {
    uint8 public constant totalAsset= 8;
    uint8 public constant default_asset_id = 0;
    cmtk[] public cur_asset_commits_tokens;

    address Issuer;
    uint256 totalSupply;
    mapping(address => cmtk[]) state; // state of the contract
    mapping(address => cmtk[]) tempzl;
    mapping(address => uint256) allids;
    address[] public allParticipants;
    txcell[] public currenttx;
    ecpointxy public newcm;
    ecpointxy public newtk;
    ecpointxy public sumcm;
    ecpointxy public sumtk;
    ecpointxy public tempcm;
    ecpointxy public updatedstatecm;
    ecpointxy public updatedstatetk;
    string public identifier;
    //ecpointxy public h2r;
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
    uint256 public constant g = 0xe4c9192893d7a85eb9793f8748e258e1184448f8092bcdd8b77c9403b65495ce;
    uint8 public constant preg = 0x2;
    string public gov_rules='';


    Secp256k public secp = new Secp256k();
    ZKProofs public zkp = new ZKProofs();
    EquivalenceProof public eqp = new EquivalenceProof();
    ConsistencyProof public csp = new ConsistencyProof();
    RangeProofVer public rng = new RangeProofVer();
    EquivalenceProof.solpoint public h2r;

    /// @dev totalSupply Maybe used later to regulate minting of PADL coin..
    /// @dev Issuer=msg.sender makes sets the issuer to make sure only Issuer can add more participants
    /// @param _totalSupply The total number of PADL coin issuer wold like to eventually issue
    constructor(uint256 _totalSupply) {
        Issuer = msg.sender;
        totalSupply = _totalSupply;
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



    /// @dev (xy) tuple for a point on elliptic curve
    struct ecpointxy {
        uint256 x;
        uint256 y;
    }

    /// @dev (commitment-token tuple): a commitment and a token (each) is a point on elliptic curve
    struct cmtk {
        ecpointxy cm;
        ecpointxy tk;
    }

    /// @dev PADL transaction structure consists of a commitment, token, complimentary commitment, complimentary token,
    /// @dev proof of positive commitment, range proof, equivalence proof.
    struct txcell {
        ecpointxy cm;
        ecpointxy tk;
        ecpointxy compcm;
        ecpointxy comptk;
        RangeProofVer.rangeProofR ppositive;
        ConsistencyProof.consistencyProofSolR pc;
        EquivalenceProof.eqProofSolR peq;
        ConsistencyProof.consistencyProofSolR pc_;
    }

///  COMMON FUNCTIONS ///////////////////////////

    /// @dev function to add participants that are permitted to access SC functionalities
    /// @param _add ethereum address
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
    function checkadd() public{
        (updatedstatecm.x, updatedstatecm.y) = secp.add(commitsTokens[0][0].cm.x, commitsTokens[0][0].cm.y, state[allParticipants[0]][0].cm.x, state[allParticipants[0]][0].cm.y);
        for (uint256 i =0; i < 100; i++) {
            (updatedstatecm.x, updatedstatecm.y) = secp.add(updatedstatecm.x, updatedstatecm.y, updatedstatecm.x, updatedstatecm.y);
        }
    }
    function updateState() public{
        for (uint256 _loop_asset_id = 0; _loop_asset_id < commitsTokens.length; _loop_asset_id++) {
            for (uint256 p = 0; p < allParticipants.length; p++) {

                (updatedstatecm.x, updatedstatecm.y) = secp.add(commitsTokens[_loop_asset_id][p].cm.x, commitsTokens[_loop_asset_id][p].cm.y, state[allParticipants[p]][_loop_asset_id].cm.x, state[allParticipants[p]][_loop_asset_id].cm.y);
                (updatedstatetk.x, updatedstatetk.y) = secp.add(commitsTokens[_loop_asset_id][p].tk.x, commitsTokens[_loop_asset_id][p].tk.y, state[allParticipants[p]][_loop_asset_id].tk.x, state[allParticipants[p]][_loop_asset_id].tk.y);
                
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


/////////////////////////////////////////////////////////////////////////////////////////
    function processTx(txcell[] memory ctx) public onlyByParticipants returns (bool) {
        return processTx(ctx,0);
    }
    /// @dev function to verify a transaction and update the state if the transaction is valid
    /// @param ctx current transaction with structure same as defined above
    /// @return true if transaction was correctly validated and updates the state before returning
    function processTx(txcell[] memory ctx, uint256 asset_id) public onlyByParticipants returns (bool) {
        require(ctx.length == allParticipants.length, "Length of transaction not equal to length of participants");

        // proof of balance across all participants
        tempcm = ctx[0].cm;
        for (uint256 p = 1; p < allParticipants.length; p++) {
            (tempcm.x, tempcm.y) = secp.add(ctx[p].cm.x, ctx[p].cm.y, tempcm.x, tempcm.y);
        }
        require((tempcm.x == 0 && tempcm.y == 0), 'Proof of balance failed');

        // Proof of asset
        uint256 id = allids[msg.sender];
        (tempcm.x, tempcm.y) = secp.add(state[allParticipants[id]][asset_id].cm.x, state[allParticipants[id]][asset_id].cm.y, ctx[id].cm.x, ctx[id].cm.y);
        (h2r.x, h2r.y) = secp.subtract(tempcm.x, tempcm.y, ctx[id].compcm.x, ctx[id].compcm.y);
        require(zkp.verifyEqProof(sval, ctx[id].peq, h2r), 'Proof of asset failed');
        //processSenderCell(ctx[id], id);

        // Proof of positive commitment and proof of consistency
        for (uint256 p = 0; p < allParticipants.length; p++) {
            if (p != id){ // everyone? SE
            // first check if commitment in range proof sums up to main commitment
                (tempcm.x, tempcm.y) = (ctx[p].ppositive.pr1.cm1.x, ctx[p].ppositive.pr1.cm1.y);
                (tempcm.x, tempcm.y) = secp.add(tempcm.x, tempcm.y, ctx[p].ppositive.pr2.cm1.x, ctx[p].ppositive.pr2.cm1.y);
                (tempcm.x, tempcm.y) = secp.add(tempcm.x, tempcm.y, ctx[p].ppositive.pr3.cm1.x, ctx[p].ppositive.pr3.cm1.y);
                (tempcm.x, tempcm.y) = secp.add(tempcm.x, tempcm.y, ctx[p].ppositive.pr4.cm1.x, ctx[p].ppositive.pr4.cm1.y);
                require((tempcm.x == ctx[p].cm.x && tempcm.y == ctx[p].cm.y), "Commitment sum in range proof does not match main commitment");
                require(zkp.verifyRangeProof(ctx[p].ppositive), 'Proof of positive commitment failed');
                require(zkp.verifyConsistencyProof(ctx[p].pc), 'Proof of consistency failed');
            }
        }
        // update state
        for (uint256 p = 0; p < allParticipants.length; p++) {
            (updatedstatecm.x, updatedstatecm.y) = secp.add(ctx[p].cm.x, ctx[p].cm.y, state[allParticipants[p]][asset_id].cm.x, state[allParticipants[p]][asset_id].cm.y);
            (updatedstatetk.x, updatedstatetk.y) = secp.add(ctx[p].tk.x, ctx[p].tk.y, state[allParticipants[p]][asset_id].tk.x, state[allParticipants[p]][asset_id].tk.y);
            state[allParticipants[p]][asset_id].cm = updatedstatecm;
            state[allParticipants[p]][asset_id].tk = updatedstatetk;
        }
        if (asset_id==0)
        { 
            ledger.push(identifier);
        }


        return true;
    }
    function toCompressed(uint256 x, uint256 y) public pure returns (string memory, bytes memory) {
        bytes memory prefix;
        if (y % 2 == 0) {
            prefix = hex"02";
        } else {
            prefix = hex"03";
        }
        
        bytes memory xBytes = _uintToBytes(x);
        bytes memory compressed = abi.encodePacked(prefix, xBytes);
        
        return (_toHexString(compressed), xBytes);
    }
    function _uintToBytes(uint256 value) private pure returns (bytes memory) {
        bytes memory buffer = new bytes(32);
        for (uint256 i = 0; i < 32; i++) {
            buffer[31 - i] = bytes1(uint8(value >> (i * 8)));
        }
        return buffer;
    }
    function _toHexString(bytes memory data) private pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory str = new bytes(data.length * 2);
        // str[0] = "0";
        // str[1] = "x";
        for (uint256 i = 0; i < data.length; i++) {
            str[i * 2] = hexChars[uint8(data[i] >> 4)];
            str[1 + i * 2] = hexChars[uint8(data[i] & 0x0f)];
        }
        return string(str);
    }
    function bytes32ToBytes(bytes32 _input) public pure returns (bytes memory) {
        // Create a dynamic bytes array with a length of 32
        bytes memory output = new bytes(32);
        
        // Copy each byte from the bytes32 input to the bytes array
        for (uint256 i = 0; i < 32; i++) {
            output[i] = _input[i];
        }
        
        return output;
    }


    /// @dev function to verify proofs for the broadcaster cell
    /// @param ctxid is the transaction cell of broadcaster
    /// @param id is the id of the broadcaster
    /// @return true if all proofs are verified correctly and are true
    // function processSenderCell(txcell memory ctxid, uint256 id) public returns (bool) {

    //     (tempcm.x, tempcm.y) = secp.add(state[allParticipants[id]].cm.x, state[allParticipants[id]].cm.y, ctxid.cm.x, ctxid.cm.y);
    //     (h2r.x, h2r.y) = secp.subtract(tempcm.x, tempcm.y, ctxid.compcm.x, ctxid.compcm.y);
    //     require(zkp.verifyEqProof(sval, ctxid.peq, h2r), 'Proof of asset failed');
    //     require(zkp.verifyConsistencyProof(ctxid.pc_), 'Proof of consistency of complimentary commit failed');

    //     (tempcm.x, tempcm.y) = (ctxid.ppositive.pr1.cm1.x, ctxid.ppositive.pr1.cm1.y);
    //     (tempcm.x, tempcm.y) = secp.add(tempcm.x, tempcm.y, ctxid.ppositive.pr2.cm1.x, ctxid.ppositive.pr2.cm1.y);
    //     (tempcm.x, tempcm.y) = secp.add(tempcm.x, tempcm.y, ctxid.ppositive.pr3.cm1.x, ctxid.ppositive.pr3.cm1.y);
    //     (tempcm.x, tempcm.y) = secp.add(tempcm.x, tempcm.y, ctxid.ppositive.pr4.cm1.x, ctxid.ppositive.pr4.cm1.y);
    //     require((tempcm.x == ctxid.compcm.x && tempcm.y == ctxid.compcm.y), "Commitment sum in range proof does not match main commitment for the broadcaster");
    //     require(zkp.verifyRangeProof(ctxid.ppositive), 'Proof of positive commitment failed');
    //     require(zkp.verifyConsistencyProof(ctxid.pc), 'Proof of consistency failed');
    //     return true;
    // }


    /// @dev function to support verification of proof of asset in form of equivalence proof
    /// @param sval is the claimed balance by a bank
    /// @param bankid is id of the bank
    /// @return h2r which is h ** sum of r (blinding factors) in a participants column
    function getLedgerH2R(uint256 sval, uint256 bankid) public returns (uint256, uint256) {
        uint256 gy = secp.getY(preg, g);
        (uint256 tempx, uint256 tempy) = secp.scalMul(sval, g, gy);
         return secp.subtract(state[allParticipants[bankid]][default_asset_id].cm.x, state[allParticipants[bankid]][default_asset_id].cm.y, tempx, tempy);
    }

    /// @dev function to cashout after processing and verifying equivalence proof
    /// @notice only intended to be used by participant. If the proof of asset is verified the contract will
    /// @notice automatically transfer claimed balance from itself to the participant's ethereum address
    /// @param sval is the claimed balance by a bank
    /// @param bankid is the id of the bank
    /// @param pr is the proof of asset in form of a equivalence proof
    function processEqPr(uint256 sval, uint256 bankid, EquivalenceProof.eqProofSolR memory pr) public onlyByParticipants returns (bool) {
        EquivalenceProof.solpoint memory h2r;
        (h2r.x, h2r.y) = getLedgerH2R(sval, bankid);
        require(zkp.verifyEqProof(sval, pr, h2r), "Asset balance proof failed");

        (bool sent, bytes memory data) = msg.sender.call{value: (sval * 1000000000000000000)}("");
        participants[msg.sender] = false;

        require(sent, "failed to send ether");
        return true;
    }

    function checkSenderCell(txcell memory ctxid, address add, EquivalenceProof.solpoint memory h2rd) public returns (bool){
        ecpointxy memory tempcm;
        (h2r.x, h2r.y) = secp.subtract(tempcm.x, tempcm.y, ctxid.compcm.x, ctxid.compcm.y);
        require(zkp.verifyEqProof(sval, ctxid.peq, h2rd), 'Proof of asset failed');
        require(zkp.verifyConsistencyProof(ctxid.pc_), 'Proof of consistency of complimentary commit failed');

        (tempcm.x, tempcm.y) = (ctxid.ppositive.pr1.cm1.x, ctxid.ppositive.pr1.cm1.y);
        (tempcm.x, tempcm.y) = secp.add(tempcm.x, tempcm.y, ctxid.ppositive.pr2.cm1.x, ctxid.ppositive.pr2.cm1.y);
        (tempcm.x, tempcm.y) = secp.add(tempcm.x, tempcm.y, ctxid.ppositive.pr3.cm1.x, ctxid.ppositive.pr3.cm1.y);
        (tempcm.x, tempcm.y) = secp.add(tempcm.x, tempcm.y, ctxid.ppositive.pr4.cm1.x, ctxid.ppositive.pr4.cm1.y);
        require((tempcm.x == ctxid.compcm.x && tempcm.y == ctxid.compcm.y), "Commitment sum in range proof does not match main commitment for the broadcaster");
        require(zkp.verifyRangeProof(ctxid.ppositive), 'Proof of positive commitment failed');
        require(zkp.verifyConsistencyProof(ctxid.pc), 'Proof of consistency failed');
        return true;
    }


    function checkReceiverCell(txcell memory ctx) public returns (bool) {
        ecpointxy memory tempcm;
        (tempcm.x, tempcm.y) = (ctx.ppositive.pr1.cm1.x, ctx.ppositive.pr1.cm1.y);
        (tempcm.x, tempcm.y) = secp.add(tempcm.x, tempcm.y, ctx.ppositive.pr2.cm1.x, ctx.ppositive.pr2.cm1.y);
        (tempcm.x, tempcm.y) = secp.add(tempcm.x, tempcm.y, ctx.ppositive.pr3.cm1.x, ctx.ppositive.pr3.cm1.y);
        (tempcm.x, tempcm.y) = secp.add(tempcm.x, tempcm.y, ctx.ppositive.pr4.cm1.x, ctx.ppositive.pr4.cm1.y);
        require((tempcm.x == ctx.cm.x && tempcm.y == ctx.cm.y), "Commitment sum in range proof does not match main commitment");
        require(zkp.verifyRangeProof(ctx.ppositive), 'Proof of positive commitment failed');
        return true;
    }
}
