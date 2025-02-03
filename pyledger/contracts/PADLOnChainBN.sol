pragma solidity ^0.8.20;
/// @title Private and auditable transaction via on-chain verification
/// @author Applied research, Global Tech., JPMorgan Chase, London
/// @notice This is an code for research and experimentation.


import "./Interfaces/PADLOnChainInterface.sol";
import "../Interfaces/RangeProofInterface.sol";
import "../Interfaces/BNInterface.sol";
import "../Interfaces/ConsistencyProofInterface.sol";
import "../Interfaces/EquivalenceProofInterface.sol";
//import "./ZK_proof/RangeProofVer.sol";

contract PADLOnChainBN is PADLOnChainInterface{

    address bnaddress;
    address eqaddress;
    address consaddress;

    address rngaddress;
    BNInterface bn;
    EquivalenceProofInterface eqp;
    ConsistencyProofInterface csp;
    RangeProofInterface rng;

    uint8 public constant totalAsset= 8;
    uint8 public constant default_asset_id = 0;
    PADLOnChainInterface.cmtk[] public cur_asset_commits_tokens;

    uint256 constant gy = 0x211f2c237d907e6e11073f667fb026085665bb1ba108518ddd23bebfbe896ca5;
    uint256 constant gx = 0x2f9fb7e98cc14aced65e3f4e0871e0a012a699c8f474e2286fce8b97adfad91a;
    uint256 constant hx = 0x1;
    uint256 constant hy = 0x2;

    address Issuer;
    uint256 totalSupply;
    mapping(address => PADLOnChainInterface.cmtk[]) state; // state of the contract
    mapping(address => PADLOnChainInterface.cmtk[]) tempzl;
    mapping(address => uint256) allids;
    address[] public allParticipants;
    PADLOnChainInterface.txcell[] public currenttx;
    BN254Point public newcm;
    BN254Point public newtk;
    BN254Point public sumcm;
    BN254Point public sumtk;
    BN254Point public tempcm;
    BN254Point public updatedstatecm;
    BN254Point public updatedstatetk;
    string public identifier;

    PADLOnChainInterface.cmtk[] public intzl;
    uint256 public sval = 10;

    PADLOnChainInterface.cmtk cmtk_temp;
    mapping(address => PADLOnChainInterface.cmtk) public zlnotuseful;
    mapping(address => string) public zl;
    mapping(address => string) public reqs;
    mapping(address => uint) public reqs_amounts;
    mapping(address => bool) public txnApproval;
    mapping(address => string) public zkledgerPks;
    mapping(address => bool) public participants;

    PADLOnChainInterface.cmtk[][] public commitsTokens;
    bool public majorityvotes;
    string[] public ledger; // ledger as arrays of hashes
    uint8 public constant preg = 0x2;
    string public gov_rules='';

    //BN254 public bn = new BN254();

    BN254Point public h2r;

    struct initargs {
        uint256 _totalSupply;
        address _bnaddress;
        address _eqaddress;
        address _consaddress;
        address _rngaddress;
    }

    constructor(initargs memory init){
        bn = BNInterface(init._bnaddress);
        bnaddress = init._bnaddress;
        eqp = EquivalenceProofInterface(init._eqaddress);
        csp = ConsistencyProofInterface(init._consaddress);
        Issuer = msg.sender;
        totalSupply = init._totalSupply;
        rng = RangeProofInterface(init._rngaddress);
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

    /// @dev PADL transaction structure consists of a commitment, token, complimentary commitment, complimentary token,
    /// @dev proof of positive commitment, range proof, equivalence proof.
    /*
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
    */

    function isPermitted(address _add) public override returns (bool){
        return participants[_add];
    }

        /// @dev function to add initial commit-token (also called zeroline) for a new participant
    /// @param _add ethereum address of participant
    /// @param _zl zero line
    /// @param _amt amount of coins minted (initial balance)
    function addRequests(address _add, string memory _zl, uint _amt) public override onlyByIssuer {
        reqs[_add] = _zl;
        reqs_amounts[_add] = _amt;
    }

    /// @dev function to add a participant to contract. Gives access to the functionalities of the contract
    /// @param _add ethereum address of participant
    function addParticipant(address _add) public override onlyByIssuer {
        participants[_add] = true;
        txnApproval[_add] = false;
        allParticipants.push(_add);
        allids[_add] = allParticipants.length - 1;
    }

    /// @dev function to find balance deposited in the contract
    /// @return returns balance deposited in the contract
    function getTotalBalance() public override view returns (uint) {
        return address(this).balance;
    }

    /// @dev function to retrieve participant by id or index
    /// @param i integer corresponding to participants id or index
    /// @return address of participant corresponding to i
    function retrieveParticipant(uint i) public override view returns (address){
        return allParticipants[i];
    }

    /// @dev function to retrieve total number of participants
    /// @return number of participants
    function retrieveNumberOfParticipants() public override view returns (uint){
        return allParticipants.length;
    }

    /// @dev function to store participants PADL public key on the contract
    /// @param _pk public key of participant
    /// @param _add ethereum address of participant
    function storePublicKey(string memory _pk, address _add) public override {
        zkledgerPks[_add] = _pk;
    }

    /// @dev function to retrieve PADL public key of a participant
    /// @param _add participant's ehtereum address
    /// @return public key of participant with address _add
    function retrievePk(address _add) public override view returns (string memory){
        return zkledgerPks[_add];
    }

    /// @dev function to retrieve public key of all participants
    /// @return all PADL public keys
    function retrieveAllPks() public override view returns (string memory){
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
    function retrieveZeroLine(address _add) public override view returns (string memory){
        return zl[_add];
    }

    /// @dev function to add zero line for a participant
    /// @param _zl zero line in string format
    /// @param _add ethereum address
    function addZeroLine(string memory _zl, address _add) public override {
        zl[_add] = _zl;
    }

    function retrieveTxnLength() public override view returns(uint){
        return ledger.length;
    }

    function storeIntCMTK(PADLOnChainInterface.cmtk[][] memory _p) public override{
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

    function addstorageidentifier(string memory _idnt) public override{
        identifier = _idnt;
    }


    function retrieveCommitsTokens() public override view returns(PADLOnChainInterface.cmtk[][] memory){
        return commitsTokens;
    }

    function retrieveIdentifier() public override view returns(string memory){
        return identifier;
    }

    function voteTxn() public override onlyByParticipants{
        txnApproval[msg.sender] = true;
    }

    function checkTxnApproval() public override returns(bool){
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
    function resetVotes() public override{
        for(uint256 i=0; i<allParticipants.length;i++){
            address addr = allParticipants[i];
            txnApproval[addr] = false;
        }
    }

    function updateState() public override{
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

    function approveTxn() public override onlyByParticipants{
        bool a = checkTxnApproval();
        if (majorityvotes){
            ledger.push(identifier);

            updateState();
            clearTxn();
        }
    }
    function approveTxnIssuer() public override onlyByIssuer {
        ledger.push(identifier);
        clearTxn();
        updateState();
    }
    function clearTxn() public override{
        // delete txn;
    }
    function retrieveTxn(uint i) public override view returns(string memory){
        // require(i < ledger.length, "Index out of bounds of ledger length");
        return ledger[i];
    }

    function setGovRules(string memory gov) public override onlyByIssuer{
        gov_rules = gov;
    }
    function retrieveGovarnenceRules() public override view returns(string memory){
        return gov_rules;
    }

    /// @dev function to store zero line in a temporary mapping that is later changed to state once the deposit is received
    /// @param zls commitment-token tuple
    function addZeroLineToState(PADLOnChainInterface.cmtk [] memory zls) public override {
         //tempzl[msg.sender] = zls;
         for (uint256 index=0;index<zls.length;index++){
             state[msg.sender].push(zls[index]);
         }
    }

    /// @dev function to retrieve state of a participant
    /// @param p participant id
    /// @return state of a participant on the contract (commitment-token tuple)
    function retrieveStateId(uint256 p) public override returns (PADLOnChainInterface.cmtk[] memory){
        return (state[allParticipants[p]]);
    }

    function processTx(PADLOnChainInterface.txcell[] memory ctx, uint256 asset_id) public override onlyByParticipants returns (bool) {
        require(ctx.length == allParticipants.length, "Length of transaction not equal to length of participants");
        // proof of balance
        BN254Point memory sum_cm = ctx[0].cm;
        for (uint256 p = 1; p < allParticipants.length; p++) {
            sum_cm =  bn.add(ctx[p].cm, sum_cm);
        }
        require((sum_cm.x == 0 && sum_cm.y == 0), 'Proof of balance failed');

        // TODO need to take cm and pubk from tx and contract - not from pc.
        for (uint256 p = 0; p < allParticipants.length; p++) {
            // proof of consistency
            require(csp.verify(ctx[p].pc), 'Proof of consistency failed');
            // proof of asset
            require(rng.verify_range_proof(ctx[p].ppositive), 'Range Proof is failed');
        }

        // proof of equivalence
        uint256 id = allids[msg.sender];
        BN254Point memory tempcm = bn.add(state[allParticipants[id]][asset_id].cm, ctx[id].cm);
        h2r = bn.add(tempcm, bn.neg(ctx[id].compcm));
        require(eqp.verify(ctx[id].peq, h2r), 'Proof of Equivalence failed');

         // update state
        for (uint256 p = 0; p < allParticipants.length; p++) {
            state[allParticipants[p]][asset_id].cm = bn.add(ctx[p].cm, state[allParticipants[p]][asset_id].cm);
            state[allParticipants[p]][asset_id].tk = bn.add(ctx[p].tk, state[allParticipants[p]][asset_id].tk);
        }
        if (asset_id==0)
        {
            ledger.push(identifier);
        }

        return true;
    }

    function checkSenderCell(PADLOnChainInterface.txcell memory ctxid, address add, BN254Point memory h2rd) public override returns (bool){
        require(eqp.verify(ctxid.peq, h2rd), 'Proof of asset failed');
        require(csp.verify(ctxid.pc_), 'Proof of consistency of complimentary commit failed');
        require(rng.verify_range_proof(ctxid.ppositive), 'Proof of positive commitment failed');
        require(csp.verify(ctxid.pc), 'Proof of consistency failed');
        return true;
    }

    function checkReceiverCell(PADLOnChainInterface.txcell memory ctx) public override returns (bool) {
        require(rng.verify_range_proof(ctx.ppositive), 'Proof of positive commitment failed');
        return true;
    }
}
