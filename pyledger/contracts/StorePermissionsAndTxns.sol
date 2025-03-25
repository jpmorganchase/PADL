pragma solidity ^0.8.0;
/// @title Private and auditable transaction via on-chain verification
/// @author Applied research, Global Tech., JPMorgan Chase, London
/// @notice This is an code for research and experimentation.

contract StorePermissionsAndTxns{
  
  constructor(uint256 _totalSupply){
    Issuer = msg.sender;
    totalSupply = _totalSupply;
  }

  address Issuer;
  modifier onlyByIssuer{
    require(msg.sender == Issuer, "Only Issuer can add participants");
    _;
  }

  modifier onlyByParticipants{
    require(isPermitted(msg.sender), "Only participants can make txns");
    _;
  }

  uint256 totalSupply;
  string public txn;
  mapping (address => bool) public participants;
  mapping (address => bool) public txnApproval;
  mapping (address => bool) public txnApprovalIssuer;
  mapping (address => string) public zkledgerPks;
  mapping (address => string) public zl; 
  address[] public allParticipants;
  string[] public ledger;
  string[] public rough;
  string[] public pks;
  bool public askForApproval;
  uint256 deadline = 0;
  bool public majorityvotes;
  string public commitsTokens;
  uint public test=2;
  string public gov_rules='';



  mapping (address => string) public reqs;
  mapping (address => uint) public reqs_amounts;
  mapping (address => string) public newzl;
  uint256 resx;
  uint256 resy;

  receive() external payable {
    require((msg.value == reqs_amounts[msg.sender]), "Values not same");
    zl[msg.sender] = reqs[msg.sender];
  }


  function getBalance() public view returns (uint) {
    return address(this).balance;
  }

  function addRequests(address _add, string memory _zl, uint _amt) public {
    reqs[_add] = _zl;
    reqs_amounts[_add] = _amt;
  }

  function addParticipant(address _add) public onlyByIssuer{
    participants[_add] = true;
    txnApproval[_add] = false;
    allParticipants.push(_add);
  }

  function retrieveTotalSupply() public view returns (uint256){
    return totalSupply;
  }

  function retrieveIssuer() public returns(address){
    return Issuer;
  }

  function retrieveParticipant(uint i) public view returns(address){
    return allParticipants[i];
  }

  function retrieveNumberOfParticipants() public view returns(uint){
    return allParticipants.length;
  }

  function storePublicKey(string memory _pk, address _add) public onlyByParticipants{
    zkledgerPks[_add] = _pk;
  }

  function retrievePk(address _add) public view returns(string memory){
    return zkledgerPks[_add];
  }

  function retrieveAllPks() public view returns(string memory){
    if (allParticipants.length==0)
    {
      return "";
    }
    string memory all_pks = zkledgerPks[allParticipants[0]];
    for(uint256 i = 1; i<allParticipants.length; i++){
       all_pks = string.concat(all_pks," ", zkledgerPks[allParticipants[i]]);
    }
    return all_pks;
  }

  function setGovRules(string memory gov) virtual public onlyByIssuer{
      gov_rules = gov;
  }

  function retrieveGovarnenceRules() public view returns(string memory){    
    return gov_rules;
  }

  function isPermitted(address _add) public view returns(bool){
    return participants[_add];
  }

  function retrieveDeadline() public view returns(uint256){
    return deadline;
  }

  function removeAllParticipants() public onlyByIssuer{
    if (allParticipants.length > 0){
      delete allParticipants;
      }
  }

  function removeAllTxn() public onlyByIssuer{
    if (ledger.length > 0){
      delete ledger;
    }
  }

  function addTxn(string memory _txn) public onlyByParticipants{
    txn = _txn;
    askForApproval = true;
  }

  function addCommitsTokens(string memory _cmtk) public onlyByParticipants{
    commitsTokens = _cmtk;
  }

  function addZeroLine(string memory _zl, address _add) public onlyByParticipants{
    zl[_add] = _zl;
  }

  struct zl4duint{
    uint256 a;
    uint256 b;
    uint256 c;
    uint256 d;
  }

  struct InnerTuple {
      uint256 a;
      uint256 b;
  }

  struct OuterTuple {
      InnerTuple first;
      InnerTuple second;
  }

  function addIntZeroLine(zl4duint [] memory zl) public returns(string memory){
    return "not implemented for this contract";
  }

  function storeIntCMTK(OuterTuple[][] memory p) public returns(string memory){
    return "not implemented for this contract";
  }

  function updateState() public returns(string memory){
    return "not implemented for this contract";
  }

  function retrieveZeroLine(address _add) public view returns(string memory){
    return zl[_add];
  }

  function retrieveCommitsTokens() public view returns(string memory){
    return commitsTokens;
  }

  function clearTxn() public{
    delete txn;
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

  function approveTxn() public onlyByParticipants{
    bool a = checkTxnApproval();
    if (majorityvotes){
      ledger.push(commitsTokens);
      clearTxn();
    }
  }

  function approveTxnIssuer() virtual public onlyByIssuer{
      ledger.push(commitsTokens);
      clearTxn();
  }

  function storeRoughStr(string memory _rstr) public onlyByParticipants{
    rough.push(_rstr);
  }


  function retrieveTxnLength() public view returns(uint){
    return ledger.length;
  }

  function retrieveTxn(uint i) public view returns(string memory){
    require(i < ledger.length, "Index out of bounds of ledger length");
    return ledger[i];
  }

  function retrieveState(uint256 p) public returns (string memory){
    return "not implemented for this contract";
  }
}
