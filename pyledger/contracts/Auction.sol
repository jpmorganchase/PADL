pragma solidity ^0.8.0;
import "./PADLOnChain.sol";
/// @title A wrapper for auction, including the ending time of opening the auction and issuer approve the transaction
/// @author Applied research, Global Tech., JPMorgan Chase, London
/// @notice This is an code for research and experimentation.
contract Auction is PADLOnChain{
  event auctionOpen(string msg, uint time);
  event auctionClosed(string msg, uint id);
  bool public auctionOpenBool;

  constructor(uint256 _totalSupply)  PADLOnChain(_totalSupply) {
  }

  string name;
  uint auctionEndTime;

  function setEndTime(uint endTime) public onlyByIssuer{
    auctionEndTime = block.timestamp + endTime;
    auctionOpenBool = true;
    emit auctionOpen('Auction open with deadline after', endTime);
  }

  // overriding default to include deadline
  function  approveTxnIssuer() public override onlyByIssuer{
      require(block.timestamp < auctionEndTime, 'Auction ended');
      ledger.push(identifier);
      clearTxn();
  }

}
