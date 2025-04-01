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
  uint256 constant BUFFER_TIME = 30;

  event TxnApprovedByIssuer(string identifier);

  function setEndTime(uint endTime) public onlyByIssuer{
    auctionEndTime = block.timestamp + endTime;
    auctionOpenBool = true;
    emit auctionOpen('Auction open with deadline after', endTime);
  }

  // overriding default to include deadline
  function  approveTxnIssuer() public override onlyByIssuer{
      if (block.timestamp >= auctionEndTime + BUFFER_TIME) {
          auctionOpenBool = false;
          emit auctionClosed("Auction closed", ledger.length);
          revert("Auction ended");
      }
      require(bytes(identifier).length > 0, "Invalid identifier");
      require(block.timestamp < auctionEndTime + BUFFER_TIME, 'Auction ended');
      ledger.push(identifier);
      clearTxn();
      emit TxnApprovedByIssuer(identifier);
  }

    function closeAuction() public onlyByIssuer {
      require(block.timestamp >= auctionEndTime, "Auction still active");
      require(auctionOpenBool == true, "Auction already closed");
      auctionOpenBool = false;
      emit auctionClosed("Auction closed", ledger.length); // or pass any relevant ID
  }


}
