pragma solidity ^0.8.28;

import "./ERC/ERC20.sol";
import "./ZK_proof/bn254.sol";
import "./ZK_proof/ZKProofsBN254.sol";
import "./PADLOnChainBN.sol";
/// @title Private and auditable transaction via on-chain verification
/// @author Applied research, Global Tech., JPMorgan Chase, London
/// @notice This is an code for research and experimentation.

contract PadlTokenBN is ERC20 {
    BN254 public bn = new BN254();
    ZKProofsBN254 public zkp = new ZKProofsBN254();

    uint256 public sval = 10;
    PADLOnChainBN public padl = new PADLOnChainBN(sval);

    mapping(address => uint256) internal _balances;
    mapping(address => PADLOnChainBN.cmtk) internal privateBalances;
    BN254Point internal h2r;
    PADLOnChainBN.txcell storecell;

    constructor(uint256 initialSupply, BN254Point memory cm, BN254Point memory tk) ERC20("PadlToken", "PDL"){
        _mint(msg.sender,initialSupply);
        privateBalances[msg.sender].cm.x = cm.x;
        privateBalances[msg.sender].cm.y = cm.y;
        privateBalances[msg.sender].tk.x = tk.x;
        privateBalances[msg.sender].tk.y = tk.y;
    }

    function privateBalanceOf(address from) public view returns(uint256, uint256, uint256, uint256){
        return (privateBalances[from].cm.x, privateBalances[from].cm.y, privateBalances[from].tk.x, privateBalances[from].tk.y);
    }

    function storeCell(PADLOnChainBN.txcell[] memory storecelltemp) public {
        storecell = storecelltemp[0];
    }

    function privateTransfer(address from, address to, PADLOnChainBN.txcell memory senderCell, PADLOnChainBN.txcell memory receiverCell) public returns (bool){
        return _privateUpdate(from, to, senderCell,receiverCell);
    }

    function transfer(address to, uint256 amount, PADLOnChainBN.txcell memory senderCell, PADLOnChainBN.txcell memory receiverCell) public returns (bool) {
        privateTransfer(msg.sender, to, senderCell, receiverCell);
        _update(msg.sender, to, amount);
        return true;
    }

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        recipient;
        amount;
        revert('TRANSFER_NOT_SUPPORTED, TRY transfer WITH PRIVATE TRANSACTION');
    }

    function balanceOf (address account) public view virtual override returns(uint256){
        return _balances[account];
    }

    function geth2r(BN254Point memory cm, BN254Point memory compcm, address add) public returns (BN254Point memory){
        BN254Point memory tempcmd ;
        tempcmd = bn.add(privateBalances[add].cm, cm);
        return bn.add(tempcmd, bn.neg(compcm));
    }

    function _privateUpdate(address from, address to, PADLOnChainBN.txcell memory senderCell, PADLOnChainBN.txcell memory receiverCell) internal returns (bool){
        BN254Point memory tempcm ;
        tempcm = bn.add(receiverCell.cm, senderCell.cm);
        h2r = geth2r(senderCell.cm, senderCell.compcm, from);
        require((tempcm.x == 0 && tempcm.y == 0), 'Proof of balance failed');
        require(padl.checkReceiverCell(receiverCell), 'Received cell not approved');
        require(padl.checkSenderCell(senderCell, from, h2r), 'Sender cell not approved');
        privateBalances[to].cm = bn.add(privateBalances[to].cm, receiverCell.cm);
        privateBalances[from].cm = bn.add(privateBalances[from].cm, senderCell.cm);
        privateBalances[to].tk = bn.add(privateBalances[to].tk, receiverCell.tk);
        privateBalances[from].tk = bn.add(privateBalances[from].tk, senderCell.tk);
        return true;
    }
}
