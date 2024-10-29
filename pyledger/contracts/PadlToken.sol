pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "pyledger/contracts/ZK_proof/Secp256k.sol";
import "pyledger/contracts/PADLOnChain.sol";

/// @title Private and auditable transaction via on-chain verification
/// @author Applied research, Global Tech., JPMorgan Chase, London
/// @notice This is an code for research and experimentation.

contract PadlToken is ERC20 {
    Secp256k public secp = new Secp256k();
    ZKProofs public zkp = new ZKProofs();

    uint256 public sval = 10;
    PADLOnChain public padl = new PADLOnChain(sval);

    mapping(address => uint256) internal _balances;
    mapping(address => PADLOnChain.cmtk) internal privateBalances;
    EquivalenceProof.solpoint internal h2r;

    constructor(uint256 initialSupply, PADLOnChain.ecpointxy memory cm, PADLOnChain.ecpointxy memory tk) ERC20("PadlToken", "PDL"){
        _mint(msg.sender,initialSupply);
        privateBalances[msg.sender].cm.x = cm.x;
        privateBalances[msg.sender].cm.y = cm.y;
        privateBalances[msg.sender].tk.x = tk.x;
        privateBalances[msg.sender].tk.y = tk.y;
    }

    function privateBalanceOf(address from) public view returns(uint256, uint256, uint256, uint256){
        return (privateBalances[from].cm.x, privateBalances[from].cm.y, privateBalances[from].tk.x, privateBalances[from].tk.y);
    }

    function privateTransfer(address from, address to, PADLOnChain.txcell memory senderCell, PADLOnChain.txcell memory receiverCell) public returns (bool){
        return _privateUpdate(from, to, senderCell,receiverCell);
    }

    function transfer(address to, uint256 amount, PADLOnChain.txcell memory senderCell, PADLOnChain.txcell memory receiverCell) public returns (bool) {
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

    function geth2r(PADLOnChain.ecpointxy memory cm, PADLOnChain.ecpointxy memory compcm, address add) public returns (uint256, uint256){
        PADLOnChain.ecpointxy memory tempcmd ;
        (tempcmd.x, tempcmd.y) = secp.add(privateBalances[add].cm.x, privateBalances[add].cm.y, cm.x, cm.y);
        return secp.subtract(tempcmd.x, tempcmd.y, compcm.x, compcm.y);
    }

    function _privateUpdate(address from, address to, PADLOnChain.txcell memory senderCell, PADLOnChain.txcell memory receiverCell) internal returns (bool){
        PADLOnChain.ecpointxy memory tempcm ;
        (tempcm.x, tempcm.y) = secp.add(receiverCell.cm.x, receiverCell.cm.y, senderCell.cm.x, senderCell.cm.y);
        (h2r.x, h2r.y) = geth2r(senderCell.cm, senderCell.compcm, from);
        require((tempcm.x == 0 && tempcm.y == 0), 'Proof of balance failed');
        require(padl.checkReceiverCell(receiverCell), 'Received cell not approved');
        require(padl.checkSenderCell(senderCell, from, h2r), 'Sender cell not approved');
        (privateBalances[to].cm.x, privateBalances[to].cm.y) = secp.add(privateBalances[to].cm.x, privateBalances[to].cm.y,receiverCell.cm.x, receiverCell.cm.y);
        (privateBalances[from].cm.x, privateBalances[from].cm.y) = secp.add(privateBalances[from].cm.x, privateBalances[from].cm.y, senderCell.cm.x, senderCell.cm.y);
        (privateBalances[to].tk.x, privateBalances[to].tk.y) = secp.add(privateBalances[to].tk.x, privateBalances[to].tk.y, receiverCell.tk.x, receiverCell.tk.y);
        (privateBalances[from].tk.x, privateBalances[from].tk.y) = secp.add(privateBalances[from].tk.x, privateBalances[from].tk.y, senderCell.tk.x, senderCell.tk.y);
        return true;
    }


}
