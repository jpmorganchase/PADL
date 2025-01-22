pragma solidity ^0.8.28;

import "./ERC/ERC20.sol";
import "../Interfaces/BNInterface.sol";
import "./Interfaces/PADLOnChainInterface.sol";
/// @title Private and auditable transaction via on-chain verification
/// @author Applied research, Global Tech., JPMorgan Chase, London
/// @notice This is an code for research and experimentation.

contract PadlTokenBN is ERC20 {
    //BN254 public bn = new BN254();
    BNInterface public bn;
    PADLOnChainInterface padl;
    uint256 public sval = 10;

    mapping(address => uint256) internal _balances;
    mapping(address => PADLOnChainInterface.cmtk) internal privateBalances;
    BN254Point internal h2r;
    PADLOnChainInterface.txcell storecell;
    address eqaddress;
    address consaddress;

    struct initargs {
        uint256 initialSupply;
        BN254Point cm;
        BN254Point tk;
        address _padlInterfaceAdd;
        address _bnaddress;
        address _eqaddress;
        address _consaddress;
    }
    //ZKProofsBN254 public zkp = new ZKProofsBN254(eqaddress, consaddress);

    constructor(initargs memory init) ERC20("PadlToken", "PDL"){
        padl = PADLOnChainInterface(init._padlInterfaceAdd);
        bn = BNInterface(init._bnaddress);
        _mint(msg.sender, init.initialSupply);
        eqaddress = init._eqaddress;
        consaddress = init._consaddress;
        privateBalances[msg.sender].cm.x = init.cm.x;
        privateBalances[msg.sender].cm.y = init.cm.y;
        privateBalances[msg.sender].tk.x = init.tk.x;
        privateBalances[msg.sender].tk.y = init.tk.y;
    }

    function privateBalanceOf(address from) public view returns(uint256, uint256, uint256, uint256){
        return (privateBalances[from].cm.x, privateBalances[from].cm.y, privateBalances[from].tk.x, privateBalances[from].tk.y);
    }

    function storeCell(PADLOnChainInterface.txcell[] memory storecelltemp) public {
        storecell = storecelltemp[0];
    }

    function privateTransfer(address from, address to, PADLOnChainInterface.txcell memory senderCell, PADLOnChainInterface.txcell memory receiverCell) public returns (bool){
        return _privateUpdate(from, to, senderCell,receiverCell);
    }

    function transfer(address to, uint256 amount, PADLOnChainInterface.txcell memory senderCell, PADLOnChainInterface.txcell memory receiverCell) public returns (bool) {
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

    function _privateUpdate(address from, address to, PADLOnChainInterface.txcell memory senderCell, PADLOnChainInterface.txcell memory receiverCell) internal returns (bool){
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
