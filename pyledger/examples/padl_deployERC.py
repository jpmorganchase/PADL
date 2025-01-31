import zkbp
from solcx import compile_standard, install_solc, import_installed_solc
import json
import os
import solcx
from web3 import Web3
from pathlib import Path
from eth_account import Account
import sys

from pyledger.extras.evmnet.evmpadl import EvmLedger
from pyledger.ledger import BankCommunication
from pyledger.zkutils import BNCurve

path = os.path.realpath(__file__)
parent_dir = str(Path(path).parents[2])
main_dir = str(Path(path).parents[2])
sys.path.append(parent_dir)
from pyledger.extras.evmnet.participant_scripts import *


url = "http://127.0.0.1:8545"
chain_id = 1337
local_dirname = str(Path(os.path.realpath(__file__)).parents[1])
w3 = Web3(Web3.HTTPProvider(url, request_kwargs={'timeout': 600000}))


account_address = '0xFE3B557E8Fb62b89F4916B721be55cEb828dBd73'
example_private_key = '0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63'
public_key = '0c21444513f038286a2e46a73d57c438e397e2f76e412fef6507cb618b156ecc'
private_key = example_private_key
account_address2 = "0x8c171946c84D214e9F54fF22F515347dA4d78F7B"
account_address = Web3.toChecksumAddress(account_address)
account_address2 = Web3.toChecksumAddress(account_address2)
LocalAccount = Account.from_key(example_private_key)

##### DEPLOY BN #######


ledger,bank = deploy_PADLOnChain(example_private_key, contract_tx_name="PADLOnChainBN", file_name_contract="PADLOnChainBN.sol")
contract_address = ledger.deployed_address
account_dict = create_account(contract_address=contract_address)
add_participant(account_dict["address"])#, "Issuer 0", contract_tx_name=contract_tx_name, file_name_contract=file_name_contract)
publickey_bank = account_dict['public_key']
print('publickey_bank',publickey_bank)

bank=register_padl('Bank', account_dict, v0=[0,0] , types={'0': 'cash-token', '1': 'fund-token'})

bank_gkp = PadlEVM(secret_key=account_dict['private_key'], contract_address=account_dict['contract_address'], contract_tx_name="PADLOnChainBN", file_name_contract="PADLOnChainBN.sol")
pks = bank_gkp.retrieve_pks()
print('pks', pks)

pub_keys = [public_key, publickey_bank]

r = r_blend()
cmo = Commit(zkbp.gen_GH(), 100, r)
cm = cmo.eval.get

tk = zkbp.to_token_from_pk(public_key, r.val)

tx_str = get_private_tx_str(pub_keys, [[-2, 2]], file_name='Issuer 0', state=[cm,tk.get], old_balance=100, audit_pk=None)# contract_tx_name=contract_tx_name, file_name_contract=file_name_contract )



c = BNCurve.get_xy(cm)
t = BNCurve.get_xy(tk.get)
print('c', c)
print('t', t)
print(contract_address)
print(ledger.bnaddress)
contract_args = (100, c, t, contract_address, ledger.bnaddress, ledger.eqaddress, ledger.consaddress)
ev = EvmLedger(BankCommunication(), "PadlTokenBN.sol", local_dirname, w3, chain_id, account_address, private_key, "PadlTokenBN")
deployed_address = ev.deploy_padl_erc(contract_args)
conn = ev.connect_to_evm()
contract = conn['contract_obj']
#contract = w3.eth.contract(address=deployed_address, abi=abi)
b = contract.functions.privateBalanceOf(account_address).call()

check_balance_by_commit_token('Issuer 0', (b[0], b[1]), (b[2], b[3]))
print(contract.functions.privateBalanceOf(account_address2).call())
nonce = w3.eth.get_transaction_count(account_address)
transaction = contract.functions.privateTransfer(account_address, account_address2, tx_str[0], tx_str[1]).buildTransaction(
    {
        "chainId":chain_id, "from":account_address, "nonce":nonce, "gas":1000000000
    }
)

signed_txn = w3.eth.account.sign_transaction(transaction,private_key=private_key)
tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print(tx_receipt)
print(contract.functions.balanceOf(account_address2).call())


b = contract.functions.privateBalanceOf(account_address).call()
check_balance_by_commit_token('Issuer 0', (b[0], b[1]), (b[2], b[3]))
b = contract.functions.privateBalanceOf(account_address2).call()
check_balance_by_commit_token('Bank 1', (b[0], b[1]), (b[2], b[3]))


print('transaction done')

