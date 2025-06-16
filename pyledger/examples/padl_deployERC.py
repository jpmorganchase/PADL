import os
from pathlib import Path
import sys
from eth_account import Account
path = os.path.realpath(__file__)
parent_dir = str(Path(path).parents[2])
main_dir = str(Path(path).parents[2])
sys.path.append(parent_dir)
from pyledger.extras.evmnet.participant_scripts import *

# EVM Net config
url = "http://127.0.0.1:8545"
chain_id = 1337
local_dirname = str(Path(os.path.realpath(__file__)).parents[1]) # contracts path
w3 = Web3(Web3.HTTPProvider(url, request_kwargs={'timeout': 600000}))

# Ethereum account for partyA
account_address = Web3.toChecksumAddress('0xFE3B557E8Fb62b89F4916B721be55cEb828dBd73')
private_key = '0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63'

# Ethereum account for partyB
account_address2 = Web3.toChecksumAddress("0x8c171946c84D214e9F54fF22F515347dA4d78F7B")

ledger, PartyA = deploy_PadlToken(private_key, name='PartyA',v0=[100])

# let's check the private balance of PartyA using its wallet file 'PartyA 0'
conn = ledger.token.connect_to_evm()
contract = conn['contract_obj']
private_state = ledger.retrieve_state(PartyA.address)
check_balance_by_commit_token('PartyA 0', private_state)

# PartyB now is creating its padl object and wallet
PartyB = MakeLedger().register_new_bank(name='PartyB', address=account_address2, contract_address=ledger.deployed_address, tx_obj=ERCTx())
print('partyB balance:', contract.functions.privateBalanceOf(account_address2).call())

# PartyA creates private transaction of 2 units, using PartyB's, pk+address
tx_str = PartyA.create_asset_tx([[-2,2]],[PartyA.pk, PartyB.pk],state=ledger.retrieve_state(PartyA.address))

nonce = w3.eth.get_transaction_count(account_address)
transaction = contract.functions.privateTransfer(account_address, account_address2, tx_str[0], tx_str[1]).buildTransaction(
    {
        "chainId":chain_id, "from":account_address, "nonce":nonce, "gas":10000000
    }
)
signed_txn = w3.eth.account.sign_transaction(transaction,private_key=private_key)
tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

# Each party can check its balance:
private_state = ledger.retrieve_state(PartyA.address)
print('PartyA private balance', private_state)
check_balance_by_commit_token('PartyA 0', private_state)

private_state = ledger.retrieve_state(PartyB.address)
print('PartyB private balance', private_state)
check_balance_by_commit_token('PartyB 0', private_state)

print('transaction done')

