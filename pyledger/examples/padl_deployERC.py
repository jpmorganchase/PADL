import zkbp
from solcx import compile_standard, install_solc, import_installed_solc
import json
import os
import solcx
from web3 import Web3
from pathlib import Path
from eth_account import Account
import sys

from pyledger.zkutils import BNCurve

path = os.path.realpath(__file__)
parent_dir = str(Path(path).parents[2])
main_dir = str(Path(path).parents[2])
sys.path.append(parent_dir)
from pyledger.extras.evmnet.participant_scripts import *
from pyledger.extras.evmnet.participant_scripts import get_private_tx_str


url = "http://127.0.0.1:8545"
chain_id = 1337
local_dirname = "/Users/yashsatsangi/Documents/code/PADL/PADL-latest/padl_private/pyledger/"
w3 = Web3(Web3.HTTPProvider(url, request_kwargs={'timeout': 600000}))


def send_tx_from_call(private_key, transaction):
    signed_txn = w3.eth.account.sign_transaction(transaction, private_key=private_key)
    print("deploying contract")
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_receipt


def compile_contract(contract_location, contract_tx_name, file_name_contract):

    with open(main_dir + f"/pyledger/contracts/{contract_location}", "r") as f:
        contract = f.read()

    # complie our solidity
    compiled_sol = compile_standard(
        {
            "language": "Solidity",
            "sources": {f"{file_name_contract}": {"content": contract}},
            "settings": {
                "optimizer": {
                    "enabled": True,
                    "runs": 100,
                    "details": {
                        "peephole": True,
                        "inliner": True,
                        "jumpdestRemover": True,
                        "orderLiterals": True,
                        "deduplicate": True,
                        "cse": True,
                        "constantOptimizer": True,
                        "yul": True,
                    }
                },
                "viaIR": True,
                "evmVersion": "london",

                "outputSelection": {
                    "*": {
                        "*": ["abi", "metadata", "evm.bytecode", "evm.sourceMap"]
                    }
                }
            },
        },
        solc_version="0.8.28",
        allow_paths=os.path.join(local_dirname, "contracts"),
        base_path=os.path.join(local_dirname, "contracts")
    )

    with open("compiled_code.json", "w") as f:
        json.dump(compiled_sol, f)

    bytecode = compiled_sol["contracts"][file_name_contract][contract_tx_name]["evm"][
        "bytecode"
    ]["object"]

    abi = compiled_sol["contracts"][file_name_contract][contract_tx_name]["abi"]
    return bytecode, abi
    # '===========COMPILE DONE=============='


account_address = '0xFE3B557E8Fb62b89F4916B721be55cEb828dBd73'
example_private_key = '0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63'
public_key = '0c21444513f038286a2e46a73d57c438e397e2f76e412fef6507cb618b156ecc'
private_key = example_private_key
account_address2 = "0x8c171946c84D214e9F54fF22F515347dA4d78F7B"
account_address = Web3.toChecksumAddress(account_address)
account_address2 = Web3.toChecksumAddress(account_address2)
LocalAccount = Account.from_key(example_private_key)
#contract_tx_name="PADLOnChainBN"
#file_name_contract="PADLOnChainBN.sol"

##### DEPLOY BN #######

bytecode, abi = compile_contract("ZK_proof/bn254.sol", "BN254", "BN254.sol")
bn = w3.eth.contract(abi=abi, bytecode=bytecode)
nonce = w3.eth.get_transaction_count(account_address)
transaction = bn.constructor().buildTransaction(
    {"chainId": chain_id, "from": account_address, "nonce": nonce, 'gas': 100000000} )
tx_receipt = send_tx_from_call(example_private_key, transaction)
_bnaddress = tx_receipt.contractAddress



##### Deploy PadlOnChain
#bytecode, abi = compile_contract("PADLOnChainBN.sol", "PADLOnChainBN", "PADLOnChainBN.sol")
#padlonchain = w3.eth.contract(abi=abi, bytecode=bytecode)
#nonce = w3.eth.get_transaction_count(account_address)
#transaction = padlonchain.constructor(100).buildTransaction(
#    {"chainId":chain_id, "from":account_address, "nonce":nonce, 'gas': 100000000}
#)
#tx_receipt = send_tx_from_call(example_private_key, transaction)
#contract_address = tx_receipt.contractAddress

contract_address,bank = deploy_PADLOnChain(example_private_key, contract_tx_name="PADLOnChainBN", file_name_contract="PADLOnChainBN.sol")
account_dict = create_account(contract_address=contract_address)
add_participant(account_dict["address"])#, "Issuer 0", contract_tx_name=contract_tx_name, file_name_contract=file_name_contract)
publickey_bank = account_dict['public_key']
print('publickey_bank',publickey_bank)



bank=register_padl('Bank', account_dict, v0=[0,0] , types={'0': 'cash-token', '1': 'fund-token'})

bank_gkp = PadlEVM(secret_key=account_dict['private_key'], contract_address=account_dict['contract_address'], contract_tx_name="PADLOnChain", file_name_contract="PADLOnChain.sol")
pks = bank_gkp.retrieve_pks()
print('pks', pks)

pub_keys = [public_key, publickey_bank]

r = r_blend()
cmo = Commit(zkbp.gen_GH(), 100, r)
cm = cmo.eval.get

tk = zkbp.to_token_from_pk(public_key, r.val)

tx_str = get_private_tx_str(pub_keys, [[-2, 2]], file_name='Issuer 0', state=[cm,tk.get], old_balance=100, audit_pk=None)# contract_tx_name=contract_tx_name, file_name_contract=file_name_contract )


bytecode, abi = compile_contract("PadlTokenBN.sol", "PadlTokenBN", "PadlTokenBN.sol")
#'===========COMPILE DONE=============='
StoreTxn = w3.eth.contract(abi=abi, bytecode=bytecode)

# get the latest transaction

nonce = w3.eth.get_transaction_count(account_address)


c = BNCurve.get_xy(cm)
t = BNCurve.get_xy(tk.get)
print('c', c)
print('t', t)
#transaction = StoreTxn.constructor(100, c, t).buildTransaction(

transaction = StoreTxn.constructor(100, c, t, contract_address, _bnaddress).buildTransaction(
    {"chainId": chain_id,
     "from": account_address, "nonce": nonce, 'gas': 100000000}
)

signed_txn = w3.eth.account.sign_transaction(transaction, private_key=private_key)
print("deploying contract")
tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print(f"Deployed at {tx_receipt.contractAddress}")

deployed_address = tx_receipt.contractAddress
contract = w3.eth.contract(address=deployed_address, abi=abi)
#print(t)
b = contract.functions.privateBalanceOf(account_address).call()

check_balance_by_commit_token('Issuer 0', (b[0], b[1]), (b[2], b[3]))
print(contract.functions.privateBalanceOf(account_address2).call())
nonce = w3.eth.get_transaction_count(account_address)
transaction = contract.functions.privateTransfer(account_address, account_address2, tx_str[0], tx_str[1]).buildTransaction(
    {
        "chainId":chain_id, "from":account_address, "nonce":nonce
    }
)

# transaction = contract.functions.(tx_str).buildTransaction(
#     {
#         "chainId":chain_id, "from":account_address, "nonce":nonce
#     }
# )

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

