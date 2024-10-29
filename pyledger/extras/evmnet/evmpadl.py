"""EVMLedger object inherent MakeLedger object to work with EVM/Quorum"""
from web3 import Web3
import subprocess
import ast
import sys
import os, logging
from pathlib import Path
path = os.path.realpath(__file__)
parent_dir = str(Path(path).parents[2])
sys.path.append(parent_dir)

import hashlib

from pyledger.ledger import MakeLedger
import json
from solcx import compile_standard, install_solc, import_installed_solc

if import_installed_solc() is []:
    try:
        install_solc("0.8.19")
    except:
        raise "require solc path for solidity compiler"

class EvmLedger(MakeLedger):
    def __init__(self, comm, file_name_contract, local_dirname,
                 w3, chain, account_address, private_key, contract_tx_name):
        super().__init__(comm)
        self.file_name_contract = file_name_contract
        self.local_dirname = local_dirname
        self.w3 = w3
        self.account_address = account_address
        self.contract_tx_name = contract_tx_name
        self.deployed_address = ""
        self.chain = chain
        self.private_key = private_key
        self.compiled_file_path = 'compiled_code_'

    def connect_to_evm(self):
        with open(os.path.join(self.local_dirname, self.compiled_file_path + self.file_name_contract + '.json'), "r") as f:
            compiled_sol = json.load(f)
        bytecode = compiled_sol["contracts"][self.file_name_contract][self.contract_tx_name]["evm"][
            "bytecode"
        ]["object"]
        abi = compiled_sol["contracts"][self.file_name_contract][self.contract_tx_name]["abi"]
        nonce = self.w3.eth.get_transaction_count(self.account_address)
        store_txn = self.w3.eth.contract(address=self.deployed_address, abi=abi)
        return {'w3server': self.w3, 'contract_obj': store_txn, "nonce": nonce}

    def compile_contract(self):
        old_file_hash = None
        try:
            with open(os.path.join(self.local_dirname, self.compiled_file_path + self.file_name_contract + "_hash" ), "r") as f:
                old_file_hash = f.read()
        except Exception as e:
            None

        with open(os.path.join(self.local_dirname, "contracts", self.file_name_contract), "r") as f:
            contract_source = f.read()
            # Compile our solidity
        cur_file_hash = hashlib.sha256(contract_source.encode(encoding = "utf-8")).hexdigest()

        if (old_file_hash==cur_file_hash):
            with open(os.path.join(self.local_dirname, self.compiled_file_path + self.file_name_contract + '.json'), "r") as f:
                compiled_sol = json.load(f)
            return compiled_sol         
        compiled_sol = compile_standard(
            {
                "language": "Solidity",
                "sources": {self.file_name_contract: {"content": contract_source}},
                "settings": {
                    "optimizer":{
                        "enabled":False,
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
            solc_version="0.8.20",
            allow_paths=os.path.join(self.local_dirname, "contracts"),
            base_path=os.path.join(self.local_dirname, "contracts")
        )
        with open(os.path.join(self.local_dirname, self.compiled_file_path + self.file_name_contract + '.json'), "w") as f:
            json.dump(compiled_sol, f)
        with open(os.path.join(self.local_dirname, self.compiled_file_path + self.file_name_contract + "_hash" ), "w") as f:
            f.write(cur_file_hash)
            f.close()
        return compiled_sol

    def deploy(self, v0, recompile=True):
        if recompile:
            compiled_sol = self.compile_contract()
        else:
            with open(os.path.join(self.local_dirname, self.compiled_file_path + self.file_name_contract + '.json'), "r") as f:
                compiled_sol = json.load(f)

        bytecode = compiled_sol["contracts"][self.file_name_contract][self.contract_tx_name]["evm"][
            "bytecode"
        ]["object"]

        abi = compiled_sol["contracts"][self.file_name_contract][self.contract_tx_name]["abi"]

        contractobj = self.w3.eth.contract(abi=abi, bytecode=bytecode)

        try:
            self.account_address = Web3.toChecksumAddress(self.account_address)
            nonce = self.w3.eth.get_transaction_count(self.account_address)
            transaction = contractobj.constructor(v0).buildTransaction(
                {"chainId": self.chain, "from": self.account_address, "nonce": nonce}
            )
        except:
            self.account_address = Web3.toChecksumAddress(self.account_address)
            nonce = self.w3.eth.get_transaction_count(self.account_address)
            transaction = contractobj.constructor(v0).buildTransaction(
                {"chainId": self.chain, "from": self.account_address, "nonce": nonce}
            )
        signed_txn = self.w3.eth.account.sign_transaction(transaction, private_key=self.private_key)
        tx_hash =  self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        tx_receipt =  self.w3.eth.wait_for_transaction_receipt(tx_hash)
        self.deployed_address = tx_receipt.contractAddress

