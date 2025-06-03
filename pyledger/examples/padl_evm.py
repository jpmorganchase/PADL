"""
Example of a transaction on EVM network either on cloud or local.
IP addresses configs are in contractpadl.py

Instructions:
in order to run this example. Two services need to be up. 
1. run: python cloud_server/python_storage/serv.py
(this service is a simple storage for the proofs and archive of the transactions)
2. run an evm node. For simplicity, you can use ganache-cli with the following launch command line: 
ganache-cli --miner.blockGasLimit 10000000000000000 --miner.callGasLimit 1000000000000000
--account="0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63,10000000000000000000000000"
or:
ganache-cli --account="0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63,10000000000000000000000000"

"""
from eth_account import Account
import time
import os
import sys
from pathlib import Path
import time
path = os.path.realpath(__file__)
parent_dir = str(Path(path).parents[2])
sys.path.append(parent_dir)
from pyledger.extras.evmnet.participant_scripts import *

import logging

def main(): 
    # use secret key for issuer, in this example, it should be an account already registered in EVM
    example_private_key = '0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63'
    LocalAccount = Account.from_key(example_private_key)
    print(LocalAccount.encrypt("padltest!"))

    # starting a new ledger, and deployer already by default added itself as an issuer.
    contract_address = deploy_new_contract(example_private_key, v0=[1000,1000], types={'0': 'x', '1': 'y'})

    # adding another participant to the list to give access to contract.
    account_dict = create_account(contract_address)
    add_participant(account_dict['address'])

    ledger, issuer = get_ledger_bank_padl("Issuer 0")
    public_key = issuer.pk
    # register new bank in padl ledger (issuer is done by default using deploy_new_contract().
    register_padl(name="Bank", v0=[10,10], types={'0': 'x', '1': 'y'}, account_dict=account_dict, audit_pk=public_key)
    bank_send_deposit(account_dict,10)
    check_balance("Bank 1")
    # adding another participant to the list to give access to contract.
    account_dict = create_account(contract_address)
    add_participant(account_dict['address'])
    # register new bank in padl ledger (issuer is done by default using deploy_new_contract().
    register_padl(name="Bank", v0=[10,10], types={'0': 'x', '1': 'y'}, account_dict=account_dict, audit_pk=public_key)
    bank_send_deposit(account_dict,10)
    check_balance("Bank 2")

    for txx in range(3):
            # issuer
            tx = send_coins(vals=[ [-2, 0, 2],[-2, 0, 2] ], file_name="Issuer 0", audit_pk=public_key) # this is the broadcast  (tx + approve tx by issuer)
            # participant
            tx0 = add_proof("Issuer 0")
            tx1 = add_proof("Bank 1")
            tx2 = add_proof("Bank 2")

            # # # issuer audit and vote.
            # vote_tx("Issuer 0")0
            #
            # # participant. audit and vote.
            # vote_tx("Bank 1")
            # vote_tx("Bank 2")

            # later on smart contract to append to ledger
            finalize_tx("Issuer 0", Issuer=True)

            check_balance("Bank 1")
            check_balance("Bank 2")

            check_all_balances_audit("Issuer 0")
            print('=='*20)

            tx = send_coins(vals=[[-20, 0, 20],[-20, 0, 20]], file_name="Issuer 0", audit_pk=public_key) # this is the broadcast  (tx + approve tx by issuer)
            # participant
            tx0 = add_proof("Issuer 0")
            tx1 = add_proof("Bank 1")
            tx2 = add_proof("Bank 2")

            # # issuer audit and vote.
            # vote_tx("Issuer 0")
            #
            # # participant. audit and vote.
            # vote_tx("Bank 1")
            # vote_tx("Bank 2")

            # later on smart contract to append to ledger
            finalize_tx("Issuer 0", Issuer=True)

            check_balance_by_state("Bank 1")
            check_balance("Bank 1")
            check_balance_by_state("Bank 2")
            check_balance("Bank 2")
            check_all_balances_audit("Issuer 0")
            print('=='*20)
            send_injective_tx(vals=[[0, -2, 2],[0, -2, 2]], file_name="Bank 1")
            check_balance_by_state("Bank 1")
            check_balance_by_state("Bank 2")
            print('=='*100)


if __name__ == '__main__':
    main()