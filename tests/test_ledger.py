from unittest import TestCase
import os, glob, sys
from pathlib import Path

import warnings
path = os.path.realpath(__file__)
parent_dir = str(Path(path).parents[1]) # go up 2 levels to '/zkledgerplayground/'
sys.path.append(parent_dir)
from pyledger.ledger import Bank, MakeLedger, BankCommunication, Auditing
import logging

 
from eth_account import Account
from pyledger.create_tx import *
from pyledger.extras.evmnet.participant_scripts import *
from pyledger.Proof_Generation import ProofGenerator
from pyledger.Proof_verification import Auditing
from pyledger.extras.evmnet.participant_scripts import *

class TestLocal(TestCase):
    def test_add_asset(self):
        logging.basicConfig(level=logging.INFO)
        n_banks = 5
        dummy_communication = BankCommunication()
        ledger = MakeLedger(dummy_communication)
        banks = []
        # register banks
        for b in range(n_banks):
            bank = ledger.register_new_bank(v0=[1000, 1000], types={0: 'xcoin', 1: 'ycoin'})
            banks.append(bank)

        # ------------------- make random Txs --------------
        for i in range(2):
            bi = i % n_banks
            print('Bank {} makes Tx no. {}'.format(bi, i))
            distributed_tx = banks[bi].create_rand_tx(n_banks, ledger.pub_keys)
            ledger.populate_tx(distributed_tx)
            ledger.push_tx(distributed_tx)
        logging.info("test - make txs, pass")

        # ------------------- adding dynamically asset --------------
        init_cell_asset=banks[0].add_asset(2000, asset_type="zcoin")
        ledger.register_new_asset(init_cell_asset,0)
        tx = [0] * n_banks
        tx[0] = -100
        tx[1] = 100
        txs = [tx.copy() for _ in range(3)]
        distributed_tx = banks[0].create_asset_tx(txs, n_banks, ledger.pub_keys)  
        ledger.populate_tx(distributed_tx)
        ledger.push_tx(distributed_tx)
        logging.info("test - adding asset, pass")
        self.assertFalse(len(banks[-1].v0) != 3) 

       
        bal = banks[0].check_balance_tx(distributed_tx, ledger)
        assert bal == [-100, -100, -100], 'Transaction error'


    
    def test_setup_tx(self):
        logging.basicConfig(level=logging.INFO)
        n_banks = 20
        dummy_communication = BankCommunication()
        ledger = MakeLedger(dummy_communication)
        banks = []
        # register banks
        for b in range(n_banks):
            bank = ledger.register_new_bank(v0=[10,100,1000], types={0: 'xcoin', 1: 'ycoin', 2: 'zcoin'})
            banks.append(bank)


        # ------------------- make random Txs --------------
        for i in range(1):
            bi = i % n_banks
            print('Bank {} makes Tx no. {}'.format(bi, i))
            distributed_tx = banks[bi].create_rand_tx(n_banks, ledger.pub_keys) 
            ledger.populate_tx(distributed_tx)
            ledger.push_tx(distributed_tx)
        logging.info("test - make txs, pass")

        self.assertIs(len(banks[-1].v0), 3) 



        bal = banks[0].check_balance_tx(distributed_tx, ledger)


        all_less_or_equal = all(a <= b for a, b in zip(bal, [10,100,1000]))

        assert all_less_or_equal, 'Transaction error'

    def test_txs(self):
        logging.basicConfig(level=logging.INFO)
        n_banks = 3
        dummy_communication = BankCommunication()
        ledger = MakeLedger(dummy_communication)
        banks = []
        # register banks
        for b in range(n_banks):
            bank = ledger.register_new_bank(v0=[10000,10000,10000], types={0: 'xcoin', 1: 'ycoin', 2: 'zcoin'})
            banks.append(bank)
        # in dummy run we just share the bank obj.
        # ------------------- make random Txs --------------
        for i in range(3):
            bi = i % n_banks
            print('Bank {} makes Tx no. {}'.format(bi, i))
            distributed_tx = banks[bi].create_rand_tx(n_banks, ledger.pub_keys)
            ledger.populate_tx(distributed_tx)
            ledger.push_tx(distributed_tx)
        logging.info("test - make txs, pass")

        self.assertIs(len(banks[-1].v0), 3) 

        bal = banks[0].check_balance_tx(distributed_tx, ledger)

        all_less_or_equal = all(a <= b for a, b in zip(bal, [10000,10000,10000]))

        assert all_less_or_equal, 'Transaction error'

    def test_injective_txs(self):
        """test functions relevant to injective transactions
        """
        logging.basicConfig(level=logging.INFO)
        n_banks = 3
        dummy_communication = BankCommunication()
        ledger = MakeLedger(dummy_communication)
    
    
        banks = []
    
        # register banks
        for b in range(n_banks):
            bank = ledger.register_new_bank(v0=[1000], types={0: 'xcoin'}, tx_obj=InjectiveTx())
            banks.append(bank)
    
        print("Number of Bank:",ledger.get_set_n_banks())
        assert ledger.get_set_n_banks() == n_banks, "Numberof enrolled bank does not match"
        # transactions = [[[-10,0, 10]], [[-50, 0, 50]], [[-100,0, 100]]]
        transactions = [[[-10,0, 10]]]
    
    
        for i in range(len(transactions)):
            vals= transactions[i]
            distributed_tx = banks[0].create_asset_tx(vals=vals, ledger=ledger, pub_keys=ledger.pub_keys, audit_pk=None)
            ledger.push_inject_tx(distributed_tx, send_ID=0, verify=True)




    def test_injective_txs_with_solidity(self):
        warnings.warn(
            "deprecated_function() is deprecated and will be removed in a future version.",
            DeprecationWarning,
            stacklevel=2  # Shows the warning in the caller's stack
        )
        # Function logic (optional)
        print("This is a deprecated function.")


