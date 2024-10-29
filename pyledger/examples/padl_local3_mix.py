import os
import sys
from pathlib import Path

path = os.path.realpath(__file__)
parent_dir = str(Path(path).parents[2])
sys.path.append(parent_dir)
from pyledger.ledger import Bank, MakeLedger
from pyledger.create_tx import *
from pyledger.extras.evmnet.participant_scripts import *

from pyledger.ledger import  BankCommunication
dummy_communication = BankCommunication()

logging.basicConfig(level=logging.INFO)
n_banks = 3

ledger = MakeLedger(dummy_communication)
banks = []

# register banks
for b in range(n_banks):
    bank = ledger.register_new_bank(v0=[1000,1000], types={0: 'xcoin', 1: 'ycoin'}, tx_obj=InjectiveTx())
    banks.append(bank)

print("Number of Bank:",ledger.get_set_n_banks())
assert ledger.get_set_n_banks() == n_banks, "Numberof enrolled bank does not match"


distributed_tx = banks[0].create_asset_tx(vals=[[-10, 0, 10], [-10, 0, 10]], ledger=ledger, pub_keys=ledger.pub_keys,  audit_pk=None)
ledger.push_inject_tx(distributed_tx, send_ID=0, verify=True)
print(banks[0].get_balance())
print(banks[1].get_balance())
print(banks[2].get_balance())
distributed_tx = banks[0].create_rand_tx(n_banks, ledger.pub_keys)
ledger.populate_tx(distributed_tx)
ledger.push_tx(distributed_tx)
print(banks[0].get_balance())
print(banks[1].get_balance())
print(banks[2].get_balance())
distributed_tx = banks[1].create_asset_tx(vals=[[0,-10, 10], [0, -5, 5]], ledger=ledger, pub_keys=ledger.pub_keys, audit_pk=None)
ledger.push_inject_tx(distributed_tx, send_ID=1, verify=True)
print(banks[0].get_balance())
print(banks[1].get_balance())
print(banks[2].get_balance())
distributed_tx = banks[0].create_rand_tx(n_banks, ledger.pub_keys)
ledger.populate_tx(distributed_tx)
ledger.push_tx(distributed_tx)
print(banks[0].get_balance())
print(banks[1].get_balance())
print(banks[2].get_balance())



















