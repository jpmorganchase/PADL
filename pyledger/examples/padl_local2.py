"""Example of a simple ledger - all local, no services"""
import os
import sys
from pathlib import Path
import time
path = os.path.realpath(__file__)
parent_dir = str(Path(path).parents[2])
sys.path.append(parent_dir)


from pyledger.ledger import Bank, MakeLedger, BankCommunication, Auditing
import logging
from pyledger.Proof_Generation import ProofGenerator
logging.basicConfig(level=logging.INFO)

n_banks = 2

dummy_communication = BankCommunication()
ledger = MakeLedger(dummy_communication)

banks = []

# register banks
for b in range(n_banks):
    bank = ledger.register_new_bank(v0=[1000], types={0: 'xcoin'})
    banks.append(bank)

for i in range(2):
    bi = i % n_banks
    print('Bank {} makes Tx no. {}'.format(bi, i))
    distributed_tx = banks[bi].create_rand_tx(n_banks, ledger.pub_keys, audit_pk=banks[0].pk)
    ledger.populate_tx(distributed_tx)
    ledger.push_tx(distributed_tx)

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
    distributed_tx = banks[bi].create_rand_tx(n_banks, ledger.pub_keys)
    ledger.populate_tx(distributed_tx)
    ledger.push_tx(distributed_tx)
    distributed_tx = banks[bi].create_rand_tx(n_banks, ledger.pub_keys)
    ledger.populate_tx(distributed_tx)
    ledger.push_tx(distributed_tx)

print(banks[0].get_balances_from_state(ledger))

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
txs = [tx.copy() for _ in range(3)]
distributed_tx = banks[0].create_asset_tx(txs, n_banks, ledger.pub_keys, sparse_tx=True)
ledger.populate_tx(distributed_tx)
ledger.push_tx(distributed_tx)

txs = [tx.copy() for _ in range(3)]
distributed_tx = banks[0].create_asset_tx(txs, n_banks, ledger.pub_keys)
ledger.populate_tx(distributed_tx)
ledger.push_tx(distributed_tx)
print(banks[0].get_balances_from_state(ledger))
logging.info("test - adding asset, pass")

# ------------------- test auditing of asset --------------
# generate balance proof
scst = ledger.compute_sum_commits_tokens()

for asset_id in range(2):
    pr, sval = (ProofGenerator().generate_asset_balance_proof(scst, asset_id, banks[0], ledger))
    assert Auditing.verify_asset_balance(scst, ledger.gh, pr, sval, 0, asset_id), "auditing is wrong"
    sval[asset_id] = sval[asset_id] + 5
    assert not Auditing.verify_asset_balance(scst, ledger.gh, pr, sval, 0, asset_id), "auditing is wrong"

logging.info("test - auditing, pass")



# generate ratio asset threshold proof
proof=banks[0].generate_asset_ratio_proof(asset=1, n=1,d=4)
Auditing.valdiate_proof_of_ratio_asset(ledger,proof, asset=1, n=1,d=4)

logging.info("test - auditing, pass")