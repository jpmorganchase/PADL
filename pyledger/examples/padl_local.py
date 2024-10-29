"""Local zkledger using bulletproofs/sigma protocls"""
import os
import sys
from pathlib import Path
import time
path = os.path.realpath(__file__)
parent_dir = str(Path(path).parents[2])
sys.path.append(parent_dir)

from pyledger.ledger import Bank, BankCommunication
import logging
logging.basicConfig(level=logging.INFO)
from pyledger.extras.file_padl import LedgerFile

def main(): 
    ledger = LedgerFile(path=r"./Ledger.json",
                        communication=BankCommunication(),
                        name="Bank")
    n_banks = 2
    n_assets = 1
    n_txs = 4
    banks = []
    # register banks
    for b in range(n_banks):
        bank = ledger.register_new_bank(v0=[100]*n_assets,
                                        types=dict(zip([i for i in range(n_assets)],['padl'+str(l) for l in range(n_assets)])))
        banks.append(bank)
    t0=time.time()
    for i in range(n_txs):
        t1=time.time()
        bi = i % n_banks
        print('Bank {} makes Tx no. {}'.format(bi, i))
        distributed_tx = banks[bi].create_rand_tx(n_banks, ledger.pub_keys)

        ledger.populate_tx(distributed_tx)
        t2 = time.time()
        print("proof time",t2-t1)
        ledger.push_tx(distributed_tx)
        t3=time.time()
        print("validation time", t3-t2)
    print("--------------Local Run Experiment-------------")
    print("time for tx of", n_assets, "and ", banks, "banks:", (time.time()-t0)/n_txs)
    print("average tx per party and asset",(time.time()-t0)/(n_txs*n_assets*n_banks))

    ledger = LedgerFile(path=r"./Ledger.json",
                        communication=BankCommunication(),
                        name="Bank")
    n_banks = 10
    n_assets = 10
    n_txs = 2
    banks = []
    # register banks
    for b in range(n_banks):
        bank = ledger.register_new_bank(v0=[100]*n_assets,
                                        types=dict(zip([i for i in range(n_assets)],['padl'+str(l) for l in range(n_assets)])))
        banks.append(bank)
    t0=time.time()
    for i in range(n_txs):
        t1=time.time()
        bi = i % n_banks
        distributed_tx = banks[bi].create_rand_tx(n_banks, ledger.pub_keys)

        ledger.populate_tx(distributed_tx)
        t2 = time.time()
        print("proof time",t2-t1)
        ledger.push_tx(distributed_tx)
        t3=time.time()
        print("validation time", t3-t2)
    print("--------------Local Run Experiment-------------")
    print("no. asset", n_assets, ", no. banks", n_banks)
    print("time for tx of", n_assets, "and ", banks, "banks:", (time.time()-t0)/n_txs)
    print("average tx per party and asset",(time.time()-t0)/(n_txs*n_assets*n_banks))

if __name__ == '__main__':
    main()
