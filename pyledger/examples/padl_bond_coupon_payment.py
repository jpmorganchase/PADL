import sys
import zkbp
import os
import sys
from pathlib import Path
#sys.path.append("../..")
path = os.path.realpath(__file__)
parent_dir = str(Path(path).parents[2])
sys.path.append(parent_dir)
from pyledger.ledger import  MAX, BankCommunication
from zkutils import Commit
from pyledger.extras.file_padl import LedgerFile
n_banks = 5

ledger = LedgerFile(path=r"./Ledger.json",
                     communication=BankCommunication(),
                     name="Bank")
b = 4

# create participants, bond issuer add the bonds units,
# the name of the bond asset provides the value and rate of the bond.
custodian = ledger.register_new_bank(v0=[MAX, 0], types={0: "USD", 1: r"Bonds10$2y10%"}, name='Custodian')
bondsissuer = ledger.register_new_bank( v0=[0, 300], types={0: "USD", 1: r"Bonds10$2y10%"}, name="BondIssuer")
broker = ledger.register_new_bank( v0=[0, 0], types={0: "USD", 1: r"Bonds10$2y10%"}, name='Broker')
investorM = ledger.register_new_bank( v0=[0, 0], types={0: "USD", 1: r"Bonds10$2y10%"}, name = "Investor M")
investorN = ledger.register_new_bank( v0=[0, 0], types={0: "USD", 1: r"Bonds10$2y10%"}, name="Investor N")

banks = [custodian, bondsissuer, broker, investorM, investorN]
tx = [0] * n_banks
n_assets = 2
txs = [tx.copy() for _ in range(n_assets)]

# transactions from custodian to Investor M: custodian transfers 2000 usd to investor M for maximum investment in bond:
tx1 = [[-2000, 0, 0, 2000, 0],
       [0, 0, 0, 0, 0]]

distributed_tx = custodian.create_asset_tx(tx1, n_banks, ledger.pub_keys)
ledger.populate_tx(distributed_tx)
ledger.push_tx(distributed_tx)
# transaction from custodian to Investor N: custodian transfers 2000 usd to investor N for maximum investment in bond:
tx2 = [[-2000, 0, 0, 0, 2000],
       [0, 0, 0, 0, 0]]
distributed_tx = custodian.create_asset_tx(tx2, n_banks, ledger.pub_keys)
ledger.populate_tx(distributed_tx)
ledger.push_tx(distributed_tx)

# broker creates an exchange tx between issuer and investors (broker is the only one that knows values of the deal)
# the tx: is issuer gets 3000$ (2000$ from M and 1000$ from N, issuer can only verify it is 3000$ and consistency but cannot see 1000$,2000$)
# in returns, it sends 300 of Bonds10$2y10% the broker makes the tx such as m gets 200 bonds units and n 100 units, which they verify during tx).
tx3 = [[0, 3000, 0, -2000, -1000],
       [0, -300, 0, 200, 100]]
distributed_tx = broker.create_asset_tx(tx3, n_banks, ledger.pub_keys)
ledger.populate_tx(distributed_tx)
ledger.push_tx(distributed_tx)

# coupon futures txs, 10% yearly coupon, the transactions created by broker, and broadcasted by issuer
tx4_yr1 = [[0, -300, 0, 200, 100],
           [0, 0, 0, 0, 0]]
# coupon futures txs, 10% yearly coupon, the transactions created by broker, and broadcasted by issuer
tx5_yr2 = [[0, -300, 0, 200, 100],
           [0, 0, 0, 0, 0]]

distributed_tx_coupon1 = broker.create_asset_tx(tx4_yr1, n_banks, ledger.pub_keys)
ledger.populate_tx(distributed_tx)
# Complementary proof that added by parties in the tx which shows the right coupon and that everyone is honest.
# for demo we make this proof here, later we will add this into pyledger proofs.
# -------------------------- coupon payment ratio proof -------------------------
# prover (investors,issuers) calculates:
#                    C = tx3.cm*tx4_yr1.cm^(inverse_coupon_rate),
#                    T = tx3.token*tx4_yr1.token^(inverse_coupon_rate)
# prover generates a proof that it has x which solves: the DLP: x = log T, here notes that only prover has sk to solve this.
# verifier: calculates C, and T, and verifies with the proof generated that prover could solve the DLP.
# -------------------------------------------------------------------------------
for i in range(n_banks):  # proof is important only for issuer and investors but fulfills also for other zeros value participants
    inverse_rate = 10
    cm_coupon = Commit.from_str(distributed_tx_coupon1[0][i].cm)
    cm_bond_tx = Commit.from_str(distributed_tx[0][i].cm)
    token_coupon = Commit.from_str(zkbp.to_token_from_str(distributed_tx_coupon1[0][i].token).get)
    token_bond_tx = Commit.from_str(zkbp.to_token_from_str(distributed_tx[0][i].token).get)
    C = cm_bond_tx + (cm_coupon * inverse_rate)
    T_inter = token_bond_tx + (token_coupon * inverse_rate)
    T = zkbp.to_token_from_str(T_inter.eval.get)
    pbsk = banks[i].sk_pk_obj
    # shared proof by the prover:
    public_proof = zkbp.sigma_dlog_proof_explicit(T, pbsk, C.eval)
    # everyone can calculate C and T and verifies this automatically:
    verified_proof = zkbp.sigma_dlog_proof_explicit_verify(public_proof, C.eval, T)
    assert verified_proof

# do validation as before: validate_ratio_coupon_proof(distributed_tx, distributed_tx_coupon2)

# issuer does in the right time (probably with a smart contract):
ledger.populate_tx(distributed_tx_coupon1)
ledger.push_tx(distributed_tx_coupon1)

distributed_tx_coupon2 = broker.create_asset_tx(tx5_yr2, n_banks, ledger.pub_keys)
# again we will generate the additional proof for coupon
# issuer does in the right time (probably with a smart contract):
ledger.populate_tx(distributed_tx_coupon2)
ledger.push_tx(distributed_tx_coupon2)

# before maturity, bond issuer needs to have enough fund to return back the money, hence issuer needs to transfer
# extra money from custodian to cover interests and fee:
tx6 = [[-1000, 1000, 0, 0, 0],
       [0, 0, 0, 0, 0]]
distributed_tx = custodian.create_asset_tx(tx6, n_banks, ledger.pub_keys)
ledger.populate_tx(distributed_tx)
ledger.push_tx(distributed_tx)

# broker finally creates a tx to burn bonds and return the money from issuer to investors.
# broker also earns fees of 0.1% for all the hard work.
tx7_burn_bonds = [[0, -3003, 6, 1998, 999],
                  [0, 300, 0, -200, -100]]

distributed_tx = broker.create_asset_tx(tx7_burn_bonds, n_banks, ledger.pub_keys)
ledger.populate_tx(distributed_tx)
ledger.push_tx(distributed_tx)
print("end")
