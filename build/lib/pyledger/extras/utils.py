"""utilities"""
import sys
import os
from pathlib import Path
path = os.path.realpath(__file__)
parent_dir = str(Path(path).parents[1])
sys.path.append(parent_dir)

from pyledger.ledger import Bank, MakeLedger, BankCommunication
from pyledger.create_tx import *

def load_bank_from_file(bank_file_name=str(), ledger=MakeLedger(comm=BankCommunication())) -> Bank:
    """
    Loading serialised bank from a file path
    :param bank_file_name: serialised bank file
    :type bank_file_name: String
    :param ledger: attaching ledger
    :type ledger: MakeLedger
    :return: Bank object
    :rtype: Bank
    """
    bank_name = bank_file_name.split()[0]
    bank = Bank(ledger, [0], types={0: 'padl'}, name=bank_name, serialise=False)  # default bank
    try:
        with open(bank_file_name, 'rb') as file:
            bank_details = json.load(file)
    except:
        return bank
    for key, val in zip(list(bank_details.keys()), list(bank_details.values())):
        bank.__dict__[key] = val
    
    bank.secret_balance_book = json.loads(bank.secret_balance_book)
    bank.r0 = [r_blend(zkbp.to_scalar_from_str(r0)) for r0 in json.loads(bank.r0)]
    bank.sk_pk_obj = zkbp.regen_pb_sk(bank.gh,
                                      zkbp.to_scalar_from_str(bank.sk))
    for ai in bank.secret_balance_book:  # from strings to r objects
        for tx in ai:
            tx[1] = r_blend(zkbp.to_scalar_from_str(tx[1]))

    
    return bank

