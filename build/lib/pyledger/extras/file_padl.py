"""PADL - GTAR - London, JPMorgan"""
import sys
import os
from pathlib import Path
path = os.path.realpath(__file__)
parent_dir = str(Path(path).parents[1]) # go up 2 levels [1] to '/zkledgerplayground/'
sys.path.append(parent_dir)

from pyledger.ledger import Bank, MakeLedger, MAX
from pyledger.zkutils import r_blend
import zkbp
import json


class LedgerFile(MakeLedger):
    def __init__(self, path, communication, name):
        self.path = path # ledger file path
        self.communication = communication
        self.id = -1
        self.bank_name = name
        super().__init__(self.communication)


    def create_new_ledger(self, address_def_bank):
        bank = Bank(self, v0=[MAX], name=self.bank_name, types={0: 'padl'}, address=address_def_bank)
        print(bank.id, self.id, len(self.pub_keys))
        if bank.id !=0:
            AssertionError("ledger should be empty")
        self.id = bank.id
        print("your id is set to 0")
        content = {"accounts": [bank.pk], "zero_line": [MakeLedger.Cell.list_to_json(bank.initial_assets_cell)], "Ledger": MakeLedger.to_json(self.txs)}
        json_details = json.dumps(content)
        with open(self.path, "w") as outfile:
            outfile.write(json_details)

    def read_ledger(self):
        with open(self.path, "r") as outfile:
            data_json = outfile.read()
        data = json.loads(data_json)
        return data

    def join_to_ledger(self, bank):
        data = self.read_ledger()
        id = len(data['accounts'])
        data['accounts'].append(bank.pk)
        if isinstance(data['zero_line'],str):
            data['zero_line'] = json.loads(data['zero_line'])
        data['zero_line'].append(MakeLedger.Cell.list_to_json(bank.initial_assets_cell))  
        data_json = json.dumps(data)
        with open(self.path, "w") as outfile:
            outfile.write(data_json)
        with open(self.path, "r") as outfile:
            ledger0 = outfile.read()
        print("your id:", id)
        self.id = id
        return id

    def get_ledger_from_file(self):
        data = self.read_ledger()
        super().__init__(self.communication)
        self.txs = MakeLedger.txs3d_from_json(data['Ledger'])
        for account in data['accounts']:
            id = self.register_bank(account, "")
        self.zero_line = MakeLedger.txs_from_json(data['zero_line'])
        return self

    def load_bank_from_file(self, bank_file_name=""):
        if bank_file_name=="":
            bank_file_name = self.bank_name + " " + str(self.id)
        else:
            self.id =int(bank_file_name.split()[-1])
            self.bank_name = bank_file_name.split()[0]
        try:
            with open(bank_file_name, 'rb') as file:
                bank_details = json.load(file)
        except FileNotFoundError:
            print('file not found')
        dummy_ledger = MakeLedger(self.communication) # must be 1 so using dummy
        bank = Bank(dummy_ledger, v0=[0], types={0: 'padl'},name=self.bank_name, serialise=False)
        print(bank.v0)
        for key, val in zip(list(bank_details.keys()), list(bank_details.values())):
            bank.__dict__[key] = val
        # de-serailsing lists:
        bank.secret_book = json.loads(bank.secret_book)
        bank.r0 = [r_blend(zkbp.to_scalar_from_str(r0)) for r0 in json.loads(bank.r0)]
        bank.sk_pk_obj = zkbp.regen_pb_sk(bank.gh, zkbp.to_scalar_from_str(bank.sk))
        for ai in bank.secret_book: # from strings to r objects
            for tx in ai:
                tx[1] = r_blend(zkbp.to_scalar_from_str(tx[1]))
        if bank.pk != self.pub_keys[self.id]:
            AssertionError("bank file miss-match with ledger index of the bank")
        print(self.id, bank.v0)
        bank.serialise()
        return bank

    def update_ledger_file(self):
        content = {"accounts": self.pub_keys, "zero_line": MakeLedger.to_json(self.zero_line),
                   "Ledger": MakeLedger.to_json(self.txs)}
        json_details = json.dumps(content)
        print(self.path)
        with open(self.path, "w") as outfile:
            outfile.write(json_details)
        with open(self.path, "r") as outfile:
            ledger0 = outfile.read()

    def add_val_r_secret_book(self, str_vr):
        list_vr = json.loads(str_vr)
        bank = self.load_bank_from_file()
        for a, val_ra in enumerate(list_vr):
            print(val_ra)
            r = r_blend(zkbp.to_scalar_from_str(val_ra[1]))
            bank.append_asset_to_book(a, (val_ra[0], r), val_ra[2])
        bank.serialise()
