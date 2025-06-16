"""
All Padl objects require Bank as a participant private object,
and a ledger object which is publicly distributed.
GTAR - London - JPMorgan Chase
"""
import logging
import zkbp  # module interface to Rust curv, bulletproofs zero-gen, and sigma proofs.
from functools import reduce
import json
import random
import os
import time
import sys
from pathlib import Path
from multiprocessing import Pool
from multiprocessing.pool import ThreadPool as Poolt
from functools import partial

from pyledger.create_tx import CreateTx, InjectiveTx, InjectiveTxSmartContract
logging.basicConfig(level=logging.WARN, format='%(message)s')

path = os.path.realpath(__file__)
parent_dir = str(Path(path).parents[1])
sys.path.append(parent_dir)
from pyledger.zkutils import Commit, Token, r_blend, curve_util
from pyledger.extras.injective_utils import InjectiveUtils
from pyledger.Proof_Generation import ProofGenerator
from pyledger.Proof_verification import Auditing

# BITS = 64
BITS = 32
# MAX = int(2 ** (BITS / 4))
MAX = int(2 ** 16)

from enum import Enum
class TransactionMode(Enum):
    NonInjective_OffChain = 1
    Injective_OnChain = 2
    Injective_OffChain = 3

class Bank:
    """
    This object is Padl Participant object for the ledger.
"""
    def __init__(self, ledger,
                 v0=None,
                 types=None,
                 port=4000,
                 address="https://localhost",
                 contract_address="",
                 name='Bank',
                 serialise=True,
                 secret_key=None,
                 initial_asset_cell=None,
                 audit_pk=None,
                 audit_account={},
                 contract_tx_name='',
                 file_name_contract='',
                 tx_obj=CreateTx()
                 ):
        """
    initalise object for participant
    :param ledger : MakeLedger object of a ledger from file or local
    :param v0 : list of initial assets value
    :param types : Dict. asset types
    :param port: port of string
    :param address: string participant name and file name
    :param contract_address: for evm deployment only
        """
        self.gh = ledger.gh
        if secret_key:
            secret_scalar = curve_util.to_scalar(secret_key)
            self.sk_pk_obj = zkbp.regen_pb_sk(self.gh, secret_scalar)  # generate pair sk/pk
        else:
            self.sk_pk_obj = zkbp.gen_pb_sk(self.gh)   # generate new pair sk/pk
        self.sk = self.sk_pk_obj.get_sk()  # scalar json kept secret.
        self.pk = self.sk_pk_obj.get_pk()  # point json which is shared.

        if secret_key:
            self.sk_ext = secret_key
        else:
            self.sk_ext = self.sk

        if v0 is None:
            v0 = [0]
        if initial_asset_cell is not None:
            v0 = self.extract_vals_cell(initial_asset_cell)
        self.v0 = v0  # initial assets value in a list
        self.nassets = len(self.v0)  # total number of assets

        try:
            self.id = ledger.pub_keys.index(self.pk)
        except:
            self.id = ledger.get_set_n_banks()
        self.name = name

        # communication
        self.bank_comm = ledger.bank_comm
        # commits and rs
        self.part_rs = []


        self.r0 = []
        for i in range(self.nassets):
            self.r0.append(r_blend())

        self.cm0 = [Commit(self.gh, v, self.r0[i]) for i, v in enumerate(self.v0)]
        self.token0 = [self.sk_pk_obj.to_token(rl0.get()) for rl0 in self.r0]
        self.secret_balance_book = [[(self.v0[a], self.r0[a])] for a in range(self.nassets)]  # (balance values, rs values of assets) for each asset
        # initial cell to be set in zero-line of the ledger
        self.initial_assets_cell = [MakeLedger.Cell(token=t.get, cm=c.eval.get, cm_=c.eval.get, token_=t.get) for c, t
                                    in zip(self.cm0, self.token0)]

        if initial_asset_cell:
            for a in range(len(initial_asset_cell)):
                self.initial_assets_cell[a].cm = initial_asset_cell[a].cm
                self.initial_assets_cell[a].token = initial_asset_cell[a].token
                self.initial_assets_cell[a].P_Eq = ProofGenerator().generate_value_eq_cm_proof(self.initial_assets_cell[a].token,
                                                                                   self.initial_assets_cell[a].cm,
                                                                                   self.initial_assets_cell[a].token_,
                                                                                   self.initial_assets_cell[a].cm_, a, self.sk_pk_obj)
        if audit_pk:
            audit_tokens = [zkbp.to_token_from_pk(audit_pk, rl0.get()).get for rl0 in self.r0]
            for a in range(len(self.initial_assets_cell)):
                self.initial_assets_cell[a].meta_data = {"audit": audit_tokens[a]}

        self.cm_account_info = {}
        for key in audit_account:
            if key == 'audit': key = 'audit_1'
            v = audit_account[key]['value']
            aud_pk = audit_account[key]['audit_pk']
            if aud_pk is None:
                aud_pk=self.pk
            r = r_blend()
            cm = Commit(self.gh, v, r)
            t = zkbp.to_token_from_pk(aud_pk, r.get())
            self.cm_account_info[key]= {'cm': cm, 'v': v, 'r': r}
            self.initial_assets_cell[0].meta_data[key] = cm.eval.get+'_'+t.get


        if types:
            self.asset_secret_map = types
        else:
            self.asset_secret_map = {}

        self.auditor_proofs = []
        self.auditor_proofs_ratio = []
        self.port = port
        if address is not None:
            if 'http' in address:
                self.address = address + ":" + str(self.port)
            else:
                self.address = address
        else:
            self.address = self # only for local test purposes

        self.contract_address = contract_address
        self.contract_tx_name = contract_tx_name
        self.file_name_contract = file_name_contract
        # new tx info
        self.approval_result = False
        self.new_tx_info = True
        self.new_tx = []
        self.state_cm_token = []
        self.origin_tx_id = -1
        self.received_latest_assets = []

        self.distributed_tx = ledger.distributed_tx
        # saving ledger address and getting the id from ledger
        self.ledger_address = ledger.address
        id = ledger.register_bank(self.pk, self.address)
        if self.id != id:
            AssertionError("ledger and input id should be the same")
        #
        ledger.register_zero_line(self.initial_assets_cell)

        self.tx_obj = tx_obj
        self.tx_type = self.tx_obj.__class__.__name__

        self.txs_log = []
        if serialise:
            self.serialise()
        logging.info("registered participant {} in port {}".format(self.id, self.port))
        
    
    def set_tx_type(self, tx_obj=CreateTx()):
            self.tx_obj = tx_obj
            self.tx_type = self.tx_obj.__class__.__name__

        
    def serialise(self):
        """serialising all necessary private details,
        this can be later be used to save and reload participant information.
        :return: file name
        """
        json_details = self.serialise_json()
        # Writing to sample.json
        file_name = self.name + " " + str(self.id)
        self.file_name = file_name

        with open(file_name, "w") as outfile:
            outfile.write(json_details)
        return file_name

    def serialise_json(self):
        """the wallet dict to be serialised - cannot be shared"""
        json_details = json.dumps({'sk': self.sk,
                                   'pk': self.pk,
                                   'sk_ext': self.sk_ext,
                                   'address': self.address,
                                   'contract_address': self.contract_address,
                                   'contract_tx_name' : self.contract_tx_name,
                                   'file_name_contract' : self.file_name_contract,
                                   'ledger_address': self.ledger_address,
                                   'v0': self.v0,
                                   'txs_log': self.txs_log,
                                   'id': self.id,
                                   'state_cm_token': self.state_cm_token,
                                   'nassets': self.nassets,
                                   'asset_secret_map': self.asset_secret_map,
                                   'secret_balance_book': json.dumps(
                                       [[(tx[0], tx[1].val.get) for tx in ai] for ai in self.secret_balance_book]),
                                   'r0': json.dumps([r0a.to_str() for r0a in self.r0]),
                                   'asset_map': self.asset_secret_map})
                                   
        # Writing to sample.json
        return json_details


    @staticmethod
    def deserialise(bank_file_name=""):
        bank_name = bank_file_name.split()[0]
        try:
            with open(bank_file_name, 'rb') as file:
                bank = Bank.deserialise_json(file,bank_name)
        except FileNotFoundError:
            print('file not found')
        return bank

    @staticmethod
    def deserialise_json(bank_json, bank_name=""):
        """Parser of the dict"""
        bank_details = json.loads(bank_json)
        bank = Bank(MakeLedger(comm=None), v0=[0], types={0: 'padl'}, name=bank_name, serialise=False)
        for key, val in zip(list(bank_details.keys()), list(bank_details.values())):
            bank.__dict__[key] = val
        # de-serailising lists:
        bank.secret_balance_book = json.loads(bank.secret_balance_book)
        bank.state_cm_token = json.loads(bank.state_cm_token)
        bank.r0 = [r_blend(zkbp.to_scalar_from_str(r0)) for r0 in json.loads(bank.r0)]
        bank.sk_pk_obj = zkbp.regen_pb_sk(bank.gh, zkbp.to_scalar_from_str(bank.sk))
        for ai in bank.secret_balance_book: # from strings to r objects
            for tx in ai:
                tx[1] = r_blend(zkbp.to_scalar_from_str(tx[1]))

        return bank

    def init_state_to_json(self):
        json_st = {}
        for i, a in enumerate(self.initial_assets_cell):
            json_st[str(i)] = {"commit": a.cm, "token": a.token}
        return json.dumps(json_st)

    def check_balance_tx(self, tx, ledger):
        id = ledger.pub_keys.index(self.pk)
        bals=[]
        for ai in range(self.nassets):
            bal = zkbp.get_brut_v(zkbp.from_str(tx[ai][id].cm),zkbp.to_token_from_str(tx[ai][id].token),ledger.gh, self.sk_pk_obj, MAX)
            print(self.asset_secret_map[ai], bal)
            bals.append(bal)

        return bals

    def get_balance(self):
        """getting ballance from all assets as a list"""
        balance_across_assets = []
        for asset in range(0, self.nassets):
            balance_across_assets.append(self.secret_balance_book[asset][-1][0])
        return balance_across_assets

    def get_balance_from_contract(self,c,t):
        cm = Commit.from_str(c).eval
        token = Token.from_str(t).eval
        return zkbp.get_brut_v(cm, token, self.gh, self.sk_pk_obj, MAX)

    def get_balance_brut(self,c,t):
        cm = Commit.from_str(c).eval
        token = Token.from_str(t).eval
        return zkbp.get_brut_v(cm, token, self.gh, self.sk_pk_obj, MAX)

    def get_balances_from_state(self, ledger, distributed_tx=None):
        state = ledger.get_state_id(self.id)
        balances = []
        for a in range(len(state)):
            if distributed_tx:
                c = distributed_tx[a][self.id]
                sum_tokens = zkbp.add_token(zkbp.to_token_from_str(state[a].token), zkbp.to_token_from_str(c.token))
                sum_cms=zkbp.add_value_commits(state[a].cm,c.cm)
                v_sum = self.get_balance_brut(sum_cms,sum_tokens.get)
            else:
                v_sum = self.get_balance_brut(state[a].cm, state[a].token)
            balances.append(v_sum)
        return balances

    def create_tx(self, vals, n_banks, pub_keys, asset=0, audit_pk=None):
        self.tx_obj.set_bank(self)
        return self.tx_obj.create_tx(vals, n_banks, pub_keys, asset, audit_pk)

    def create_asset_tx(self, *arg, **kwarg):
        self.tx_obj.set_bank(self)
        return self.tx_obj.create_asset_tx(*arg, **kwarg)

    def create_rand_tx(self, n_banks, pub_keys, audit_pk=None):
        self.tx_obj.set_bank(self)
        return self.tx_obj.create_rand_tx(n_banks, pub_keys, audit_pk)
    

    def extract_no_communication(self, tx, id, gh, pbsk):
        vals = [0] * len(tx)
        asset_type=""
        for a in range(len(vals)):
            is_zero_cell = tx[a][id].is_str_sparse_cell()
            cm = Commit.from_str(tx[a][id].cm).eval
            token = Token.from_str(tx[a][id].token).eval
            vals[a] = zkbp.get_brut_v(cm, token, gh, pbsk, MAX)


    def extract_vals(self, tx):
        vals = [0] * len(tx)
        for a in range(len(vals)):
            cm = Commit.from_str(tx[a][self.id].cm).eval
            token = Token.from_str(tx[a][self.id].token).eval
            vals[a] = zkbp.get_brut_v(cm, token, self.gh, self.sk_pk_obj, MAX)
        return vals

    def extract_vals_cell(self, cell):
        vals = [0] * len(cell)
        for a in range(len(vals)):
            cm = Commit.from_str(cell[a].cm).eval
            token = Token.from_str(cell[a].token).eval
            vals[a] = zkbp.get_brut_v(cm, token, self.gh, self.sk_pk_obj, MAX)
        return vals

    def add_asset(self, val=0, asset_type=""):
        if val != 0:
            assert len(asset_type), "asset type is missing"
        
        self.secret_balance_book.append([])
        self.r0.append(r_blend())
        self.v0.append(val)
        self.cm0 = [Commit(self.gh, v, self.r0[i]) for i, v in enumerate(self.v0)]
        self.token0 = [self.sk_pk_obj.to_token(rl0.get()) for rl0 in self.r0]
        self.nassets += 1
        self.initial_assets_cell = [MakeLedger.Cell(token=t.get, cm=c.eval.get, cm_=c.eval.get, token_=t.get) for c, t
                                    in zip(self.cm0, self.token0)]
        if val != 0:
            self.asset_secret_map[len(self.v0) - 1] = asset_type

        self.serialise()
        return self.initial_assets_cell[-1]

    def append_asset_to_book(self, asset_i, v_r_pair, asset_type="", is_zero_cell=False):
        if len(self.secret_balance_book) == asset_i:
            self.add_asset()

        self.secret_balance_book[asset_i].append(v_r_pair)
        self.approval_result = False
        self.new_tx_info = False
        if len(asset_type):
            if asset_i not in self.asset_secret_map.keys():
                self.asset_secret_map[asset_i] = asset_type
            else:
                assert (asset_type == self.asset_secret_map[asset_i]), "error in mapping"

    def gen_cells(self, asset, tx, ledger):
        """generate transaction cells including commit, token, proof of consistency, value equal commit proof, proof of asset and proof of balance

        Args:
            asset (int): the index inside the whole asset list
            tx (list): a list of transactions

        Returns:
            bool: assuming consent by returning True
        """
        c = tx[self.id]
        if c.is_str_sparse_cell(): return True

        state = ledger.get_state_id(self.id)
        sum_tokens = zkbp.add_token(zkbp.to_token_from_str(state[asset].token), zkbp.to_token_from_str(c.token))
        sum_cms=zkbp.add_value_commits(state[asset].cm,c.cm)
        v_sum = self.get_balance_brut(sum_cms,sum_tokens.get)
        r_ = r_blend()
        v_r = [v_sum, r_]
        self.append_asset_to_book(asset, v_r)
        c.cm_ = Commit(self.gh,v_sum, r_).eval.get
        c.token_ = self.sk_pk_obj.to_token(r_.get()).get
        c.P_C_ = ProofGenerator().generate_proof_of_consistency(tx[self.id].cm_, tx[self.id].token_, v_r, self.pk)
        c.P_Eq = ProofGenerator().generate_value_eq_cm_proof(sum_tokens, sum_cms, c.token_, c.cm_, asset, self.sk_pk_obj)

        c.P_A = ProofGenerator().generate_proof_of_asset(v_sum, r_)
        c.P_B = ProofGenerator().generate_proof_of_balance(tx)

        return True  # assuming consent

    def approve_tx(self, txn, ledger):
        # consent tx.
        if self.new_tx_info:
            self.extract_no_communication(txn, self.id, self.gh, self.sk_pk_obj)
        for asset, tx in enumerate(txn):
            self.gen_cells(asset,tx, ledger)
        return True  # after consent


    def generate_asset_ratio_proof(self, n_bit=BITS, asset=0, n=1, d=2):
        '''# raise NotImplementedError()'''
        sum_v_r = self.secret_balance_book[asset][-1]


        s_b_all = []
        for ai in range(len(self.secret_balance_book)):
            s_b_all.extend([self.secret_balance_book[ai][-1]])
        sum_v_r_all = reduce(lambda x, y: (x[0] + y[0], x[1] + y[1]), s_b_all)
        sum_v_all = sum_v_r_all[0]
        sum_r_all = sum_v_r_all[1]

        sum_v_all = sum_v_all * n
        sum_r = sum_v_r[1] * d
        sum_v = sum_v_r[0] * d
        sum_r_all = sum_r_all * n

        sum_v_ratio = sum_v_all - sum_v
        sum_r_ratio = sum_r_all - sum_r


        range_proof = zkbp.range_proof_single(n_bit=n_bit, val=sum_v_ratio, gh=self.gh, r=sum_r_ratio.val)
        return range_proof

class MakeLedger:
    def __init__(self, comm=None, address="https://localhost", port=4444):
        self.gh = curve_util.gh
        self.txs = []
        self.zero_line = []
        self.pub_keys = []
        self.bank_addresses = []
        self.bank_comm = comm
        self.port = port
        self.address = address + ":" + str(self.port)
        self.distributed_tx = []
        self.n_banks = self.get_set_n_banks()
        self.status_tx = self.n_banks * [0]
        self.gtox = []
        self.state = []

    def register_bank(self, pk, bank_func_pointer):
        self.pub_keys.append(pk)
        self.bank_addresses.append(bank_func_pointer)
        self.zero_line.append(MakeLedger.Cell())
        id = len(self.pub_keys) - 1
        self.n_banks = len(self.pub_keys)
        return id
    def register_new_asset(self, asset_cell, id):
        self.zero_line[id].append(asset_cell)
        self.state.append([])
        for p in range(self.n_banks):
            if p==id:
                self.state[-1].append(asset_cell)
            else:
                self.state[-1].append(self.Cell.CellZero(self.pub_keys[id]))

    def register_zero_line(self, initial_assets_cell):
        self.zero_line[-1] = initial_assets_cell
        for a in range(len(initial_assets_cell)):
            if len(self.state) == a:
                self.state.append([])
            self.state[a].append(initial_assets_cell[a])

    def get_set_n_banks(self):
        self.n_banks = len(self.pub_keys)
        self.status_tx = self.n_banks * [0]
        return self.n_banks

    def push_tx(self, distributed_tx, verify=True):
        # verify proofs or other auditing
        if verify: self.audit_tx(distributed_tx)
        # appending to ledger
        self.txs.append(distributed_tx)
        self.update_state(distributed_tx)
        self.distributed_tx = []
        self.status_tx = self.n_banks * [0]


    def update_state(self,distributed_tx):
        for a in range(len(distributed_tx)):
            for i in range(len(distributed_tx[a])):
                self.state[a][i].cm= zkbp.add_value_commits(self.state[a][i].cm,distributed_tx[a][i].cm)
                self.state[a][i].token = zkbp.add_token(zkbp.to_token_from_str(self.state[a][i].token), zkbp.to_token_from_str(distributed_tx[a][i].token)).get



    def push_inject_tx(self, distributed_tx, send_ID, verify=True):
        # verify proofs or other auditing
        if verify: self.audit_injective_tx(distributed_tx, send_ID, asset=0)

        # appending to ledger
        self.txs.append(distributed_tx)
        self.update_state(distributed_tx)

        self.distributed_tx = []
        self.status_tx = self.n_banks * [0]

    def audit_injective_tx(self, txs, send_ID, asset=0):
        """all participants can use this function to validate proofs at any time

        Args:
            tx (list): a list of transactions
            vals (list): a list of asset
            ledger (object): ledger object
            asset (int): asset index
        """
        # Need to be adapted to BN254
        # assert InjectiveUtils.check_tx_structure(txs, send_ID), "Transaction structure validation failed."

        # validate proofs, can be done by anyone at anytime
        for a in range(len(txs)):
            tx = txs[a]
            Auditing.validate_proof_of_balance(tx)
            for p in range(len(tx)):
                if p == send_ID:
                    Auditing.valdiate_proof_of_asset(self.txs, self.zero_line, p, tx, asset=asset)
                    Auditing.valdiate_proof_of_consistency(self.pub_keys, p, tx)
                    Auditing.valdiate_proof_of_ext_consistency(self.pub_keys,p,tx)

                else:
                    Auditing.valdiate_proof_of_positive_commit(tx[p].cm, tx[p].P_A)
                    Auditing.valdiate_proof_of_consistency(self.pub_keys, p, tx)


    def audit_tx(self, distributed_tx):
        """
        :param distributed_tx:

        :return:
        """
        # validate proofs, can be done by anyone at anytime
        for asset, tx in enumerate(distributed_tx):
            Auditing.validate_proof_of_balance(tx)
            for i in range(self.n_banks):
                if distributed_tx[asset][i].is_str_sparse_cell(): continue
                Auditing.valdiate_proof_of_asset(self.txs, self.zero_line, i, tx, asset=asset)
                Auditing.valdiate_proof_of_consistency(self.pub_keys, i, tx)
                Auditing.valdiate_proof_of_ext_consistency(self.pub_keys, i, tx)
                Auditing.verify_value_eq_cm(i, tx, self.state[asset])

    def register_new_bank(self, **args):
        bank = Bank(self, **args)
        if self.bank_comm!=None:
            self.bank_comm.banks.append(bank)
        return bank

    def broadcast_tx(self, vals):
        raise NotImplementedError("no broadcast in default")

    def populate_tx(self, distributed_tx):

        if not self.bank_comm.is_online:  # the default is local
            for bank_add in self.bank_comm.banks:
                self.zero_line[bank_add.id] = bank_add.initial_assets_cell  # update zero line for added asset
                assert bank_add.approve_tx(distributed_tx, self), "Bank doesn't consent to Tx"
                bank_add.new_tx_info = True
        else:
            logging.info('in online mode the subclass needs to overload this populate_tx')
        return distributed_tx

    def retrieve_txs(self):
        return self.distributed_tx

    @staticmethod
    def to_json(txs):
        if not txs:
            return {}
        if isinstance(txs[0], MakeLedger.Cell):
            txsj = [cell.to_json() for cell in txs]
        elif isinstance(txs[0][0], MakeLedger.Cell):
            txsj = []
            for i in range(len(txs)):
                txsj.append([cell.to_json() for cell in txs[i]])
        else:
            txsj = []
            for txs_a in txs:
                txsb = []
                for bi in range(len(txs_a)):
                    txsb.append([cell.to_json() for cell in txs_a[bi]])
                txsj.append(txsb)

        return json.dumps(txsj)

    @staticmethod
    def tx_from_json(tx_json):
        return [MakeLedger.Cell.from_json(cell) for cell in json.loads(tx_json)]

    @staticmethod
    def txs_from_json(txs_json):
        if isinstance(txs_json, str) or isinstance(txs_json, bytes):
            txs_json = json.loads(txs_json)
        txs = []
        for tx_a in txs_json:
            if isinstance(tx_a, str) or isinstance(tx_a, bytes):
                tx_a = json.loads(tx_a)
            txs.append([MakeLedger.Cell.from_json(cell) for cell in tx_a])
        return txs

    @staticmethod
    def create_initial_cell_from_asset_vals(v0, pk, audit_pk=None):
        r0 = [r_blend()] * len(v0) # zero commit for assets
        cm0 = [Commit(zkbp.gen_GH(), v, r0[i]) for i, v in enumerate(v0)]
        token0 = [zkbp.to_token_from_pk(pk, rl0.val) for rl0 in r0]

        initial_assets_cell = [MakeLedger.Cell(token=t.get, cm=c.eval.get, cm_=c.eval.get, token_=t.get) for c, t
                               in zip(cm0, token0)]
        if audit_pk:
            audit_tokens = [zkbp.to_token_from_pk(audit_pk, rl0.val).get for rl0 in r0]
            for a in range(0,len(initial_assets_cell)):
                initial_assets_cell[a].meta_data = {"audit": audit_tokens[a]}
                initial_assets_cell[a].token = audit_tokens[a]
        return initial_assets_cell

    @staticmethod
    def txs3d_from_json(txs_json):
        if isinstance(txs_json, str):
            txs_json = json.loads(txs_json)
        txs = []
        assets = []
        for asset in txs_json:
            if isinstance(asset, str) or isinstance(asset, bytes):
                asset = json.loads(asset)
            for tx in asset:
                txs.append([MakeLedger.Cell.from_json(cell) for cell in tx])
            assets.append(txs)
        return assets

    @staticmethod
    def loads(txs):
        if isinstance(txs, list):
            return [MakeLedger.txs_from_json(tx_json) for tx_json in txs]
        elif isinstance(txs, str) or isinstance(txs, bytes):
            return [MakeLedger.txs_from_json(tx_json) for tx_json in json.loads(txs)]
        AssertionError("doesn't recognise type")

    def arrange_commits_tokens_columns(self, asset, bank):
        commits = [zkbp.from_str(self.zero_line[bank][asset].cm)]
        tokens = [zkbp.to_token_from_str(self.zero_line[bank][asset].token)]
        for tx in self.txs:
            if len(tx) <= asset: continue  # we have dynamic size of assets
            commits.append(zkbp.from_str(tx[asset][bank].cm))
            tokens.append(zkbp.to_token_from_str(tx[asset][bank].token))
        c = reduce(lambda x, y: zkbp.add(x, y), commits)
        t = reduce(lambda x, y: zkbp.add_token(x, y), tokens)
        return c, t
    

    def get_state_id(self, id):
        return [self.state[a][id] for a in range(len(self.state))]

    def compute_sum_commits_tokens(self):
        # ledger.zero_line is: nbanks x nassets
        # ledger.txs is: ntxs x nassets x nbanks
        nassets = len(self.zero_line[0])
        commits_sum_by_asset_bank = []
        tokens_sum_by_asset_bank = []
        for asset in range(0, nassets):
            temp_sum_commits = []
            temp_sum_tokens = []
            for bank in range(0, self.n_banks):
                c, t = MakeLedger.arrange_commits_tokens_columns(self, asset, bank)
                temp_sum_commits.append(c.get)
                temp_sum_tokens.append(t.get)
            commits_sum_by_asset_bank.append(temp_sum_commits)
            tokens_sum_by_asset_bank.append(temp_sum_tokens)
        return json.dumps([commits_sum_by_asset_bank, tokens_sum_by_asset_bank])

    class Cell:
        """
        Represents a cell in the ledger
        Attributes
        ----------
        """
        def __init__(self, cm=None, token=None, P_A=None, P_B=None,
                     P_C=None, cm_=None, token_=None, P_C_=None, P_Eq=None, meta_data={}):
            """
            token : EcPt token pk^r
            cm : EcPt pedersen commitment: g^v+h^r
            P_A: obj. proof of Asset
            P_B: validate proof of balance.
            P_C: validate proof of consistency.
            """
            self.token = token
            self.token_ = token_
            self.cm = cm
            self.cm_ = cm_
            self.P_A = P_A  # proof of asset in tx.
            self.P_B = P_B  # proof of balance in tx.
            self.P_C = P_C  # proof of consistency in tx.
            self.P_C_ = P_C_  # proof r and r_ from cm and cm_ are consistent.
            self.P_Eq = P_Eq  # proof of equivalence of value in state balance to cm_.
            self.meta_data = meta_data
        def set_meta_data(self, meta_data:dict):
            """adding any meta zk to the tx"""
            self.meta_data = meta_data
            return meta_data

        @classmethod
        def CellZero(cls, pk):
            gh = curve_util.gh
            r0=r_blend(curve_util.to_scalar_from_zero())
            cm = Commit(gh, 0, r0).eval
            token = zkbp.to_token_from_pk(pk, r0.val)
            return cls(cm=cm.get, token=token.get, cm_=cm.get,token_=token.get)

        def is_str_sparse_cell(self):
            """sparse cell contains zero cm and cm_ to ignore in proof gen, and verification"""
            zero_point = '00'+curve_util.to_scalar_from_zero().get
            return self.cm == zero_point and self.cm_ == zero_point

        def is_sparse_cell(self):
            """sparse cell contains zero cm and cm_ to ignore in proof gen, and verification"""
            return self.cm.is_zero() and self.cm_.is_zero()

        def to_json(self):
            return self.__dict__

        @classmethod
        def list_to_json(cls, cell_list):
            return json.dumps([cell.to_json() for cell in cell_list])

        @classmethod
        def from_json_list(cls, json_list):
            l_o = [cls.from_json(o) for o in json_list]
            return l_o

        @classmethod
        def from_json(cls, json_o):
            o = (json_o)
            return MakeLedger.Cell(**o)



class BankCommunication:  
    """Define the communication between participants in broadcasting transaction.
    Default is for dummy & local development/test"""
    def __init__(self, is_online=False, banks_adds=None):
        if banks_adds is None:
            banks_adds = []
        self.is_online = is_online
        self.banks = banks_adds

    def send_assets_to_banks(self, vals, r_tx, asset_map, mode="v_r"):
        for i in range(len(self.banks)):
            for j in range(len(vals)):
                asset_type = ""
                if vals[j][i] != 0:  # will pass type only for tx with value
                    asset_type = asset_map[j]
                if mode == "v_r":
                    # this mode provides v and r.
                    self.banks[i].append_asset_to_book(j, (vals[j][i], r_tx[j][i]), asset_type)
                elif mode == "v":
                    # this mode provides only v, and party creates extra cm_ and token_
                    self.banks[i].append_asset_to_book(j, (vals[j][i], 0), asset_type)
                elif mode == "none":
                    pass
        return True

    def receive_asset_balance_proof(self, ledger, bank_id, asset):
        return self.banks[bank_id].get_asset_balance_proof(ledger, asset)
