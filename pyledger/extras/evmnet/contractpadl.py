"""PADL Contract interface for transactions with EVM"""
import ast
import sys
import os
import time
import logging
import requests
import zkbp
from web3 import Web3
import time

from pathlib import Path
path = os.path.realpath(__file__)
parent_dir = str(Path(path).parents[3])
main_dir = str(Path(path).parents[2])

sys.path.append(parent_dir)
from pyledger.extras.evmnet.evmpadl import EvmLedger
from pyledger.ledger import BankCommunication, MakeLedger
from pyledger.zkutils import curve_util
import hashlib
import json
import configparser

config_file_path = os.path.join(str(Path(os.path.realpath(__file__)).parents[0]), "ip_config.ini")
ip_config = configparser.ConfigParser()
ip_config.read(config_file_path)


url=ip_config["LOCAL"]["url"]
storage_url=ip_config["LOCAL"]["storage_url"]
chain_id=ip_config.getint("LOCAL", "chain_id")


class PadlEVM(EvmLedger):
    def __init__(self, secret_key=None, v0=0,
                 contract_address=None,
                 comm=BankCommunication(),
                 contract_tx_name="StorePermissionsAndTxns",
                 file_name_contract="StorePermissionsAndTxns.sol",
                 redeploy=False):
        if not secret_key:
            raise NotImplementedError("Need secret key")

        self.url = url
        self.storage_url = storage_url
        self.w3 = Web3(Web3.HTTPProvider(self.url, request_kwargs={'timeout': 600000}))
        self.local_dirname = main_dir
        account_address = self.w3.eth.account.from_key(secret_key).address

        super().__init__(comm, file_name_contract, self.local_dirname, self.w3, chain_id,
                         account_address, secret_key, contract_tx_name)

        self.attached_pk = curve_util.to_pk(secret_key)
        if redeploy:
            self.deploy(v0, recompile=True)
        else:
            if not contract_address:
                NotImplementedError('Need contract address or set redeploy=True')
            self.deployed_address= contract_address
        
        self.testnet_dict = self.connect_to_evm()
        self.pub_keys = self.get_all_pks()
        self.n_banks = len(self.pub_keys)
        self.zero_line = self.get_all_zerolines()


    def get_eth_balance(self, _add):
        return self.w3.eth.get_balance(self.w3.toChecksumAddress(_add))

    def add_participant_to_contract(self, _address):
        # issuer only function
        _address = self.w3.toChecksumAddress(_address)
        nonce = self.w3.eth.get_transaction_count(self.account_address)
        fn_call = self.testnet_dict['contract_obj'].functions.addParticipant(_address).buildTransaction(
            {"chainId": self.chain, "from": self.account_address, "nonce": nonce, "gas": 20000000})
        self.send_txn_from_fn_call(fn_call)

    def add_participant_to_contract_pk(self, _address, _pk, initial_assets):
        _address = self.w3.toChecksumAddress(_address)
        nonce = self.w3.eth.get_transaction_count(self.account_address)
        fn_call = self.testnet_dict['contract_obj'].functions.addParticipant(_address).buildTransaction(
        {"chainId": self.chain, "from": self.account_address, "nonce": nonce})
        self.send_txn_from_fn_call(fn_call)
        initial_cell=self.create_initial_cell_from_asset_vals(initial_assets,_pk)
        json_initial_cell = MakeLedger.to_json(initial_cell)
        self.add_pk_to_contract(_pk,_address)
        self.add_zero_line(json_initial_cell,_address)

    def send_inital_gas(self, add, verbose=False):
        add = self.w3.toChecksumAddress(add)
        print('address', add)
        nonce = self.w3.eth.get_transaction_count(self.account_address)

        tx = {
            'chainId': 1337,
            'nonce': nonce,
            'from': self.account_address,
            'to': add,
            'value': self.w3.toWei(100, 'ether'),
            'gas': 100000,
            'gasPrice': self.w3.eth.gasPrice


        }
        signed_tx = self.w3.eth.account.sign_transaction(tx, self.private_key)
        tx_hash = self.w3.eth.sendRawTransaction(signed_tx.rawTransaction)


    @staticmethod
    def create_account(contract_add=""):
        w3 = Web3(Web3.HTTPProvider(url))
        new_account = w3.eth.account.create()
        secret_key = w3.toHex(new_account.privateKey)
        # temporal just until it will be registered.
        temp_env = {'ADDRESS': new_account.address,
                    'SECRET_KEY': secret_key,
                    'PUBLIC_KEY': zkbp.regen_pb_sk(zkbp.gen_GH(),zkbp.to_scalar_from_str(secret_key[2:])).get_pk()
                    }
        if contract_add != "":
            temp_env['CONTRACT_ADDRESS'] = contract_add

        return temp_env['ADDRESS'], temp_env['SECRET_KEY'], temp_env['PUBLIC_KEY']

    @staticmethod
    def create_account_new():
        w3 = Web3(Web3.HTTPProvider(url))
        new_account = w3.eth.account.create()
        address = new_account.address
        sk = w3.toHex(new_account.privateKey)
        return address, sk

    def send_txn_from_fn_call(self, fn_call):
        signed_tx = self.w3.eth.account.sign_transaction(fn_call, self.private_key)
        send_tx = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        tx_receipt = self.w3.eth.wait_for_transaction_receipt(send_tx)
        return tx_receipt

    def add_pk_to_contract(self, pk, add=""):
        nonce = self.w3.eth.get_transaction_count(self.account_address)
        if add=="":
            add=self.account_address
        fn_call = self.testnet_dict['contract_obj'].functions.storePublicKey(pk,add).buildTransaction(
            {"chainId": self.chain, "from": self.account_address, "nonce": nonce, "gas": 20000000})
        return self.send_txn_from_fn_call(fn_call)

    def empty_participants_list(self):
        nonce = self.w3.eth.get_transaction_count(self.account_address)
        fn_call = self.testnet_dict['contract_obj'].functions.removeAllParticipants().buildTransaction(
            {"chainId": self.chain, "from": self.account_address, "nonce": nonce})
        self.send_txn_from_fn_call(fn_call)
        print("removed all participants")

    def broadcast_tx_to_contract(self, distributed_tx):
        contract_tx = self.to_json(distributed_tx)
        nonce = self.w3.eth.get_transaction_count(self.account_address)
        fn_call = self.testnet_dict['contract_obj'].functions.addTxn(contract_tx[0:10]).buildTransaction(
            {"chainId": self.chain, "from": self.account_address, "nonce": nonce, "gas": 20000000}
        )
        return self.send_txn_from_fn_call(fn_call)

    def retrieve_total_supply(self):
        total_supply = self.testnet_dict['contract_obj'].functions.retrieveTotalSupply().call()
        return total_supply

    def retrieve_num_txns(self):
        num_txs = self.testnet_dict['contract_obj'].functions.retrieveTxnLength().call()

        return num_txs

    def voteTxn(self):
        nonce = self.w3.eth.get_transaction_count(self.account_address)
        fn_call = self.testnet_dict['contract_obj'].functions.voteTxn().buildTransaction(
            {"chainId": self.chain, "from": self.account_address, "nonce": nonce}
        )
        return self.send_txn_from_fn_call(fn_call)

    def add_txn_to_ledger(self):
        nonce = self.w3.eth.get_transaction_count(self.account_address)
        fn_call = self.testnet_dict['contract_obj'].functions.approveTxn().buildTransaction(
            {"chainId": self.chain, "from": self.account_address, "nonce": nonce, "gas": 20000000}
        )
        return self.send_txn_from_fn_call(fn_call)

    def add_txn_to_ledger_issuer(self):
        nonce = self.w3.eth.get_transaction_count(self.account_address)

        fn_call = self.testnet_dict['contract_obj'].functions.approveTxnIssuer().buildTransaction(
            {"chainId": self.chain, "from": self.account_address, "nonce": nonce, "gas": 20000000}
        )
        rx = self.send_txn_from_fn_call(fn_call)
        return rx

    def update_int_state(self):
        nonce = self.w3.eth.getTransactionCount(self.account_address)
        fn_call = self.testnet_dict["contract_obj"].functions.updateState().buildTransaction(
            {"chainId":self.chain, "from":self.account_address, "nonce":nonce, "gas": 20000000}
        )
        return self.send_txn_from_fn_call(fn_call)

    def check_txn_approval(self):
        nonce = self.w3.eth.get_transaction_count(self.account_address)
        fn_call = self.testnet_dict['contract_obj'].functions.checkTxnApproval().buildTransaction(
            {"chainId": self.chain, "from": self.account_address, "nonce": nonce, "gas": 20000000}
        )
        return self.send_txn_from_fn_call(fn_call)

    def check_txn_can_settle(self):
        nonce = self.w3.eth.get_transaction_count(self.account_address)
        fn_call = self.testnet_dict['contract_obj'].functions.checkTxnApproval().call()
        return fn_call


    def add_commits_tokens(self, distributed_tx, proof_hash):
        for asset_tx in distributed_tx:
            for p in asset_tx:
                p.cm = zkbp.from_str(p.cm).get
                p.token = zkbp.to_token_from_str(p.token).get

        cmtk = [[p for p in asset_tx] for asset_tx in distributed_tx] 
        d = [[curve_util.get_ec_from_cells(ct) for ct in asset] for asset in cmtk]

        nonce = self.w3.eth.get_transaction_count(self.account_address)
        fn_call = self.testnet_dict['contract_obj'].functions.storeIntCMTK(d).buildTransaction(
            {"chainId": self.chain, "from": self.account_address, "nonce": nonce, "gas": 2000000}

        )
        self.send_txn_from_fn_call(fn_call)
        nonce = self.w3.eth.get_transaction_count(self.account_address)
        fn_call = self.testnet_dict['contract_obj'].functions.addstorageidentifier(proof_hash).buildTransaction(
            {"chainId":self.chain, "from":self.account_address, "nonce":nonce, "gas":2000000}
        )
        return self.send_txn_from_fn_call(fn_call)


    def add_int_commits_tokens(self,pre_n_itx):
        nonce = self.w3.eth.getTransactionCount(self.account_address)
        fn_call = self.testnet_dict['contract_obj'].functions.storeIntCMTK(pre_n_itx).buildTransaction(
            {"chainId": self.chain, "from": self.account_address, "nonce": nonce, "gas": 20000000}
        )
        return self.send_txn_from_fn_call(fn_call)


    def set_auction_end_time(self,time):
        nonce = self.w3.eth.getTransactionCount(self.account_address)
        fn_call = self.testnet_dict['contract_obj'].functions.setEndTime(time).buildTransaction(
            {'chainId': self.chain, 'from':self.account_address, 'nonce': nonce, "gas": 20000000}
        )
        return self.send_txn_from_fn_call(fn_call)

    def close_auction(self,id):
        nonce = self.w3.eth.getTransactionCount(self.account_address)
        fn_call = self.testnet_dict['contract_obj'].functions.closeAuction(id).buildTransaction(
            {'chainId': self.chain, 'from': self.account_address, 'nonce':nonce, "gas": 20000000}
        )
        return self.send_txn_from_fn_call(fn_call)

    def retrieve_state(self,id):
        nonce = self.w3.eth.getTransactionCount(self.account_address)
        state_id = self.testnet_dict['contract_obj'].functions.retrieveStateId(id).call() 
        return state_id
    
    def get_state_id(self,id):
        nonce = self.w3.eth.getTransactionCount(self.account_address)
        no_participants = self.testnet_dict['contract_obj'].functions.retrieveNumberOfParticipants().call()
        state_id = self.testnet_dict['contract_obj'].functions.retrieveStateId(id).call()
        no_assets = len(state_id)
        
        if len(self.state)!= no_assets:
            self.state=[[MakeLedger.Cell() for i in range(no_participants)] for a in range(no_assets)] 
        state_id_=[]
        for a in range(no_assets):
            c= state_id[a][0]
            t= state_id[a][1]
            commit = curve_util.get_compressed_ecpoint(c[0],c[1])
            token = curve_util.get_compressed_ecpoint(t[0],t[1])
            self.state[a][id]=MakeLedger.Cell(cm=commit,token=token)
            state_id_.append(MakeLedger.Cell(cm=commit,token=token))
        return state_id_

    def register_new_bank(self, **args):
        bank = super().register_new_bank(**args)
        self.add_pk_to_contract(bank.pk)
        return bank

    def upload_commit_token_request(self, address, initial_cell, deposit_v0):
        nonce = self.w3.eth.get_transaction_count(self.account_address)
        fn_call = self.testnet_dict['contract_obj'].functions.addRequests(
            Web3.toChecksumAddress(address), MakeLedger.to_json(initial_cell), deposit_v0).buildTransaction({
            "chainId": self.chain, "from": self.account_address, "nonce": nonce}
        )
        self.send_txn_from_fn_call(fn_call)

    def get_balance(self):
        bal = self.testnet_dict['contract_obj'].functions.getBalance().call()
        return bal


    def register_zero_line(self, initial_assets_cell):
        super().register_zero_line(initial_assets_cell)
        zero_line = MakeLedger.Cell.list_to_json(initial_assets_cell)
        self.add_zero_line(zero_line)

    def add_zero_line(self, zero_line, add=''):
        zl = MakeLedger.tx_from_json(zero_line)
        proof_hash = self.store_proofs_gkp(zl)
        cmtk = zero_line + ";" + proof_hash
        nonce = self.w3.eth.get_transaction_count(self.account_address)
        if add == '':
            add=self.account_address
        fn_call = self.testnet_dict['contract_obj'].functions.addZeroLine(cmtk, add).buildTransaction({
            "chainId": self.chain, "from": self.account_address, "nonce": nonce, "gas": 20000000}
        )
        self.send_txn_from_fn_call(fn_call)


    def retrieve_zero_line(self, _add):
        zl = self.testnet_dict['contract_obj'].functions.retrieveZeroLine(_add).call()
        cmtks = zl.split(";")
        if len(zl)==0:
            return 0
        proof_hash = cmtks.pop()
        proof = self.retrieve_proof_gkp(filename=proof_hash)
        try:
            return MakeLedger.tx_from_json(proof)
        except:
            print("taking the hash")
            return MakeLedger.tx_from_json(proof_hash)

    def retrieve_int_zero_line(self,_add):
        zl = self.testnet_dict['contract_obj'].functions.retrieveIntZeroLine(_add).call()



    def remove_all_participants(self):
        nonce = self.w3.eth.get_transaction_count(self.account_address)
        fn_call = self.testnet_dict['contract_obj'].functions.removeAllParticipants.buildTransaction(
            {"chain_id": self.chain, "from": self.account_address, "nonce": nonce}
        )
        return self.send_txn_from_fn_call(fn_call)

    def remove_all_txn(self):
        nonce = self.w3.eth.get_transaction_count(self.account_address)
        fn_call = self.testnet_dict['contract_obj'].functions.removeAllTxn().buildTransaction(
            {"chain_id": self.chain, "from": self.account_address, "nonce": nonce}
        )
        return self.send_txn_from_fn_call(fn_call)

    def retrieve_current_tx(self):
        proof_hash = self.testnet_dict['contract_obj'].functions.retrieveIdentifier().call()
        retrievedcmtks = self.testnet_dict['contract_obj'].functions.retrieveCommitsTokens().call()


        proof = self.retrieve_proof_gkp(filename=proof_hash)
        return retrievedcmtks, MakeLedger.txs_from_json(proof), proof_hash

    def retrieve_all_txs(self):
        num_txs = self.retrieve_num_txns()
        all_txs = []
        all_proofs = []
        for i in range(0, num_txs):
            proof_hash = self.retrieve_txs(i)
            #cmtks = tx.split(";")
            tx = self.retrieve_proof_gkp(proof_hash)
            cmtk = [[{'cm': p.cm, 'token': p.token} for p in asset_tx] for asset_tx in MakeLedger.txs_from_json(tx)] # we will save only cm token on smart contract
            all_txs.append(MakeLedger.txs_from_json(json.dumps(cmtk)))
            all_proofs.append(self.retrieve_proof_gkp(proof_hash))
        return all_txs, all_proofs

    def retrieve_txs(self, i):
        txs = self.testnet_dict['contract_obj'].functions.retrieveTxn(i).call()
        return txs

    def store_random_str(self, a):
        nonce = self.w3.eth.get_transaction_count(self.account_address)
        fn_call = self.testnet_dict['contract_obj'].functions.storeRoughStr(a).buildTransaction(
            {"chainId": self.chain, "from": self.account_address, "nonce": nonce, "gas": 20000000}
        )
        tx_receipt = self.send_txn_from_fn_call(fn_call)
        logging.info(tx_receipt)

    def retrieve_rough_str(self):
        rgh = self.testnet_dict['contract_obj'].functions.retrieveRoughStr(0).call()
        logging.info(f"rough string is {rgh}")

    def retrieve_pk(self, _add):
        return self.testnet_dict['contract_obj'].functions.retrievePk(_add).call()

    def retrieve_pks(self):
        st_temp = self.testnet_dict['contract_obj'].functions.retrieveAllPks().call()
        pks = st_temp.split(" ")
        if pks[-1] == '':
            pks = pks[:-1]
        return pks

    def retrieve_participant_address(self, i):
        return self.testnet_dict['contract_obj'].functions.retrieveParticipant(i).call()

    def retrieve_number_of_participants(self):
        return self.testnet_dict['contract_obj'].functions.retrieveNumberOfParticipants().call()

    def delete_all_txn(self):
        return self.testnet_dict['contract_obj'].functions.removeAllTxn().call()

    def get_issuer_address(self):
        return self.testnet_dict['contract_obj'].functions.retrieveIssuer().call()
    
    def get_govarenence_rules(self):
        return self.testnet_dict['contract_obj'].functions.retrieveGovarnenceRules().call()
    
    def set_govarenence_rules(self, st):
        nonce = self.w3.eth.get_transaction_count(self.account_address)
        fn_call = self.testnet_dict['contract_obj'].functions.setGovRules(st).buildTransaction(
            {"chainId": self.chain, "from": self.account_address, "nonce": nonce, "gas": 20000000}
        )
        tx_receipt = self.send_txn_from_fn_call(fn_call)


    def get_all_pks_(self):
        pks = []
        n_banks = self.retrieve_number_of_participants()
        for i in range(0, n_banks):
            _add = self.retrieve_participant_address(i)
            pk = self.retrieve_pk(_add)

            pks.append(pk)
        return pks

    def get_all_pks(self):
        return self.retrieve_pks()

    def sum_cms_tks(self, id, ai, all_txs, zls):
        sum_cm =zkbp.from_str(zls[ai].cm)
        sum_tk = zkbp.to_token_from_str(zls[ai].token)
        for tx in all_txs:
            sum_cm = zkbp.add(sum_cm, zkbp.from_str(tx[ai][id].cm))
            sum_tk = zkbp.add_token(sum_tk, zkbp.to_token_from_str(tx[ai][id].token))
        return sum_cm, sum_tk

    def sum_cms_tks_audit_pk(self, id, ai, all_txs, zls):
        sum_cm =zkbp.from_str(zls[ai].cm)

        sum_tk = zkbp.to_token_from_str(zls[ai].meta_data['audit'])
        for tx in all_txs:
            sum_cm = zkbp.add(sum_cm, zkbp.from_str(tx[ai][id].cm))
            sum_tk = zkbp.add_token(sum_tk, zkbp.to_token_from_str(tx[ai][id].meta_data['audit']))
        return sum_cm, sum_tk

    def store_proofs_gkp(self, distributed_tx, filename=None):
        dtx = MakeLedger.to_json(distributed_tx)
        if not filename:
            filename = str(hashlib.sha256(dtx.encode('utf-8')).hexdigest())
        dictToSend = {'filename': filename, 'proof': dtx, 'pk': self.attached_pk, 'index': self.pub_keys.index(self.attached_pk)}
        res = requests.post(self.storage_url + '/store_long', json=dictToSend)
        if not res.ok:
            raise "failed to post tx to storage"
        return filename

    def retrieve_proof_gkp(self, filename):
        import urllib.request
        t0 = time.time()
        params = {'filename': filename}
        res = requests.get(self.storage_url + '/retrieve', params=params)
        t1 = time.time()
        logging.info("retrieving proof time: " + str(t1 - t0))
        return res.text

    def get_all_zerolines(self):
        zls = []
        n_banks = self.retrieve_number_of_participants()
        for i in range(0, n_banks):
            _add = self.retrieve_participant_address(i)
            zl = self.retrieve_zero_line(_add)
            if zl==0: break
            zls.append(zl)
        return zls

    def transform_tx_int(self, tx):
        return [[curve_util.get_ec_from_cells(p) for p in el] for el in tx]

    # remove this function
    def get_ledger(self):
        raise DeprecationWarning("don't use this, use pull_tx() ")

    def pull_txs(self):
        _, proofs = self.retrieve_all_txs()
        for p in proofs:
            dtx = MakeLedger.txs_from_json(p)
            self.txs.append(dtx)



