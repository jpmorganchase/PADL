import os
import sys
import logging
from pathlib import Path

from pyledger.extras.injective_utils import InjectiveUtils
from pyledger.extras.evmnet.contractpadl import PadlEVM
logging.basicConfig(level=logging.WARN, format='%(message)s')

path = os.path.realpath(__file__)
parent_dir = str(Path(path).parents[1])
sys.path.append(parent_dir)
from pyledger.zkutils import Commit, r_blend, curve_util
from pyledger.ledger import BankCommunication, MakeLedger


class PADLEvmInjective(PadlEVM):

    def __init__(self, secret_key=None, v0=0,
                 contract_address=None,
                 comm=BankCommunication(),
                 contract_tx_name="PADLOnChain",
                 file_name_contract="PADLOnChain.sol", redeploy=False):
        super().__init__(secret_key=secret_key, v0=v0,
                         contract_address=contract_address,
                         comm=comm,
                         contract_tx_name=contract_tx_name,
                         file_name_contract=file_name_contract, redeploy=redeploy)

    def register_zero_line(self, initial_assets_cell):
        super(PadlEVM,self).register_zero_line(initial_assets_cell)
        zero_line = MakeLedger.Cell.list_to_json(initial_assets_cell)
        super().add_zero_line(zero_line)
        zl = MakeLedger.tx_from_json(zero_line)
        self.add_zero_line_to_state(zl)


    def add_zero_line_to_state(self,zl):
        zl = [curve_util.get_ec_from_cells(a) for a in zl]
        
        nonce = self.w3.eth.getTransactionCount(self.account_address)
        fn_call = self.testnet_dict["contract_obj"].functions.addZeroLineToState(zl).buildTransaction({
            "chainId": self.chain, "from": self.account_address, "nonce": nonce}
        )
        self.send_txn_from_fn_call(fn_call)

    def send_injective_txn_padlonchain(self,tx, asset_id):
        nonce = self.w3.eth.getTransactionCount(self.account_address)
        fn_call = self.testnet_dict["contract_obj"].functions.processTx(tx, asset_id).buildTransaction({
            "chainId":self.chain, "from":self.account_address, "nonce":nonce, "gas": 20000000000}
        )
        receipt = self.send_txn_from_fn_call(fn_call)
        print(f'gas used for injective tx of asset {asset_id}, and no. of parties {len(tx)}:',receipt['gasUsed'])
        assert receipt['status']==1, 'transaction error'

    def cashout_padl_onchain(self,sval, bankid, pr):
        pr = InjectiveUtils.format_eq_proof(pr)
        nonce = self.w3.eth.getTransactionCount(self.account_address)
        fn_call = self.testnet_dict['contract_obj'].functions.processEqPr(sval, bankid, pr).buildTransaction({
            "chainId":self.chain, "from":self.account_address, "nonce":nonce, "gas": 2000000000}
        )
        x = self.send_txn_from_fn_call(fn_call)
        print(f"Verification complete. Transaction sent.")



