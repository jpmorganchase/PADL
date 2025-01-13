
import logging
import zkbp
from functools import reduce
import json
import random
import os
import sys
from pathlib import Path

#from pyledger.examples.padl_deployERC import pub_keys

#from pyledger.ledger import MakeLedger

logging.basicConfig(level=logging.WARN, format='%(message)s')

path = os.path.realpath(__file__)
parent_dir = str(Path(path).parents[1])
sys.path.append(parent_dir)
from pyledger.zkutils import Commit, Token, r_blend, curve_util
from pyledger.extras.injective_utils import InjectiveUtils
from pyledger.Proof_Generation import ProofGenerator
BITS = 64
MAX = int(2 ** (BITS / 4))

class CreateTx():
    def __init__(self, bank = None):
        if bank is not None:
            self.bank = bank
        else:
            self.bank = None
    
    def set_bank(self, bank):
        self.bank = bank

    def create_tx(self, vals, n_banks, pub_keys, asset=0, audit_pk=None, sparse_tx=False):
        from pyledger.ledger import MakeLedger

        
        if sparse_tx:
            r_tx = [r_blend(curve_util.to_scalar_from_zero()) if vals[p]==0 else r_blend() for p in range(n_banks)]
            non_zeros_i=[p for p in range(n_banks) if vals[p]!=0]
            if len(non_zeros_i):
                comp_ri = random.choice([p for p in range(n_banks) if vals[p]!=0])
                r_tx[comp_ri] = -(reduce(lambda x, y: x + y, r_tx) - r_tx[comp_ri])
        else:
            r_tx = [r_blend() for _ in range(n_banks)]
            comp_ri = random.randint(0, n_banks - 1)
            r_tx[comp_ri] = -(reduce(lambda x, y: x + y, r_tx) - r_tx[comp_ri])


        # check sum to zero:
        sum_check = reduce(lambda x, y: x + y, r_tx)
        assert sum_check.is_zero(), "Rs are not sum to zero"
        cm_tx = [Commit(self.bank.gh, vals[i], r_tx[i]).eval for i in range(n_banks)]

        tokens_tx = [zkbp.to_token_from_pk(pub_keys[i], r_tx[i].val) for i in range(n_banks)]


        if sparse_tx:
            tx = [MakeLedger.Cell(cm=cm.get, token=token.get, cm_=cm.get) if cm.is_zero()
                  else MakeLedger.Cell(cm=cm.get, token=token.get) for cm, token in zip(cm_tx, tokens_tx)]
        else:
            tx = [MakeLedger.Cell(cm=cm.get, token=token.get) for cm, token in zip(cm_tx, tokens_tx)]



        if asset == len(self.bank.v0):
            self.bank.add_asset()

        for pi, cell in enumerate(tx):
            cell.P_C = ProofGenerator().generate_proof_of_consistency(tx[pi].cm,
                                                          tx[pi].token,
                                                          [vals[pi], r_tx[pi]],
                                                          pub_keys[pi])
        if audit_pk:
            audit_tokens = [zkbp.to_token_from_pk(audit_pk, r_tx[i].val).get for i in range(n_banks)]
            for pi, cell in enumerate(tx):
                cell.set_meta_data({"audit":audit_tokens[pi]})


        self.bank.tx_dist_log = " ".join([str(vs) for vs in vals]) + " balance: " \
                           + str([v[0] for v in self.bank.secret_balance_book[asset]])
        self.bank.txs_log.append(self.bank.tx_dist_log)

        return tx, r_tx
    
    def create_rand_tx(self, n_banks, pub_keys, audit_pk=None):
        """
        Generating commits and values for sending transaction randomly.
                :param n_banks:
                :param pub_keys: their pub_keys list
                :param audit_pk:
                :return: transaction
        """
        txns = []
        v_send = []
        r_send = []
        n_banks = len(pub_keys)
        for asset in range(0, self.bank.nassets):
            val = random.randint(0, int(self.bank.v0[asset] / 100)) * 10
            bi = (random.randint(1, n_banks - 1) + self.bank.id) % n_banks
            vals = [0] * n_banks
            vals[bi] = val
            vals[self.bank.id] = -val
            tx, r_tx = self.create_tx(vals, n_banks, pub_keys, asset, audit_pk)
            txns.append(tx)
            v_send.append(vals)
            r_send.append(r_tx)

        self.bank.bank_comm.send_assets_to_banks(v_send, r_send, self.bank.asset_secret_map)
        return txns
    
    def create_asset_tx(self, vals_in, n_banks, pub_keys, audit_pk=None, sparse_tx=False):
        """
        creating the transaction cells for multi assets and participants
            :param vals_in: list of list of assets and participants
            :param n_banks:
            :param pub_keys:
            :param audit_pk: add bank pk will provides all tokens of for its pk.
            :return: encrypted transaction cells as list of list
        """
        txns = []
        v_send = []
        r_send = []
        for asset, vals in enumerate(vals_in):
            tx, r_tx = self.create_tx(vals, n_banks, pub_keys, asset,audit_pk, sparse_tx)
            txns.append(tx)
            v_send.append(vals)
            r_send.append(r_tx)
        self.bank.bank_comm.send_assets_to_banks(v_send, r_send, self.bank.asset_secret_map)
        return txns
    


class InjectiveTx(CreateTx):
    def __init__(self):
        super().__init__()


    def create_asset_tx(self, vals, ledger, pub_keys, audit_pk=None, smart_contract= False):
        """creating the transaction cells including commits and values, proof of consistency, range proof positive commitment
           and proof of asset for multi assets and participants.

        Args:
            vals_in (list): contain assets for different participants
            ledger: ledger class
            pub_keys (list): contain pub_keys (type: string) for different participants
            audit_pk: Defaults to None.

        Returns:
            list: transaction cells
        """
        tx = super().create_asset_tx(vals, len(pub_keys), pub_keys, audit_pk)
        for a in range(len(vals)):
            part_rs = []
            for id,v in enumerate(vals[a]):
                cell_a_p = tx[a][id]
                if id != self.bank.id:
                    # rpr, token, cm, r = ProofGenerator().generate_range_proof_positive_commitment(v, id, ledger,smart_contract=smart_contract)
                    r = r_blend()
                    cm = zkbp.commit(v,r.val,ledger.gh)
                    token = zkbp.to_token_from_pk(pub_keys[id],r.val)
                    rpr = ProofGenerator().generate_proof_of_asset(v, r, smart_contract=smart_contract)
                    cell_a_p.P_A = rpr
                    cell_a_p.cm = cm.get
                    part_rs.append(r)
                    cell_a_p.token = token.get
                    cell_a_p.P_C = ProofGenerator().generate_proof_of_consistency(cm.get,token.get,[v,r],ledger.pub_keys[id])
                    cell_a_p.P_C = InjectiveUtils.format_consistency_proof(cell_a_p.P_C, cell_a_p.cm, cell_a_p.token, ledger.pub_keys[id])
            r_own = -reduce(lambda x, y: x+y, part_rs)

            cm_own = zkbp.commit(vals[a][self.bank.id], r_own.get(), ledger.gh)
            tx[a][self.bank.id].cm = cm_own.get
            token_own = zkbp.to_token_from_pk(ledger.pub_keys[self.bank.id], r_own.get())
            tx[a][self.bank.id].token = token_own.get
            tx[a][self.bank.id].P_C = ProofGenerator().generate_proof_of_consistency(tx[a][self.bank.id].cm,
                                                                    tx[a][self.bank.id].token,
                                                                    [vals[a][self.bank.id], r_own],
                                                                    ledger.pub_keys[self.bank.id])

            tx[a][self.bank.id].P_C = InjectiveUtils.format_consistency_proof(tx[a][self.bank.id].P_C, tx[a][self.bank.id].cm, tx[a][self.bank.id].token, ledger.pub_keys[self.bank.id])
            rpr, token, cm_, r, eqpr, consistency_pr_, v = self.generate_proof_of_asset_for_injective_tx(vals, self.bank.id, ledger, tx[a][self.bank.id], a, smart_contract=smart_contract) # based on the new balance
            rpr = ProofGenerator().generate_proof_of_asset(v, r, smart_contract=True)
            tx[a][self.bank.id].P_A = [rpr, eqpr]
            tx[a][self.bank.id].cm_ = cm_.get
            tx[a][self.bank.id].token_ = token.get
            tx[a][self.bank.id].P_C_ = InjectiveUtils.format_consistency_proof(consistency_pr_, tx[a][self.bank.id].cm_, tx[a][self.bank.id].token_, ledger.pub_keys[self.bank.id])
        return tx
    

    def generate_proof_of_asset_for_injective_tx(self, vals, id, ledger, tx, asset, smart_contract=True):
        """generate the proof of asset for its own coloum

        Args:
            bank: bank class
            vals_in (list): contain assets for different participants
            id (int): the id index of a participant
            ledger: ledger class
            tx: transaction cell including proof of asset P_A, proof of balance P_B...
            asset (int): the value of len(tx)

        Returns:
            return range of postitive commitment(object: dict), token, commit, r, equivalent proof(eqpr, (object: dict)), consistency proof (consistency_pr,(object: dict))
        """
        if smart_contract:
            state_id = ledger.testnet_dict['contract_obj'].functions.retrieveStateId(id).call()
            c,t = state_id[asset]
            cd = curve_util.get_compressed_ecpoint(c[0],c[1])
            td = curve_util.get_compressed_ecpoint(t[0],t[1])
            old_balance = self.bank.get_balance_from_contract(cd,td)   
        else:
            all_sc,all_st = json.loads(ledger.compute_sum_commits_tokens())
            c = zkbp.from_str(all_sc[asset][self.bank.id])
            t = zkbp.to_token_from_str(all_st[asset][self.bank.id]) 
            old_balance = zkbp.get_brut_v(c,t,ledger.gh, self.bank.sk_pk_obj, MAX)                       

        new_balance = old_balance + vals[asset][id]
        

        if smart_contract:
            prs, ptoken, pcm, r = ProofGenerator().generate_range_proof_positive_commitment(new_balance, id, ledger, smart_contract=True) 
            consistency_pr = zkbp.consistency_proof_with_witness(new_balance,r.val,ledger.gh, pcm, ptoken, self.bank.pk)
        else:
            prs, ptoken, pcm, r = ProofGenerator().generate_range_proof_positive_commitment(new_balance, id, ledger, smart_contract=False) 
            consistency_pr = zkbp.consistency_proof(new_balance,r.val,ledger.gh, pcm, ptoken, self.bank.pk)            

        # sum all the commits and tokens in its own column
        if smart_contract:
            comp_sc = [zkbp.from_str(cd), zkbp.from_str(tx.cm)]
            comp_st = [zkbp.to_token_from_str(td), zkbp.to_token_from_str(tx.token)]
        else:
            all_sc,all_st = json.loads(ledger.compute_sum_commits_tokens())
            comp_sc = [zkbp.from_str(all_sc[asset][ id]), zkbp.from_str(tx.cm)]
            comp_st = [zkbp.to_token_from_str(all_st[asset][ id]), zkbp.to_token_from_str(tx.token)]              

        sum_commit = reduce(lambda x, y: zkbp.add(x, y), comp_sc)
        sum_token = reduce(lambda x, y: zkbp.add_token(x, y), comp_st) 

        # PROOF OF KNOWLEDGE OF LOG_{SUMCM - PCM} (SUMTK - PTK) = SK
        sum_com_minus_pcm = Commit.from_str(sum_commit.get) - Commit.from_str(pcm.get)
        sum_token_minus_ptoken = zkbp.sub_token(zkbp.to_token_from_str(sum_token.get), zkbp.to_token_from_str(ptoken.get))
        com_exp_sk = (zkbp.p_to_x(sum_com_minus_pcm.eval, zkbp.to_scalar_from_str(self.bank.sk)))
        eqpr = zkbp.sigma_dlog_proof_explicit_sha256_with_witness(sum_token_minus_ptoken,  self.bank.sk_pk_obj, sum_com_minus_pcm.eval)
        return prs, ptoken, pcm, r, eqpr, consistency_pr, new_balance
    

class InjectiveTxSmartContract(InjectiveTx):
    def __init__(self):
        super().__init__()


    def create_asset_tx(self, vals, ledger, pub_keys, audit_pk=None, smart_contract= True):
        """Covert the created transaction into solidity version

        Args:
            vals_in (list): contain assets for different participants
            ledger: ledger class
            pub_keys (list): contain pub_keys (type: string) for different participants
            audit_pk: Defaults to None.

        Returns:
            list: transaction cells
        """
        tx = super().create_asset_tx(vals, ledger, pub_keys, audit_pk, smart_contract)
        txsol=[]
        for a in range(len(tx)):
            txsol.append(InjectiveUtils.format_tx_to_solidity([tx[a]]))
        
        return txsol,tx
    
class ERCTx(InjectiveTx):
    def __init__(self):
        super().__init__()

    def create_asset_tx(self, v, ledger, state, old_balance):
        from pyledger.ledger import MakeLedger
        id = 1
        gh = zkbp.gen_GH()
        #rpr,token,cm,r = ProofGenerator().generate_range_proof_positive_commitment(v[0][1], id, ledger)
        r = r_blend()
        cm = zkbp.commit(v[0][1], r.val, gh)
        token = zkbp.to_token_from_pk(ledger.pub_keys[id], r.val)
        rpr = ProofGenerator().generate_proof_of_asset(v[0][1], r, smart_contract=True)
        cell = MakeLedger.Cell(cm,token)
        cell.P_A = rpr
        cell.cm = cm.get
        cell.token = token.get
        cell.P_C = ProofGenerator().generate_proof_of_consistency(cm.get,token.get,[v[0][1],r],ledger.pub_keys[1])
        cell.P_C = InjectiveUtils.format_consistency_proof(cell.P_C, cell.cm, cell.token, ledger.pub_keys[1])
        c,t = state # id = 0
        old_balance = self.bank.get_balance_from_contract(c, t)
        new_balance = old_balance + v[0][0] # asset = 0 id = 0
        r_own = -r
        cm_own = zkbp.commit(v[0][0], r_own.get(), gh)
        token_own = zkbp.to_token_from_pk(ledger.pub_keys[0], r_own.get())
        comp_sc = [zkbp.from_str(c), cm_own]
        comp_st = [zkbp.to_token_from_str(t), token_own]
        sum_commit = reduce(lambda x, y: zkbp.add(x, y), comp_sc)
        sum_token = reduce(lambda x, y: zkbp.add_token(x, y), comp_st)

        owncell = MakeLedger.Cell(cm_own, token)
        owncell.cm = cm_own.get
        owncell.token = token_own.get
        owncell.P_C = ProofGenerator().generate_proof_of_consistency(owncell.cm,
                                                                owncell.token,
                                                                [v[0][0], r_own],
                                                                ledger.pub_keys[0])
        owncell.P_C = InjectiveUtils.format_consistency_proof(owncell.P_C, owncell.cm, owncell.token, ledger.pub_keys[0])

        r_comp = r_blend()

        rpr = ProofGenerator().generate_proof_of_asset(new_balance, r_comp, smart_contract=True)
        cm_ = zkbp.commit(new_balance, r_comp.get(), gh)
        token_ = zkbp.to_token_from_pk(ledger.pub_keys[0], r_comp.get())
        owncell.cm_ = cm_.get
        owncell.token_ = token_.get
        consistency_pr_ = ProofGenerator().generate_proof_of_consistency(owncell.cm_,
                                                                     owncell.token_,
                                                                     [new_balance, r_comp],
                                                                     ledger.pub_keys[0])
        owncell.P_C_ = InjectiveUtils.format_consistency_proof(consistency_pr_, owncell.cm_, owncell.token_, ledger.pub_keys[0])
        sum_com_minus_pcm = Commit.from_str(sum_commit.get) - Commit.from_str(cm_.get)
        sum_token_minus_ptoken = zkbp.sub_token(zkbp.to_token_from_str(sum_token.get),
                                                zkbp.to_token_from_str(token_.get))
        eqpr = zkbp.sigma_dlog_proof_explicit_sha256_with_witness(sum_token_minus_ptoken, self.bank.sk_pk_obj,
                                                                  sum_com_minus_pcm.eval)
        owncell.P_A = [rpr,eqpr]
        tx = [[owncell,cell]]
        return InjectiveUtils.format_tx_to_solidity(tx)
    
    def generate_proof_of_asset_for_padlerc(self, bank, vals, pub_key, tx, state, old_balance, asset):
        """generate the proof of asset for its own coloum

        Args:
            bank: bank class
            vals_in (list): contain assets for different participants
            id (int): the id index of a participant
            ledger: ledger class
            tx: transaction cell including proof of asset P_A, proof of balance P_B...
            asset (int): the value of len(tx)

        Returns:
            return range of postitive commitment(object: dict), token, commit, r, equivalent proof(eqpr, (object: dict)), consistency proof (consistency_pr,(object: dict))
        """
        cd = state[0]
        td = state[1]
      
        new_balance = old_balance + vals

        prs, ptoken, pcm, r = ProofGenerator().generate_range_proof_positive_commitment_erc(new_balance, pub_key)
        gh = zkbp.gen_GH()
        # get consistency proof
        consistency_pr = zkbp.consistency_proof_with_witness(new_balance,r.val,gh, pcm, ptoken, self.bank.pk)

        comp_sc = [zkbp.from_str(cd), zkbp.from_str(tx.cm)]
        comp_st = [zkbp.to_token_from_str(td), zkbp.to_token_from_str(tx.token)]
        sum_commit = reduce(lambda x, y: zkbp.add(x, y), comp_sc)
        sum_token = reduce(lambda x, y: zkbp.add_token(x, y), comp_st)

        # PROOF OF KNOWLEDGE OF LOG_{SUMCM - PCM} (SUMTK - PTK) = SK
        sum_com_minus_pcm = Commit.from_str(sum_commit.get) - Commit.from_str(pcm.get)
        sum_token_minus_ptoken = zkbp.sub_token(zkbp.to_token_from_str(sum_token.get), zkbp.to_token_from_str(ptoken.get))
        eqpr = zkbp.sigma_dlog_proof_explicit_sha256_with_witness(sum_token_minus_ptoken,  self.bank.sk_pk_obj, sum_com_minus_pcm.eval)
        return prs, ptoken, pcm, r, eqpr, consistency_pr






