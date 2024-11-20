"""
ZK proof generation for a ledger cell by using zkbp module.
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
logging.basicConfig(level=logging.WARN, format='%(message)s')

path = os.path.realpath(__file__)
parent_dir = str(Path(path).parents[1])  # go up 2 levels [1] to '/zkledgerplayground/'
sys.path.append(parent_dir)
from pyledger.zkutils import Commit, Token, r_blend, Secp256k1  # interface to zkbp.
from pyledger.extras.injective_utils import InjectiveUtils
BITS = 32
MAX = int(2 ** (BITS / 4))



class ProofGenerator:
    """
    This object is for generating proofs.
"""


    def generate_proof_of_asset(self, v, r, n_bit=BITS):
        from pyledger.Proof_verification import Auditing
        start = time.time()
        range_proof = zkbp.range_proof_single(n_bit=n_bit, val=v, gh=zkbp.gen_GH(), r=r.val)
#        print(n_bit, v)
        c=Commit(zkbp.gen_GH(),v,r)
#        print('commit',c.eval.get, zkbp.get_y_coord(c.eval))
        
#        print(range_proof)
        done = time.time()
        elapsed = done - start
        return range_proof
  

    def generate_proof_of_balance(self, tx):
        from pyledger.Proof_verification import Auditing
        return Auditing.validate_proof_of_balance(tx)


    def generate_proof_of_consistency(self, cmstr, tkstr, v_r, pk):
        """generate proof of consistency

        Args:
            cmstr (str): commit
            tkstr (str): token
            v_r (list): a list of asset
            pk (str): public key

        Returns:
            str: return consistency proof
        """
        cm = zkbp.from_str(cmstr)
        token = zkbp.to_token_from_str(tkstr)
        proof = zkbp.consistency_proof_with_witness(val=v_r[0], r=v_r[1].val, gh=zkbp.gen_GH(), ped_cm=cm, token=token, pubkey=pk)
        return proof
    

    def generate_asset_balance_proof(self, scst, asset, bank, ledger):
        if isinstance(scst, str):
            all_sc, all_st = json.loads(scst)
            sc = zkbp.from_str(all_sc[asset][bank.id])
            st = zkbp.to_token_from_str(all_st[asset][bank.id])
        else:
            sc = scst[0]
            st = scst[1]
        sval = bank.get_balances_from_state(ledger)
        g_to_sval = zkbp.g_to_x(bank.gh, sval[asset])
        pbsk = bank.sk_pk_obj
        h_sum_r = zkbp.sub(sc, g_to_sval)
        if isinstance(scst, str):
            pr = zkbp.sigma_dlog_proof_explicit(st, pbsk, h_sum_r)
        else:
            pr = zkbp.sigma_dlog_proof_explicit_sha256(st, pbsk, h_sum_r)
        return pr, sval


    def generate_value_eq_cm_proof(self, token, cm, token_, cm_, asset, pbsk):
        h_to_dr = Commit.from_str(cm) - Commit.from_str(cm_)  # when g^v_*g^v=1
        if type(token)==str: token=zkbp.to_token_from_str(token)

        pk_to_dr = zkbp.sub_token(token, zkbp.to_token_from_str(token_))
        pr = zkbp.sigma_dlog_proof_explicit(pk_to_dr, pbsk, h_to_dr.eval)
        return pr


    def generate_asset_ratio_proof(self, n_bit=BITS, asset=0, n=1, d=2):
        NotImplementedError()
        sum_v_r = reduce(lambda x, y: (x[0] + y[0], x[1] + y[1]), self.secret_book[asset])
        sum_v = sum_v_r[0] + self.v0[asset]
        sum_r = sum_v_r[1] + self.r0[asset]

        s_b_all = []
        for ai in range(len(self.secret_book)):
            s_b_all.extend(self.secret_book[ai])
        sum_v_r_all = reduce(lambda x, y: (x[0] + y[0], x[1] + y[1]), s_b_all)
        sum_v_all = sum_v_r_all[0]
        sum_r_all = sum_v_r_all[1]
        for ai in range(len(self.secret_book)):
            sum_v_all = sum_v_all + self.v0[ai]
            sum_r_all = sum_r_all + self.r0[ai]

        sum_v_all = sum_v_all * n
        sum_r = sum_r * d
        sum_v = sum_v * d
        sum_r_all = sum_r_all * n

        sum_v_ratio = sum_v_all - sum_v
        sum_r_ratio = sum_r_all - sum_r


        range_proof = zkbp.range_proof_single(n_bit=n_bit, val=sum_v_ratio, gh=zkbp.gen_GH(), r=sum_r_ratio.val)
        return range_proof

    def generate_asset_ratio_proof_(self, n_bit=BITS, asset=0, n=1, d=2):
        sum_v_r = reduce(lambda x, y: (x[0] + y[0], x[1] + y[1]), self.secret_book[asset])
        sum_v = sum_v_r[0] + self.v0[asset]
        sum_r = sum_v_r[1] + self.r0[asset]

        s_b_all = []
        for ai in range(len(self.secret_book)):
            s_b_all.extend(self.secret_book[ai])
        sum_v_r_all = reduce(lambda x, y: (x[0] + y[0], x[1] + y[1]), s_b_all)
        sum_v_all = sum_v_r_all[0]
        sum_r_all = sum_v_r_all[1]
        for ai in range(len(self.secret_book)):
            sum_v_all = sum_v_all + self.v0[ai]
            sum_r_all = sum_r_all + self.r0[ai]

        sum_v_all = sum_v_all * n
        sum_r = sum_r * d
        sum_v = sum_v * d
        sum_r_all = sum_r_all * n

        sum_v_ratio = sum_v_all - sum_v
        sum_r_ratio = sum_r_all - sum_r


        range_proof = zkbp.range_proof_single(n_bit=n_bit, val=sum_v_ratio, gh=self.gh, r=sum_r_ratio.val)
        return range_proof
    

    def generate_range_proof_positive_commitment_erc(self, val, pub_key):
        """generate the range proof positive commitment

        Args:
            val (int): the asset of a participant
            id (int): the id index of a participant
            ledger: ledger class

        Returns:
            return range of postitive commitment (object: dict), token, commit, and r
        """
        eqprs = []
        cm = []
        token = []
        rs = []

        if val == 0:
            four_square = (0,0,0,0)
        elif val > 0:
            four_square = InjectiveUtils.get_four_squares(val)
        for vi, val in enumerate(four_square):
            pk = pub_key
            gh = zkbp.gen_GH()
            newg = zkbp.g_to_x(gh, val)
            newgh = zkbp.gen_new_GH(newg,zkbp.from_str(gh.h))
            pr = zkbp.sigma_eq_dlog_ped_proof_with_witness(val, gh, newgh, pk) #?
            jpr = json.loads(pr)
            rs.append(r_blend(zkbp.to_scalar_from_str(jpr["r1"]['scalar'])))
            useful_pr = InjectiveUtils.format_range_proof_positive_commitment(jpr)
            eqprs.append(useful_pr)
            tcm = zkbp.from_str(jpr['cm1']['point'])
            cm.append(tcm)
            ttoken = zkbp.to_token_from_str(jpr['token']['point'])
            token.append(ttoken)
        c = reduce(lambda x, y: zkbp.add(x, y), cm)
        t = reduce(lambda x, y: zkbp.add_token(x, y), token)
        r = reduce(lambda x, y: x+y, rs)
        rpr = {"cm": Secp256k1.get_xy(c.get), "pr1": eqprs[0], "pr2": eqprs[1], "pr3": eqprs[2], "pr4": eqprs[3]}
        return rpr, t, c, r
    

    def generate_range_proof_positive_commitment(self, val, id, ledger, smart_contract=True):
        """generate the range proof positive commitment

        Args:
            val (int): the asset of a participant
            id (int): the id index of a participant
            ledger: ledger class

        Returns:
            return range of postitive commitment (object: dict), token, commit, and r
        """
        eqprs = []
        cm = []
        token = []
        rs = []
        prs = []
        if val == 0:
            four_square = (0,0,0,0)
        elif val > 0:
            four_square = InjectiveUtils.get_four_squares(val)
        for vi, val in enumerate(four_square):
            gh =  ledger.gh
            pk = ledger.pub_keys[id]
            newg = zkbp.g_to_x(gh, val)
            newgh = zkbp.gen_new_GH(newg,zkbp.from_str(gh.h))
            if smart_contract:
                pr = zkbp.sigma_eq_dlog_ped_proof_with_witness(val, gh, newgh, pk) 
                # prs.append(pr)
            else:
                pr = zkbp.sigma_eq_dlog_ped_proof(val, gh, newgh, pk)
                prs.append(pr)
            jpr = json.loads(pr)
            rs.append(r_blend(zkbp.to_scalar_from_str(jpr["r1"]['scalar'])))

            if smart_contract:
                useful_pr = InjectiveUtils.format_range_proof_positive_commitment(jpr)
                eqprs.append(useful_pr)

            tcm = zkbp.from_str(jpr['cm1']['point'])
            cm.append(tcm)
            ttoken = zkbp.to_token_from_str(jpr['token']['point'])
            token.append(ttoken)
        c = reduce(lambda x, y: zkbp.add(x, y), cm)
        t = reduce(lambda x, y: zkbp.add_token(x, y), token)
        r = reduce(lambda x, y: x+y, rs)
        
        if smart_contract:
            rpr = {"cm": Secp256k1.get_xy(c.get), "pr1": eqprs[0], "pr2": eqprs[1], "pr3": eqprs[2], "pr4": eqprs[3]}
            return rpr, t, c, r
        else :
            return prs, t, c, r
        

    
