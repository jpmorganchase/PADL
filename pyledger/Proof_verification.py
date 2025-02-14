"""
ZK proof verification for a ledger cell by using zkbp module.
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
parent_dir = str(Path(path).parents[1])  # go up 2 levels [1] to '/zkledgerplayground/'
sys.path.append(parent_dir)
from pyledger.zkutils import Commit, Token, r_blend, Secp256k1  # interface to zkbp.
from pyledger.extras.injective_utils import InjectiveUtils
BITS = 32
MAX = int(2 ** 16)
# MAX = int(2 ** (BITS / 4))




class Auditing:
    """
       Represents auditing to non-interactive proofs of the ledger that anyone can do.
       ----------
    """
    @staticmethod
    def validate_proof_of_balance(tx):
        cms = [c.cm for c in tx]
        sum_cms = reduce(lambda x, y: zkbp.add_value_commits(x, y), cms)
        if zkbp.from_str(sum_cms).is_zero():
            for t in tx: t.P_B = True
            return True
        else:
            for t in tx: t.P_B = False
            assert False, "proof of balance in Tx is failed."


    @staticmethod
    def valdiate_proof_of_asset(txs, zero_line, i, tx, nbit=int(BITS), asset=0):
        range_proof = tx[i].P_A
        if isinstance(range_proof,list):
            range_proof = tx[i].P_A[0] # the first index is proof A, the second is eq proof which can be removed.
        cms = [x[asset][i].cm for x in txs if len(x) > asset]
        cms.append(zero_line[i][asset].cm)  # issued asset value
        cms.append(tx[i].cm)  # new Tx commit
        cms = filter(lambda x:  x is not None, cms)
        sum_cms = reduce(lambda x, y: zkbp.add_value_commits(x, y), cms)
        cms_obj = zkbp.from_str(sum_cms)  # add proof of eq.

        result = zkbp.range_proof_single_verify(range_proof, nbit, zkbp.gen_GH(), zkbp.from_str(tx[i].cm_))
        assert result, "proof of asset is failed"

    @staticmethod
    def valdiate_proof_of_positive_commit(cm:str, range_proof:str, nbit=int(BITS)):
        result = zkbp.range_proof_single_verify(range_proof, nbit, zkbp.gen_GH(), zkbp.from_str(cm))
        assert result, "proof of asset is failed"

    @staticmethod
    def valdiate_proof_of_consistency(pub_keys, i, tx):
        consistency_proof = tx[i].P_C
        cm = zkbp.from_str(tx[i].cm)
        token = zkbp.to_token_from_str(tx[i].token)
        result = zkbp.consistency_proof_verify(proof=consistency_proof, gh=zkbp.gen_GH(), ped_cm=cm, token=token,
                                               pubkey=pub_keys[i])
        assert result, "proof of consistency between token and commit is failed"

    @staticmethod
    def valdiate_proof_of_ext_consistency(pub_keys, i, tx):
        consistency_proof = tx[i].P_C_
        cm = zkbp.from_str(tx[i].cm_)
        token = zkbp.to_token_from_str(tx[i].token_)
        result = zkbp.consistency_proof_verify(proof=consistency_proof, gh=zkbp.gen_GH(), ped_cm=cm, token=token,
                                               pubkey=pub_keys[i])
        assert result, "proof of consistency between token_ and commit_ is failed"

    @staticmethod
    def audit_asset_balance(ledger, bank_id, asset):
        pr, sval = ledger.bank_comm.receive_asset_balance_proof(ledger, bank_id, asset)
        all_sc, all_st = ledger.compute_sum_commits_tokens()
        sc = all_sc[asset][bank_id]
        st = all_st[asset][bank_id]
        g_to_sval = zkbp.g_to_x(ledger.gh, sval[asset])
        h_sum_r = zkbp.sub(sc, g_to_sval)
        return zkbp.sigma_dlog_proof_explicit_verify(pr, h_sum_r, st)

    @staticmethod
    def verify_asset_balance(scst, gh, pr, sval, bank_id, asset):
        all_sc, all_st = json.loads(scst)
        sc = zkbp.from_str(all_sc[asset][bank_id])
        st = zkbp.to_token_from_str(all_st[asset][bank_id])
        g_to_sval = zkbp.g_to_x(gh, sval[asset])
        h_sum_r = zkbp.sub(sc, g_to_sval)
        return zkbp.sigma_dlog_proof_explicit_verify(pr, h_sum_r, st)

    @staticmethod
    def verify_value_eq_cm(i, tx,state):
        eq_value_proof = tx[i].P_Eq
        cm_sum = zkbp.add_value_commits(state[i].cm, tx[i].cm) # state+ cm
        cm_ = Commit.from_str(tx[i].cm_) 
        token_sum = zkbp.add_token(zkbp.to_token_from_str(state[i].token),zkbp.to_token_from_str(tx[i].token)) # state + token

        token_ = zkbp.to_token_from_str(tx[i].token_)

        h_to_dr = Commit.from_str(cm_sum) - cm_  # when g^v_*g^v=1
        pk_to_dr = zkbp.sub_token(token_sum, token_)
        result = zkbp.sigma_dlog_proof_explicit_verify(eq_value_proof, h_to_dr.eval, pk_to_dr)
        assert result, "proof of consistency between value in cm and cm_ is failed"

    @staticmethod
    def valdiate_proof_of_ratio_asset(ledger, range_proof, nbit=BITS, asset=0, i=0, n=1, d=2):
        '''validate range proofs that an asset is within threshold of n/d. The cm_ is used for the sum'''
        tx = ledger.txs[-1] # last transaction cm_ is verified sum
        sum_cms = tx[asset][i].cm_
        cmsall=[]
        for txa in tx:
            cmsall.append(txa[i].cm_)
        sum_cms_all = reduce(lambda x, y: zkbp.add_value_commits(x, y), cmsall)

        sum_cms_all = Commit.from_str(sum_cms_all)
        sum_cms = Commit.from_str(sum_cms)

        sum_cms_all = sum_cms_all * n
        sum_cms = sum_cms * d
        ratiocms = sum_cms_all - sum_cms

        result = zkbp.range_proof_single_verify(range_proof, nbit, ledger.gh, ratiocms.eval)
        assert result, "proof of asset is failed"


    @staticmethod
    def validate_proof_of_asset_injective_tx(tx, bank_id, ledger, asset):
        """validate the proof of asset for bank itself
        Args:
            tx (list): a list of transactions
            i (int): index
            ledger (object): ledger class
            asset (int): asset index
        """
        # get historical of all commitments and token
        all_sc, all_st = json.loads(ledger.compute_sum_commits_tokens())
        # add current commitment and token
        comp_sc = [zkbp.from_str(all_sc[asset][bank_id]), zkbp.from_str(tx[asset][bank_id].cm)]
        comp_st = [zkbp.to_token_from_str(all_st[asset][bank_id]), zkbp.to_token_from_str(tx[asset][bank_id].token)]

        sum_commit = reduce(lambda x, y: zkbp.add(x, y), comp_sc)
        sum_token = reduce(lambda x, y: zkbp.add_token(x, y), comp_st)
        # subtract complimentary commitment
        sum_com_minus_pcm = Commit.from_str(sum_commit.get) - Commit.from_str(tx[asset][bank_id].cm_)
        sum_token_minus_ptoken = zkbp.sub_token(zkbp.to_token_from_str(sum_token.get), zkbp.to_token_from_str(tx[asset][bank_id].token_))


        pf = tx[asset][bank_id].P_A [1]
        rpr = tx[asset][bank_id].P_A[0]
        cm_ = tx[asset][bank_id].cm_
        result = zkbp.sigma_dlog_proof_explicit_verify_sha256(pf,sum_com_minus_pcm.eval,sum_token_minus_ptoken)


        Auditing.validate_proof_of_positive_commitment(rpr, cm_, ledger)



        assert result, "proof of asset is failed"

    @staticmethod
    def validate_eqpr_proof(tx, ledger):
        """check the four proofs in range proof positive commit (rpr)

        Args:
            tx (object): transaction object
            ledger (object): ledger object

        Returns:
            bool: whether eq positive proof is achieved
        """
        result = []
        if len(tx.P_A)>1:
            rpr = tx.P_A[0]
        else:
            rpr = tx.P_A

        if isinstance(rpr, list):
            for i in range(len(rpr)):
                result.append(zkbp.sigma_eq_dlog_ped_verify(rpr[i], ledger.gh, ledger.gh))
            eq_output = all(res==True for res in result)
        else:
            eq_output = zkbp.sigma_eq_dlog_ped_verify(rpr, ledger.gh, ledger.gh)



        return eq_output

    @staticmethod
    def audit_all_proof_of_asset_injective_tx(tx, ledger, id):
        for a in range(len(tx)):
            if not Auditing.validate_proof_of_balance(tx[a]):
                return False
            for p in range(len(tx[a])):
                if p == id:
                    if not Auditing.validate_proof_of_asset_injective_tx(tx, id, ledger, a):
                        return False
                    Auditing.valdiate_proof_of_consistency(ledger.pub_keys, )
                else:
                    if not Auditing.validate_proof_of_positive_commitment(tx[a][p].P_A, tx[a][p].cm, ledger):
                        return False
        return True
    @staticmethod
    def validate_proof_of_positive_commitment(rpr, cm, ledger):
        """used to validate the range proof positive commitment;

        Args:
            rpr (list): positive range proof
            cm (object): commitment
            ledger (object): ledger object
        """
        # check if it consists of 4 equivalence proofs and if the sum of four commitments is equal to total commitment
        result = []
        cms = []
        if len(rpr) == 4:
            for i in range(len(rpr)):
                cms.append(zkbp.from_str(json.loads(rpr[i])['cm1']['point']))
                result.append(zkbp.sigma_eq_dlog_ped_verify(rpr[i], ledger.gh, ledger.gh))
            cmsum = reduce(lambda x, y: zkbp.add(x, y), cms)
            eq_output = all(res==True for res in result)
            assert (eq_output and (cmsum.get == cm)), "Proof of positive commitment failed"
        else:
            assert False, "Proof of positive commitment failed, length not equal to four"
