"""utilities - PADL - GTAR - London, JPMorgan"""
import sys
import os
from pathlib import Path
import zkbp
path = os.path.realpath(__file__)
parent_dir = str(Path(path).parents[1])
sys.path.append(parent_dir)
BITS = 32
import json
import numpy as np
from pyledger.zkutils import curve_util


class InjectiveUtils():

    @staticmethod
    def get_four_squares(x):
        """
        function to find numbers whose squares sum up to x = v1^2 + v2^2 + v3^2+ v4^2
        :param x: any integer
        :return: four integers whose squares sum up to x
        """
        xd = int(np.ceil(np.sqrt(x)))
        for i in range(0,xd):
            for j in range(0,xd):
                for l in range(0,xd):
                    for m in range(0,xd):
                        if i*i + j*j + l*l + m*m == x:
                            return (i,j,l,m)
        return(0,0,0,0)

    @staticmethod
    def format_range_proof_positive_commitment(rpr):
        useful_keys_point = {'cm1':'cm1',
                             'cm2':'cm2',
                             'cm3':'cm3',
                             'chalRspDg':'chalRspDg',
                             'chalRspD1h':'chalRspD1h',
                             'challengecm2':'challengecm2',
                             'chalRspDcm2':'chalRspDcm2',
                             'chalRspD2h':'chalRspD2h',
                             'challengecm3':'challengecm3'}

        useful_keys_scalar = {'challenge':'challenge',
                              'challenge_response_D':'chalRspD',
                              'challenge_response_D1':'chalRspD1',
                              'challenge_response_D2':'chalRspD2'}
        useful_pr_point = {useful_keys_point[key]:curve_util.get_xy(rpr[key]['point']) for key in useful_keys_point.keys()}
        useful_pr_scalar = {useful_keys_scalar[key]:int('0x'+rpr[key]['scalar'],16) for key in useful_keys_scalar.keys()}
        useful_pr_point.update(useful_pr_scalar)
        return useful_pr_point

    @staticmethod
    def format_proofs(pr):
        pr = json.loads(pr)
        sol_pr = pr
        for key,values in pr.items():
            if 'scalar' in pr[key]:
                sol_pr[key] = int('0x' + pr[key]['scalar'],16)
            elif 'point' in pr[key]:
                sol_pr[key] = curve_util.get_xy(pr[key]['point'])
            else:
                sol_pr[key] = pr[key]
        return sol_pr


    @staticmethod
    def format_eq_proof(pr):
        pr = json.loads(pr)
        useful_keys_point = {'pk': 'pk',
                             'pk_t_rand_commitment':'pktrand'}
                             #'chalrsph2r':'chalrsph2r',
                             #'challengepk':'challengepk'}

        useful_keys_scalar = {'challenge_response':'chalrsp'}
        useful_pr_point = {useful_keys_point[key]:curve_util.get_xy(pr[key]['point']) for key in useful_keys_point.keys()}
        useful_pr_scalar = {useful_keys_scalar[key]:int('0x'+pr[key]['scalar'],16) for key in useful_keys_scalar.keys()}
        useful_pr_point.update(useful_pr_scalar)
        return useful_pr_point

    @classmethod
    def get_eq_order(cls,peq):
        return (peq['pk'], peq['pktrand'],peq['chalrsp'],)

    @staticmethod
    def format_consistency_proof(P_C, cm, token, pubkey):
        pc = json.loads(P_C)
        pc['cm'] = curve_util.get_xy(cm)
        pc['tk'] = curve_util.get_xy(token)
        pc['pubkey'] = curve_util.get_xy(pubkey)
        return json.dumps(pc)

    @classmethod
    def get_pc_order(cls,pc):
        return (pc['t1'], pc['t2'], pc['s1'], pc['s2'], pc['challenge'], pc['pubkey'], pc['cm'], pc['tk'], pc['chalcm'],
              pc['chaltk'], pc['s2pubkey'], pc['s1g'], pc['s2h'],)

    @staticmethod
    def format_tx_to_solidity(tx):
        """
        formats a transaction to solidity transaction structure
        :param tx: PADL transaction
        :return: PADL transaction as defined on smart contract 'PADLOnChain.sol'
        """
        txsol = []
        compcm = ""
        comptk = ""
        eqp = ""
        comppc = ""
        for a in range(0, len(tx)):
            for p in range(0, len(tx[a])):
                if tx[a][p].cm_:
                    eqp = tx[a][p].P_A[1]
                    compcm = curve_util.get_xy(tx[a][p].cm_)
                    comptk = curve_util.get_xy(tx[a][p].token_)
                    comppc = tx[a][p].P_C_

        for a in range(0, len(tx)):
            for p in range(0, len(tx[a])):
                if tx[a][p].cm_:
                    txsol.append({'cm': curve_util.get_xy(tx[a][p].cm),
                                  'tk': curve_util.get_xy(tx[a][p].token),
                                  'compcm': compcm,
                                  'comptk': comptk,
                                  'ppositive': tx[a][p].P_A[0],
                                  'pc': InjectiveUtils.format_proofs(tx[a][p].P_C),
                                  'peq': InjectiveUtils.format_eq_proof(eqp),
                                  'pc_': InjectiveUtils.format_proofs(tx[a][p].P_C_)})
                else:
                    txsol.append({'cm': curve_util.get_xy(tx[a][p].cm),
                                  'tk': curve_util.get_xy(tx[a][p].token),
                                  'compcm': compcm,
                                  'comptk': comptk,
                                  'ppositive': tx[a][p].P_A,
                                  'pc': InjectiveUtils.format_proofs(tx[a][p].P_C),
                                  'peq': InjectiveUtils.format_eq_proof(eqp),
                                  'pc_': InjectiveUtils.format_proofs(comppc)})
        return txsol

    def format_range_proof(self,rp, cm):

        def ptsol(point_str):
            return (int(zkbp.from_str(point_str["point"]).x), int(zkbp.from_str(point_str["point"]).y))

        def ptsol_arr(point_str_arr):
            return [(int(zkbp.from_str(point_str["point"]).x), int(zkbp.from_str(point_str["point"]).y)) for point_str
                    in point_str_arr]

        def ssol(scalar_str):
            return int((scalar_str["scalar"]), 16)

        ghvec = json.loads(zkbp.ghvec(BITS))
        gh = zkbp.gen_GH()
        range_proof_json = json.loads(rp)
        range_proof_sol = ((ptsol(range_proof_json["A"]), ptsol(range_proof_json["S"]), ptsol(range_proof_json["T1"]),
                            ptsol(range_proof_json["T2"]), ssol(range_proof_json["tau_x"]),
                            ssol(range_proof_json["miu"]), ssol(range_proof_json["tx"]),
                            int(range_proof_json["inner_product_proof"]["a_tag"], 16),
                            int(range_proof_json["inner_product_proof"]["b_tag"], 16), ptsol({"point": gh.g}),
                            ptsol({"point": gh.h}), ptsol({"point": cm}),
                            ptsol_arr(range_proof_json["inner_product_proof"]["L"]),
                            ptsol_arr(range_proof_json["inner_product_proof"]["R"]), ptsol_arr(ghvec[0]),
                            ptsol_arr(ghvec[1])))

        return range_proof_sol

    @staticmethod
    def check_tx_structure(tx, send_ID):
            """Check the structure (data type and variable length)
            Args:
                tx (list): a list of transactions
                vals (list): a list of asset
            """
            result = []
            for i in range(len(tx)):
                for id,v in enumerate(tx[i]):
                    result.append(InjectiveUtils.check_help(tx[i][id], id, send_ID))
            return all(res==True for res in result)

 
    @staticmethod
    def check_help(tx, id, send_ID):
            """help function to check the type and ;ength of each variable in tx
            Args:
                tx (object): one transaction object
                id (int): the index number of asset in vals[i]
            """
            # there are both a solidity and rust version for the checking structure
            type_checks_seid = [ #('P_A[0]', dict, 'asset type is wrong'), #solidity
                #('P_A[1]', str, 'eqpr type is wrong'), #solidity
                ('P_A', list, 'rpr type is wrong'), #rust
                ('P_C_', str, 'complimentary consistency type is wrong'),
                ('cm_', str, 'complimentary commit type is wrong', 66),
                ('token_', str, 'complimentary token type is wrong', 66),
                #('P_Eq', str, 'proof of Eq type is wrong')]
                # for common variables
                ('P_C', str, 'consistency type is wrong'),
                ('cm', str, 'commit type is wrong', 66),
                ('token', str, 'token type is wrong', 66)]

            type_checks_Nseid = [ #('P_A', dict, 'asset type is wrong'), #solidity
                ('P_A', list, 'asset type is wrong'), #rust
                # for common variables
                ('P_C', str, 'consistency type is wrong'),
                ('cm', str, 'commit type is wrong', 66),
                ('token', str, 'token type is wrong', 66)]

            if send_ID==id:
                type_checks = type_checks_seid
            else:
                type_checks= type_checks_Nseid

            for name, err_type, error_tx, *length in type_checks:
                value = getattr(tx, name, None)
                if not isinstance(value,err_type) or (length and len(value)!=length[0]):
                    print(f'The transaction proof of {error_tx}')
                    return False

            return True

