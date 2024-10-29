from unittest import TestCase
import zkbp
import os,sys
from pathlib import Path
path = os.path.realpath('0-zkbp-intro.ipynb')
sys.path.append(str(Path(path).parents[1]))  # go up 2 levels [1] to '/pyledger/'
from pyledger.zkutils import Commit,r_blend, Token
 

class TestLocal(TestCase):
    def test_generator_operation(self):
        # generate g and h
        gh = zkbp.gen_GH()
        # generate public and secret key
        key_pair = zkbp.gen_pb_sk(gh)
        pk = key_pair.get_pk()
        sk = key_pair.get_sk()
        sk_scalar_obj  = zkbp.to_scalar_from_str(key_pair.get_sk())
        recons_key_pair = zkbp.regen_pb_sk(gh,sk_scalar_obj)
        assert recons_key_pair.get_pk() == pk and recons_key_pair.get_sk()==sk, "Reconstructed PK or SK does not agree"

        # generate a random scalar r
        r = zkbp.gen_r()
        print(f'r is {r.get}')

        # This r does not have add, mult,neg functions, so we use class r_blend()
        r = r_blend()
        rd = -r 
        # Group Operations
        hx = zkbp.h_to_x(gh, r.val)
        gr = zkbp.g_to_r(gh, r.val)
        gx = zkbp.g_to_x(gh, 123)
        assert gx.to_str=='02236c0a8acaa8ba321ca24d058efd9a9082fbf967f318db15b88f2df41c30d59e', 'gx error'

        value = 13
        r = zkbp.gen_r()
        cm = zkbp.commit(value, r, gh)
        comx = zkbp.p_to_x(cm, r)

    def test_commitment_operation(self):
        # Pedersen commitment generation
        import zkbp.zkbp

        zero_string = "000000000000000000000000000000000000000000000000000000000000000000"
        value = 13
        # generate g and h
        gh = zkbp.gen_GH()
        r = zkbp.gen_r()
        cm = zkbp.commit(value, r, gh)        

        # Commitment operations (Add, Sub)
        cm_sample = zkbp.commit(value+value, r.sum(r), gh)
        new_comm = zkbp.add(cm,cm)
        assert new_comm.to_str == cm_sample.to_str, "commit3 = Add(commit1,commit2) should satisfies commit3 === Commit(commit1.value + commit2.value, commit1.r + commit2.r)"

        new_comm = zkbp.sub(cm,cm)
        assert new_comm.to_str == zero_string, "Sub(commit1,commit2) should return 0 if commit1 === commit2"

        # Commitment operations for commitment string, returning the same string structure
        new_comm_str_repr = zkbp.add_value_commits(cm.to_str,cm.to_str)
        assert new_comm_str_repr == cm_sample.to_str, "commit3 = Add(commit1,commit2) should satisfies commit3 === Commit(commit1.value + commit2.value, commit1.r + commit2.r)"

        new_comm_str_repr = zkbp.sub_value_commits(cm.to_str,cm.to_str)
        assert new_comm_str_repr == zero_string, "Sub(commit1,commit2) should return 0 if commit1 === commit2"

        # Construct a commit point from its string representation
        # new_cm := sub(cm,cm) should be that new_cm === from_str(new_cm_str_repr)
        new_comm = zkbp.sub(cm,cm)
        new_comm_str_repr = zkbp.sub_value_commits(cm.to_str,cm.to_str)
        new_cm = zkbp.from_str(new_comm_str_repr)
        assert new_comm.to_str == new_cm.to_str, "Converting from commitment string representation should remain the same."

    def test_token_operation(self):
        # Alternative option (Note that this is different object, Commit is python Commit-helper_class while zkbp.commit return a rust commit)
        # generate g and h
        gh = zkbp.gen_GH()
        key_pair = zkbp.gen_pb_sk(gh)
        value = 13

        r = r_blend()
        cmd = Commit(gh, value, r)
        print(cmd.eval.get)

        # we can also create a token that is just the public key raised to r
        r = r_blend()
        tk = key_pair.to_token(r.val)
        print(tk.to_str)

        # Token reconstruction
        tk_recons = zkbp.to_token_from_str(tk.to_str)
        assert tk.to_str == tk_recons.to_str, "Reconstructed token should not differ in value."

        # Adding and Subtraction
        r = r_blend()
        tk1 = key_pair.to_token(r.val)
        r2 = r_blend()
        tk2 = key_pair.to_token(r2.val)
        tk_ref = key_pair.to_token(r.val.sum(r2.val))
        tk_sum = zkbp.add_token(tk1,tk2)
        assert tk_sum.to_str == tk_ref.to_str, "Adding token should be the same as adding the blinding factor before constructing token"
        tk_ref = key_pair.to_token(r.val.sum(r2.val.neg()))
        tk_sum = zkbp.sub_token(tk1,tk2)
        assert tk_sum.to_str == tk_ref.to_str, "Subtracting token should be the same as subtracting the blinding factor before constructing token"

        # PK to token
        ref_token = key_pair.to_token(r.val)
        token = zkbp.to_token_from_pk(key_pair.get_pk(), r.val)
        assert token.to_str == ref_token.to_str, "Tokens should be equal."

        #Commit - token combined operation
        value = 13
        r = zkbp.gen_r()
        cm = zkbp.commit(value, r, gh)
        r = r_blend()
        tk1 = key_pair.to_token(r.val)
        element1 = zkbp.sub_commit_token(cm, tk1)
        element2 = zkbp.add_commit_token(element1, tk1)
        assert cm.to_str == element2.to_str, "Subtracting and then adding back the same element should be behave like an identity function."

    def test_dlog_calculation(self): 
        # generate g and h
        gh = zkbp.gen_GH()
        key_pair = zkbp.gen_pb_sk(gh)
        v = 100
        r = zkbp.gen_r()
        cm = zkbp.commit(v, r, gh)
        tk = key_pair.to_token(r)
        max_range = 1000000

        computed_v = zkbp.get_brut_v(cm,tk,gh,key_pair,max_range)
        assert v==computed_v, "Brute-forcing g^v should give the correct v."

    def test_hash_commit(self):
        # generate g and h
        gh = zkbp.gen_GH()

        v = 10
        r = zkbp.gen_r()
        cm = zkbp.commit(v, r, gh)

        hash1 = zkbp.hash_test1(cm)
        hash2 = zkbp.hash_test2(cm,cm)
        hash3 = zkbp.hash_test3(cm,cm,cm)

        assert hash1!=hash2!=hash3, 'Hash error'

    def test_proof_of_knowledge(self):
        # proof of knowledge test

        # generate g and h
        gh = zkbp.gen_GH()
        
        # generate public and secret key
        pk_sk_obj = zkbp.gen_pb_sk(gh)
        sval = 10
        r = r_blend()
        cm = Commit(gh,sval,r)
        tk = pk_sk_obj.to_token(r.val)

        h2r = zkbp.sub(zkbp.from_str(cm.eval.get), zkbp.from_str(zkbp.g_to_x(gh, sval).get))
        pr = zkbp.sigma_dlog_proof_explicit_sha256(tk,pk_sk_obj,h2r)
        t = zkbp.sigma_dlog_proof_explicit_verify_sha256(pr,h2r,tk)

        print(t)
        assert t, "proof of knowledge error"


        ### Vefication failed scenario if trying another sk to open the above
        pk_sk_obj_ = zkbp.gen_pb_sk(gh)
        pr_ = zkbp.sigma_dlog_proof_explicit_sha256(tk, pk_sk_obj_, h2r)
        t_ = zkbp.sigma_dlog_proof_explicit_verify_sha256(pr_, h2r, tk)
        
        if t_:
            print('Proof of knowledge verified successfully.')
        else:
            print('Proof of knowledge verification failed as trying to use different keys.')


    def test_range_proof(self):
        # range proof test
        v = 10 
        r = r_blend()
        gh = zkbp.gen_GH()
        cm = Commit(gh, v, r)
        n_bit = 4 #(try 1, 2)
        pr = zkbp.range_proof_single(n_bit=n_bit, val=v, gh=gh, r=r.val)
        res = zkbp.range_proof_single_verify(pr, n_bit, gh, cm.eval)

        print(res)
        assert res, "range proof error"

        ### Vefication failed scenario, if v<0
        v = -10 
        r = r_blend()
        gh = zkbp.gen_GH()
        cm = Commit(gh, v, r)
        n_bit = 4 #(try 1, 2)
        pr = zkbp.range_proof_single(n_bit=n_bit, val=v, gh=gh, r=r.val)
        res = zkbp.range_proof_single_verify(pr, n_bit, gh, cm.eval)

        print(res)
        if res:
            print('Proof verified successfully.')
        else:
            print('range proof failed as v is negative.')

        ### Vefication failed scenario, if v>2^N, which is above the range
        v = 2**10
        r = r_blend()
        gh = zkbp.gen_GH()
        cm = Commit(gh, v, r)
        n_bit = 4 #(try 1, 2)
        pr = zkbp.range_proof_single(n_bit=n_bit, val=v, gh=gh, r=r.val)
        res = zkbp.range_proof_single_verify(pr, n_bit, gh, cm.eval)

        print(res)
        if res:
            print('range proof verified successfully.')
        else:
            print('range proof failed as v is above the range.')            
 
    def test_discrete_log_equality_proof(self):  
        # finally lets try a discrete log equality proof 
        # this proof lets you prove a balance:
        # that sum of commits will open to balance and sum of tokens blinding factors (rs)

        # generate g and h
        gh = zkbp.gen_GH()
        
        # generate public and secret key
        pk_sk_obj = zkbp.gen_pb_sk(gh)
        r = r_blend()
        val = 10
        tk = pk_sk_obj.to_token(r.val)
        cm = Commit(gh,val,r).eval
        h_sum_r = zkbp.sub(cm, zkbp.g_to_x(gh, val))
        pr = zkbp.sigma_eq_dlog_proof_sha256(tk, pk_sk_obj, gh, h_sum_r)
        cm = Commit(gh,val,r).eval
        res = zkbp.sigma_eq_dlog_verify_sha256(pr, gh, h_sum_r, tk)
        print(res)
        assert res, "discrete log equality proof error"
        ### Vefication failed scenario if trying to use different val value
        val_ = 20
        h_sum_r_ = zkbp.sub(cm, zkbp.g_to_x(gh, val_))
        res_ = zkbp.sigma_eq_dlog_verify_sha256(pr, gh, h_sum_r_, tk)

        if res_:
            print('discrete log equality proof verified successfully.')
        else:
            print('discrete log equality proof verification failed as trying to use different val value.')



    def test_Proof_of_consistency(self): 
        # Proof of consistency test

        # generate g and h
        gh = zkbp.gen_GH()
        
        # generate public and secret key
        pk_sk_obj = zkbp.gen_pb_sk(gh)
        pk = pk_sk_obj.get_pk()


        r = r_blend()
        v = 0
        tk = pk_sk_obj.to_token(r.val)
        cm = Commit(gh,v,r).eval
        pr = zkbp.consistency_proof(v,r.val,gh,cm,tk,pk)
        result = zkbp.consistency_proof_verify(proof=pr, gh=gh, ped_cm=cm, token=tk,
                                                    pubkey=pk_sk_obj.get_pk())
        print(result)

        assert result, "Proof of consistency error"

        ### Vefication failed scenario if trying to use different val value
        pk_sk_obj_ = zkbp.gen_pb_sk(gh)
        pk_ = pk_sk_obj_.get_pk()

        pr_ = zkbp.consistency_proof(v,r.val,gh,cm,tk,pk_)
        result_ = zkbp.consistency_proof_verify(proof=pr_, gh=gh, ped_cm=cm, token=tk,
                                                    pubkey=pk_sk_obj.get_pk())

        if result_:
            print('Proof of consistency verified successfully.')
        else:
            print('Proof of consistency verification failed as trying to use different r value.')