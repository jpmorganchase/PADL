import zkqp
'''Demo of Efficient Post Quantum Secured ZKP'''
# ---------------------------
# Key generation
# ---------------------------
pp, sk = zkqp.keygen()

# ---------------------------
# Commit to values and return random
# ---------------------------
c1, r1 = zkqp.commit_value(pp, 10000)
c2, r2 = zkqp.commit_value(pp, -10000)

# ---------------------------
# Homomorphic addition for r and value
# ---------------------------
csum = zkqp.add_commitments(c1, c2)
rs = [r1, r2]
r_sum = zkqp.sum_r_bytes(rs)
proof = zkqp.gen_proof_of_balance(pp, [c1,c2], r_sum)
ok= zkqp.verify_proof_of_balance(pp, [c1,c2], proof)
print("Verified Balance:", ok)

# ---------------------------
# Extract without randomness
# ---------------------------
v1 = zkqp.extract_const_without_r(pp, sk, c1)
v2 = zkqp.extract_const_without_r(pp, sk, c2)
print("Extracted values:", v1,v2)

# --------------------------
# proof of consistency
# --------------------------
cpp = zkqp.consistency_setup()
proof = zkqp.gen_proof_of_consistency(pp, cpp, v1, r1)
ok = zkqp.verify_proof_of_consistency(pp, cpp, c1, proof)
print("Well-formed:", ok)


# ---------------------------
# proof of asset
# ---------------------------
proof = zkqp.gen_proof_of_asset(pp, c1, 10000, r1)
ok = zkqp.verify_proof_of_asset(pp, c1, proof)
print("Verified Asset:", ok)

# --------------------------
# proof of equivalence
# --------------------------
poe_pp = zkqp.poe_setup()
c2new, r2new, proof = zkqp.recommit_and_prove_equivalence(pp, poe_pp, sk, c2)
ok = zkqp.verify_proof_of_equivalence(pp, poe_pp, c2, c2new, proof)
print("Verified recommitted value:", ok)

# --------------------------
# proof of opening
# --------------------------
op = zkqp.opening_setup()
cm1, r = zkqp.commit_value(pp, 123)
cm_abdlop, s = zkqp.abdlop_commit_full_value(op, 123, r)
proof = zkqp.gen_proof_of_opening(op, r, s, cm_abdlop)
ok =zkqp.verify_proof_of_opening(op, proof)
print('knowledge of x:',ok)


