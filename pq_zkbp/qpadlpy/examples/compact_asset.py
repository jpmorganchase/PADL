import zkqp
"""Demo of Proof of Multi-Assets (Compact)"""

# ---------------------------
# Setup
# ---------------------------
pp, sk = zkqp.keygen()
cap = zkqp.poa_compact_setup()

# ---------------------------
# Commit to a vector of values
# ---------------------------
values = [5000,5,5,0,0,4,1,5]
cm, r = zkqp.commit_values(pp, values)
v1 = zkqp.extract_const_without_r(pp, sk, cm)
print("Extracted const term:", v1)
# ---------------------------
# Extract all coefficients
# ---------------------------
extracted = zkqp.extract_all_without_r(pp, sk, cm)
print("Extracted coeffs (first 8):", extracted[:8])
print("Matches input values:", extracted[: len(values)] == values)
# ---------------------------
# Proof of Asset (Compact)
# ---------------------------
proof = zkqp.gen_proof_of_asset_compact(pp, cap, cm, values, r, True)
ok = zkqp.verify_proof_of_asset_compact(pp, cap, cm, proof)
print("Verified Compact Asset:", ok)

