import zkbp
from pyledger.extras.injective_utils import InjectiveUtils
from deployBN import deploy_contract
from web3 import Web3
import json

from pyledger.zkutils import BNCurve

w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))
#gh = zkbp.gen_GH()
#deployed_address,abi = deploy_contract('BNCurve')
#contract = w3.eth.contract(address=deployed_address,abi=abi)

def be2le(s):
    ba = bytearray.fromhex(s)
    ba.reverse()
    return ba.hex()
##########################################################################################################
##########################################################################################################
##########################################################################################################
"""
s1be = '0200000000000000000000000000000000000000000000000000000000000000'
s1betoint = int('0x'+s1be,16)

s1le = be2le(s1be)
s1gbe = zkbp.g_to_r(gh,zkbp.to_scalar_from_str(s1be)).x
s1gle = zkbp.g_to_r(gh,zkbp.to_scalar_from_str(s1le)).x
# h_to_x not work use zkbp.commit(0,x,gh) instead
s1hbe = zkbp.commit(0,zkbp.to_scalar_from_str(s1be),gh).x
s1hle = zkbp.commit(0,zkbp.to_scalar_from_str(s1le),gh).x

# now compute s1hbe from contract
hx = int(zkbp.get_x_coord(zkbp.from_str(gh.h)))
hy = int(zkbp.get_y_coord(zkbp.from_str(gh.h)))

#hle = be2le(gh.h)
#int(gh.h,16)
#hlex = zkbp.get_x_coord(zkbp.from_str(hle))
#hley = zkbp.get_y_coord(zkbp.from_str(hle))

resbe = contract.functions.mul(s1betoint, (hx,hy)).call()
print(resbe)

# conclusion: convert to be and multiply .. lets try again

gx = int(zkbp.get_x_coord(zkbp.from_str(gh.g)))
gy = int(zkbp.get_y_coord(zkbp.from_str(gh.g)))
resgbe = contract.functions.mul(s1betoint, (gx,gy)).call()

##########################################################################################################
##########################################################################################################
##########################################################################################################

# another try
s1bep = '132dfdcd63100facde85217d248f8b9a4a42ddf310680da8eb84002f97c9ee03'
s1betointp = int('0x'+s1bep,16)
resgbep = contract.functions.mul(s1betointp, (gx, gy)).call()

s1g = '215750dc6a7b8bdd645516330ba48d0ad4720c852606999e93ee59549dd53e93'
s1gx = int(zkbp.get_x_coord(zkbp.from_str(s1g)))
s1gy = int(zkbp.get_y_coord(zkbp.from_str(s1g)))
"""

gh = zkbp.gen_GH()
pksk = zkbp.gen_pb_sk(gh)
pk = pksk.get_pk()

####################### ######################## ################## ################### #################
########################## EQUIVALENCE PROOF ########################## ##########################
########################## ########################## ########################## ##########################

## Generate two commit and two tokens, then create a equivalence proof and then check verification
r1 = zkbp.gen_r()
r2 = zkbp.gen_r()
v = 10
cm1 = zkbp.commit(v,r1,gh)
cm2 = zkbp.commit(v,r2,gh)
tk1 = pksk.to_token(r1)
tk2 = pksk.to_token(r2)
h_to_dr = zkbp.sub(cm1, cm2)
pk_to_dr = zkbp.sub_token(tk1,tk2)
pr = zkbp.sigma_dlog_proof_explicit_sha256(pk_to_dr, pksk, h_to_dr)
result = zkbp.sigma_dlog_proof_explicit_verify_sha256(pr, h_to_dr, pk_to_dr)
jpr = InjectiveUtils(BNCurve()).format_proofs(pr=pr,curve="BN")
cadd, cabi = deploy_contract("EquivalenceProofBN")
contract = w3.eth.contract(address=cadd,abi=cabi)
nn = (jpr['pk'], jpr['pk_t_rand_commitment'],jpr['challenge_response'],)
#c = contract.functions.verifyEqProof((jpr['pk'], jpr['pk_t_rand_commitment'],jpr['challenge_response'],), (int(h_to_dr.x), int(h_to_dr.y),)).call()
#chal = (contract.functions.testchal((jpr['pk'], jpr['pk_t_rand_commitment'],jpr['challenge_response'],), (int(h_to_dr.x), int(h_to_dr.y),)).call())
#second = (contract.functions.testsecond((jpr['pk'], jpr['pk_t_rand_commitment'],jpr['challenge_response'],), (int(h_to_dr.x), int(h_to_dr.y),)).call())
#first = (contract.functions.testfirst((jpr['pk'], jpr['pk_t_rand_commitment'],jpr['challenge_response'],), (int(h_to_dr.x), int(h_to_dr.y),)).call())
print(contract.functions.verifyEqProof((jpr['pk'], jpr['pk_t_rand_commitment'],jpr['challenge_response'],), (int(h_to_dr.x), int(h_to_dr.y),)).call())
#exit()
####################### ######################## ################## ################### #################
########################## CONSISTENCY PROOF ########################## ##########################
########################## ########################## ########################## ##########################

r = zkbp.gen_r()
v = 10
cm = zkbp.commit(v,r,gh)
tk = pksk.to_token(r)
P_C = zkbp.consistency_proof_with_witness(v,r,gh,cm,tk,pk)

###### LETS TRY CONSISTENCY PROOF #######
#jpc = json.dumps(P_C)
fpc = InjectiveUtils(BNCurve()).format_consistency_proof(P_C, cm.get, tk.get, pk, 'BN')
pc = InjectiveUtils(BNCurve()).format_proofs(fpc,"BN")
nn = (pc['t1'], pc['t2'], pc['s1'], pc['s2'], pc['challenge'], pc['pubkey'], pc['cm'], pc['tk'], pc['chalcm'], pc['chaltk'], pc['s2pubkey'], pc['s1g'], pc['s2h'],)



cadd, cabi = deploy_contract("ConsistencyProofBN")
cpcontract = w3.eth.contract(address=cadd,abi=cabi)
c = cpcontract.functions.processConsistency((pc['t1'], pc['t2'], pc['s1'], pc['s2'], pc['challenge'],pc['pubkey'], pc['cm'], pc['tk'],pc['chalcm'], pc['chaltk'], pc['s2pubkey'], pc['s1g'], pc['s2h'],)).call()
#d = cpcontract.functions.checkchal((pc['t1'], pc['t2'], pc['s1'], pc['s2'], pc['challenge'],pc['pubkey'], pc['cm'], pc['tk'],pc['chalcm'], pc['chaltk'], pc['s2pubkey'], pc['s1g'], pc['s2h'],)).call()
print(c)

####################### ######################## ################## ################### #################
########################## DEBUG ########################## ##########################
########################## ########################## ########################## ##########################

"""
gp = gh.g
gx = int(zkbp.from_str(gp).x)
gy = int(zkbp.from_str(gp).y)
hp = gh.h
hx = int(zkbp.from_str(hp).x)
hy = int(zkbp.from_str(hp).y)



jpc=json.loads(P_C)
# g, h, t1, t2, pubkey, cm, tk,
t1 = jpc['t1']['point']
t2 = jpc['t2']['point']

chal = jpc['challenge']['scalar']
t1x = int(zkbp.from_str(t1).x)
t1y = int(zkbp.from_str(t1).y)

t2x = int(zkbp.from_str(t2).x)
t2y = int(zkbp.from_str(t2).y)

pkx = int(zkbp.from_str(pk).x)
pky = int(zkbp.from_str(pk).y)

cmx = int(cm.x)
cmy = int(cm.y)

tkx = int(zkbp.from_str(tk.get).x)
tky = int(zkbp.from_str(tk.get).y)

#print(zkbp.hash_test1(zkbp.from_str(pk)))
print(jpc['challenge'])
print(int('0x'+jpc['challenge']['scalar'], 16))
hashres = hex(cpcontract.functions.testHash((gx,gy,hx,hy,t1x,t1y,t2x,t2y,pkx,pky,cmx,cmy,tkx,tky)).call())

#print(cpcontract.functions.reverse(tcmx).call())

print(f"hashres is {hashres}")
print(int(hashres,16))
print('debug')

"""
