import solcx
import json
from web3 import Web3
from solcx import compile_standard

from pyledger.extras.injective_utils import InjectiveUtils

#solcx.install_solc("0.8.28")
w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))

def deploy_contract(name):
    with open (f'./{name}.sol', 'r') as file:
        contractfile = file.read()

    account_address = '0x21D97d67b66Dff240739Ef8a4DC65539194AC758'
    private_key = '0x2db7be3cb37926e1c573c7979cdcb220ecb3c297ade7853ea3805d9355dc0813'

    compiled_sol = compile_standard(
                {
                    "language": "Solidity",
                    "sources": {f"{name}.sol": {"content": contractfile}},
                    "settings": {
                        "optimizer":{
                            "enabled":False,
                                "runs": 100,
                                "details": {
                                    "peephole": True,
                                    "inliner": True,
                                    "jumpdestRemover": True,
                                    "orderLiterals": True,
                                    "deduplicate": True,
                                    "cse": True,
                                    "constantOptimizer": True,
                                    "yul": True,
                                }
                        },
                        "viaIR": True,
                        "evmVersion": "london",

                        "outputSelection": {
                            "*": {
                                "*": ["abi", "metadata", "evm.bytecode", "evm.sourceMap"]
                            }
                        }
                    },
                },
                solc_version="0.8.28"
    )

    with open(f'compiled_{name}.json', 'w') as f:
        json.dump(compiled_sol,f)

    bytecode = compiled_sol["contracts"][f"{name}.sol"][name]["evm"]["bytecode"]["object"]
    abi = compiled_sol["contracts"][f"{name}.sol"][name]["abi"]
    contractobj = w3.eth.contract(abi=abi,bytecode=bytecode)

    account_address=Web3.toChecksumAddress(account_address)
    nonce = w3.eth.get_transaction_count(account_address)
    transaction = contractobj.constructor().buildTransaction(
        {"chainId": 1337, "from": account_address, "nonce": nonce}
    )
    signed_tx = w3.eth.account.sign_transaction(transaction,private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    deployed_address = tx_receipt.contractAddress
    print(f"deployed at {deployed_address}")
    return deployed_address, abi
"""
scstr = '11c4a160c57fcc4863f8d44c1dc1d894c2da25d9dc10904b0931d50f0c2e92da'
bnystr = '0x25a5e98b6640d73bbf293699cec8bc2573ee8ff441a89ab4e52d1cd091d9d4e8'
bnxstr = '0x2a0c510e67c136cc6e7acddd7e407198a0d7f9157ab31371f1a3b1b2ba433217'


sc = int(scstr,16)
bny = int(bnystr, 16)
bnx = int(bnxstr, 16)
deployed_address, abi = deploy_contract("BNCurve")
prev_contract = w3.eth.contract(address=deployed_address,abi=abi)
p1 = {'x':bnx, 'y':bny}
p2 = {'x':bnx, 'y':bny}
b = prev_contract.functions.mul((sc),(bnx, bny)).call()

#print(b)
#exit()

PC = {
  "chalcm" : {
    "curve" : "bn254",
    "point" : "8dc279b735f814a166524ff7d56eaa72af1c13caac4c2315ae42a31b7e866ea3"
  },
  "challenge" : {
    "curve" : "bn254",
    "scalar" : "1259cfe496227eb99f78d50b26e7eaca94cd66fc2eed5997edf276618b75a8f1"
  },
  "chaltk" : {
    "curve" : "bn254",
    "point" : "8258b3c698bfc9dcf00c102c888bf8990e1cd817d9d667d1575b520c7cbc7628"
  },
  "s1" : {
    "curve" : "bn254",
    "scalar" : "132dfdcd63100facde85217d248f8b9a4a42ddf310680da8eb84002f97c9ee03"
  },
  "s1g" : {
    "curve" : "bn254",
    "point" : "215750dc6a7b8bdd645516330ba48d0ad4720c852606999e93ee59549dd53e93"
  },
  "s2" : {
    "curve" : "bn254",
    "scalar" : "23c83eed7429a745998d684bca4e56288571e505542f53ab28c7411e13e617f6"
  },
  "s2h" : {
    "curve" : "bn254",
    "point" : "a37eb1768df8be1a07b563f3c9a4142e2d6f644363af735b7b39e2764821fca3"
  },
  "s2pubkey" : {
    "curve" : "bn254",
    "point" : "a49a5a11ba2d54a1d1db07bb56c4f5a2a308d753b3d7456a571db1edebca7811"
  },
  "t1" : {
    "curve" : "bn254",
    "point" : "6be2450aca6309ffac2217187ca35a5aebaaf26c2aebb39f75e345ce241bf29a"
  },
  "t2" : {
    "curve" : "bn254",
    "point" : "c09b93ec6b876f500f9a6bd3fa29e62b0c5c7dc8cbc4d41ceb527608eb5d5f9e"
  }
}

cm = 'e83fa78a498181fa5c51b1f44d2f0adbde30f1362f67b1a698bd4080cfb82b23'
token = 'bb1ff1b424955a6c5815f265ea35bd313d9cbdaed141e6316edd561cec6d560e'
pubkey = '034a3c6d5c3c6b6e31e7320e4e7ae1d64d3507f181f670ea61f8888737657a17'

gh = zkbp.gen_GH()
g = gh.g
h = gh.h
gx = int('0x'+zkbp.get_x_coord(zkbp.from_str(g)),16)
gy = int('0x'+zkbp.get_y_coord(zkbp.from_str(g)),16)
hx = int('0x'+zkbp.get_x_coord(zkbp.from_str(h)),16)
hy = int('0x'+zkbp.get_y_coord(zkbp.from_str(h)),16)
print(f"gx is {gx}")
print(f"gy is {gy}")
print(f"hx is {hx}")
print(f"hy is {hy}")





print(f"s1gx is {int('0x'+zkbp.get_x_coord(zkbp.from_str(PC['s1g']['point'])),16)}")

jpc = json.dumps(PC)
fpc = InjectiveUtils.format_consistency_proof(jpc, cm, token, pubkey, 'BN')
pc = InjectiveUtils.format_proofs(fpc,"BN")
nn = (pc['t1'], pc['t2'], pc['s1'], pc['s2'], pc['challenge'], pc['pubkey'], pc['cm'], pc['tk'], pc['chalcm'], pc['chaltk'], pc['s2pubkey'], pc['s1g'], pc['s2h'], )
deployed_address,abi = deploy_contract("ConsistencyProofBN")
#print(f" mul is {prev_contract.functions.mul(pc['s1'], (pc['t1'][0], pc['t1'][1])).call()}")
#(s2gx, s2gy) = prev_contract.functions.mul(2, (gx, gy)).call()
print(pc['s1'])
(s1gx, s1gy) = prev_contract.functions.mul(int(pc['s2'],16), (gx, gy)).call()
#(ns1gx, ns1gy) = prev_contract.functions.neg((s1gx, s1gy)).call()
#(fsx, fsy) = prev_contract.functions.add((s2gx,s2gy),(ns1gx,ns1gy)).call()
#(finx,finy) = prev_contract.functions.add((fsx,fsy),(ns1gx,ns1gy)).call()
(s2hx, s2hy) = prev_contract.functions.mul(25000,(hx,hy)).call()
(s1gs2hx, s1gs2hy) = prev_contract.functions.add((s1gx, s1gy),(s2hx, s2hy)).call()


(ccmx, ccmy) = prev_contract.functions.mul(pc['challenge'], (pc['cm'][0], pc['cm'][1])).call()
(t1ccmx, t1ccmy) = prev_contract.functions.add((pc['t1'][0], pc['t1'][1]), (ccmx, ccmy)).call()

print(t1ccmx)
print(s1gs2hx)






#print(zkbp.add(zkbp.from_str(pc['t1'], zkbp.from_str(pc['t2']))))
#contract = w3.eth.contract(address=deployed_address,abi=abi)
#b = contract.functions.processConsistency(nn).call()
#print(b)
"""
