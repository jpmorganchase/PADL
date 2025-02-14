# PADL
## Customized & Efficient ZK toolkit for Private and auditable Ledger

PADL is based on zero-knowledge proofs for inter-parties framework for exploring applications for financial institutes. Padl utilises Sigma Protocols and range proofs on homomorphic multi-asset ledger with smart-contracts capability to verify transactions on chain.

## Env for Private Auditable And Distributed Ledger
- Padl includes rust lib 'zkbp' wrapped in python, so can be used directly as a python package for using crypto primitives and proof generations. 
  Rust implementation is highly based on bn254 (Ark-bn254) and secp256k1 from ZenGo-X/curv with bulletproofs, as well as extended ZKP with sigma protocols+range proofs.
- Padl Smart-Contracts developed in solidity based on ECC for deployment on evm network, providing fast proofs verification for multi-assets tx and implementation of padl-private token.


### Env. Prerequests
1. python > 3.8 and Rust.

2. For testing on EVM smart contracts: `nodejs`, and for local evm testing env., for example ganache-cli or geth.

### PADL Installation
3. run `python setup.py init`
See more examples (pyledger/examples), and tutorials under (./tutorials).

## PADL Paper
https://arxiv.org/abs/2501.03808

## License
PADL has a Apache v2-style license, as found in the LICENSE file.


#### This is a Research code only. 

### Applied Research team, JPMorgan & Chase
