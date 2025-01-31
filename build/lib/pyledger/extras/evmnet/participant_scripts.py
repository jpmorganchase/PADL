"""Interface to call PADL functions on EVM.
GTAR - London - JPMorgan Chase """
import zkbp
from pyledger.extras.evmnet.contractpadl import PadlEVM
from pyledger.zkutils import r_blend, Commit, Secp256k1, curve_util, BNCurve
from pyledger.extras import utils
import os
import logging
from pathlib import Path
from web3 import Web3
path = os.path.realpath(__file__)
parent_dir = str(Path(path).parents[3])
from pyledger.create_tx import InjectiveTxSmartContract, ERCTx
from pyledger.Proof_Generation import ProofGenerator

CONTRACT_FILE="PADLOnChainBN"
BITS = 64
MAX = int(2 ** (BITS / 4))

def create_account(contract_address):
    add, key, pubkey = PadlEVM.create_account(contract_address)
    print(f"new account created with address {add}")
    account_dict ={"address":add,"private_key": key, "public_key": pubkey,"contract_address": contract_address}
    return account_dict

def register_padl(name: str, account_dict: object, v0=[0,0],
                  types={'0': 'x', '1': 'y'},
                  retreive_v0 = None,
                  audit_pk=None,
                  audit_account={},
                  contract_tx_name=CONTRACT_FILE,
                  ) -> object:
    file_name_contract=CONTRACT_FILE+".sol"
    bank_gkp =PadlEVM(secret_key=account_dict['private_key'],
                               contract_address=account_dict['contract_address'],
                               contract_tx_name=contract_tx_name,
                               file_name_contract= file_name_contract)
    if retreive_v0 == True:
        retreive_v0=bank_gkp.retrieve_zero_line(bank_gkp.account_address)
    elif isinstance(retreive_v0, list):
        print("re-assigning initial_cells")
    bank = bank_gkp.register_new_bank(name=name, v0=v0, types=types,
                                    secret_key=account_dict['private_key'],
                                    address=account_dict['address'],
                                    contract_address=account_dict['contract_address'],
                                    serialise=True,
                                    initial_asset_cell=retreive_v0,
                                    contract_tx_name=contract_tx_name,
                                    file_name_contract=file_name_contract,
                                    audit_pk=audit_pk,
                                    audit_account=audit_account)
    return bank

def register_padl_onchain(name, account_dict, v0=[1000], types={'0':'x'},retreive_v0: object = False, audit_pk=None, audit_account={} ):
    print(f'Registering new participant')
    ledger = PadlEVM(secret_key=account_dict['private_key'], contract_address=account_dict['contract_address'])
    if retreive_v0:
        retreive_v0 = ledger.retrieve_zero_line(ledger.account_address)
    else:
        retreive_v0=None
    bank = ledger.register_new_bank(name=name, v0=v0, types=types,
                                  secret_key=account_dict['private_key'],
                                  address=account_dict['address'],
                                  contract_address=account_dict['contract_address'],
                                  serialise=True,
                                  initial_asset_cell=retreive_v0,
                                  audit_pk=audit_pk, tx_obj = InjectiveTxSmartContract(), audit_account=audit_account)
    print('Participant registered')
    return bank

def bank_send_deposit(account_dict, amount=10):
    w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
    bal = w3.fromWei(w3.eth.get_balance(account_dict['address']),'ether')
    add  = account_dict['address']
    print(f'Eth balance for address {add} is {bal}')
    print('Sending deposit')

    transaction = {
        'chainId': 1337,
        "from": account_dict['address'],
        "to": account_dict['contract_address'],
        "value": w3.toWei(amount,'ether'),
        "nonce": w3.eth.get_transaction_count(account_dict['address']),
        "gasPrice":w3.toWei(1,'gwei'),
        "gas": 20000000
    }
    signed = w3.eth.account.sign_transaction(transaction,account_dict['private_key'])
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    bal = w3.fromWei(w3.eth.get_balance(account_dict['address']),'ether')
    print(f'Deposit sent')
    print(f'Eth balance for address {add} is {bal}')

    print('checking contract Eth balance')
    cadd = account_dict['contract_address']
    cbal = w3.fromWei(w3.eth.get_balance(account_dict['contract_address']), 'ether')
    print(f'Contract Eth balance at address {cadd} is {cbal}')

def request_token_commit(file_name, address, pk, deposit_v0, v0, contract_tx_name=CONTRACT_FILE, file_name_contract=CONTRACT_FILE+".sol"):
    ledger, bank = get_ledger_bank_padl(file_name)
    initial_cell = ledger.create_initial_cell_from_asset_vals(v0, pk)
    ledger.upload_commit_token_request(address, initial_cell, deposit_v0)

def deploy_new_contract(secret_key, name='Issuer', v0=[1000,1000], types={'0':'x','1':'y'}, contract_tx_name=CONTRACT_FILE, file_name_contract=CONTRACT_FILE+".sol"):
    """
    The deployment of a new default padl contract
    also generates the bank wallet which is going to be the Issuer 0
    Args:
        secret_key: string, the secret key for padl
        name: string, padl local wallet name
        v0:  list of ints, asset values list
        types: dict, asset index map to types
        contract_tx_name: default is PADLOnChainBN
        file_name_contract:  PADLOnChainBN.sol
    Returns:
            contract address
    """
    ledger = PadlEVM(secret_key=secret_key, redeploy=True, contract_tx_name=contract_tx_name, file_name_contract=file_name_contract)
    ledger.add_participant_to_contract(ledger.account_address)

    bank = ledger.register_new_bank(name=name, v0=v0, types=types,
                                    secret_key=secret_key,
                                    address=ledger.account_address,
                                    contract_address=ledger.deployed_address,
                                    contract_tx_name=contract_tx_name,
                                    file_name_contract=file_name_contract)
    logging.info(f"new contract deployed for participant: {bank.name}")
    return ledger.deployed_address



def deploy_bond_contract(issuer_name: str, issuer_private_key: str, initial_v: 
                         list=[1000,1000], types: dict={'0':'x','1':'y'}):
    """
    initial_v : list of initial assets value
    types : Dict.   asset type map
    """
    ledger = PadlEVM(secret_key=issuer_private_key, v0=initial_v[0], redeploy=True) # deploy the padl contract on evm, and also create padl ledger object
    ledger.add_participant_to_contract(ledger.account_address)

    bank = ledger.register_new_bank(name=issuer_name, v0=initial_v, types=types,
                                    secret_key=issuer_private_key,
                                    address=ledger.account_address,
                                    contract_address=ledger.deployed_address)
    logging.info(f"new contract deployed for participant: {bank.name}")
    return bank

def deploy_PADLOnChain(secret_key, name='Issuer', v0=[1000], types={'0':'x'},contract_tx_name=CONTRACT_FILE, file_name_contract=CONTRACT_FILE+".sol", redeploy=True):
    print("deploy")
    ledger = PadlEVM(secret_key=secret_key, v0=v0[0], contract_tx_name=contract_tx_name, file_name_contract=file_name_contract, redeploy=redeploy)
    print("created ledger")
    ledger.add_participant_to_contract(ledger.account_address)
    print("added participant to ledger")
    bank = ledger.register_new_bank(name=name, v0=v0, types=types,
                                    secret_key=secret_key,
                                    address=ledger.account_address,
                                    contract_address=ledger.deployed_address,
                                    contract_tx_name = contract_tx_name,
                                    file_name_contract = file_name_contract)
    return ledger,bank

def add_participant(add, name="Issuer 0"):
    logging.info("adding participant")
    issuer, issuer_bank = get_ledger_bank_padl(name)
    issuer.add_participant_to_contract(add)
    issuer.send_inital_gas(add=add)

def add_participant_to_contract(add, pk, v0, name="Issuer 0", contract_tx_name="StorePermissionsAndTxns", file_name_contract="StorePermissionsAndTxns.sol"):
    logging.info("adding participant")
    issuer, issuer_bank = get_ledger_bank_padl(name, contract_tx_name, file_name_contract)
    issuer.add_participant_to_contract_pk(add, pk, v0)
    issuer.send_inital_gas(add=add)

def check_supply(file_name):
    bank = utils.load_bank_from_file(file_name)
    ledger = PadlEVM(secret_key=bank.sk, contract_address=bank.contract_address)
    return ledger.retrieve_total_supply()

def check_balance(file_name):
    bank = utils.load_bank_from_file(file_name)
    ledger = PadlEVM(secret_key=bank.sk_ext, contract_address=bank.contract_address,contract_tx_name=bank.contract_tx_name,file_name_contract=bank.file_name_contract)

    id = bank.id
    bals=[]
    all_txs, _ = ledger.retrieve_all_txs()

    zls = ledger.retrieve_zero_line(ledger.account_address)
    print("-------",bank.name, bank.id,"-------")
    for ai in range(bank.nassets):
        c,t = ledger.sum_cms_tks(id, ai, all_txs, zls)
        bal = zkbp.get_brut_v(c,t,ledger.gh, bank.sk_pk_obj, MAX)
        print(bank.asset_secret_map[str(ai)], bal)
        bals.append(bal)
    print("-----------------------")
    return bals

def get_state(file_name, v0=None, audit_pk=None):
    bank = utils.load_bank_from_file(file_name)
    ledger = PadlEVM(secret_key=bank.sk, contract_address=bank.contract_address)
    id = bank.id
    if v0:
        init_cell = ledger.create_initial_cell_from_asset_vals(v0, bank.pk, audit_pk)

        return init_cell
    all_txs, _ = ledger.retrieve_all_txs()
    zls = ledger.retrieve_zero_line(ledger.account_address)
    state = []
    for ai in range(bank.nassets):
        c,t = ledger.sum_cms_tks(id, ai, all_txs, zls)
        state.append(ledger.Cell(cm=c.get, token=t.get))
    return state

def check_balance_by_state(file_name):
    ledger, bank = get_ledger_bank_padl(file_name)
    id = ledger.pub_keys.index(bank.pk)
    states = ledger.retrieve_state(id)
    print(f" PADL Balance for {file_name} ")
    for a in range(len(states)):
        c,t = states[a]
        c = zkbp.from_str(curve_util.get_compressed_ecpoint(c[0],c[1]))
        t = zkbp.to_token_from_str(curve_util.get_compressed_ecpoint(t[0],t[1]))
        bal = zkbp.get_brut_v(c,t,ledger.gh, bank.sk_pk_obj, MAX)
        print(bank.asset_secret_map[str(a)],bal)
        
        g_to_sval = zkbp.g_to_x(ledger.gh, bal)
        h_sum_r = zkbp.sub(c, g_to_sval)
        pr = zkbp.sigma_dlog_proof_explicit_sha256_with_witness(t, bank.sk_pk_obj, h_sum_r)
    return bal,pr

def cashout_padl_onchain(file_name, contract_tx_name, file_name_contract):
    print(f" Processing {file_name} cashout request.  Verifying balance")
    bal, pr = check_balance_by_state(file_name, contract_tx_name, file_name_contract)
    ledger,bank = get_ledger_bank_padl(file_name, contract_tx_name=CONTRACT_FILE, file_name_contract=CONTRACT_FILE+".sol")
    ledger.cashout_padl_onchain(bal, bank.id, pr)
    bal = ledger.w3.fromWei(ledger.w3.eth.get_balance(bank.address[:-5]),'ether')
    print(f"Eth bal for {file_name} at address{bank.address[:-5]} is {bal}")

def check_balance_tx(file_name, tx):
    bank = utils.load_bank_from_file(file_name)
    ledger = PadlEVM(secret_key=bank.sk, contract_address=bank.contract_address)
    print(ledger.to_json(tx))
    id = ledger.pub_keys.index(bank.pk)
    bals=[]
    print("-------",bank.name, bank.id," my tx values-------")
    for ai in range(bank.nassets):
        bal = zkbp.get_brut_v(zkbp.from_str(tx[ai][id].cm),zkbp.to_token_from_str(tx[ai][id].token),ledger.gh, bank.sk_pk_obj, MAX)
        print(bank.asset_secret_map[str(ai)], bal)
        bals.append(bal)
    print("-----------------------")
    return bals


def check_balance_by_commit_token(file_name, c, t):
    bank = utils.load_bank_from_file(file_name)
    gh = zkbp.gen_GH()
    cc = zkbp.from_str(BNCurve.get_compressed_ecpoint(c[0], c[1]))
    tc = zkbp.to_token_from_str(BNCurve.get_compressed_ecpoint(t[0], t[1]))
    bal = zkbp.get_brut_v(cc,tc, gh, bank.sk_pk_obj, MAX)
    print(f"balance is {bal}")
    return bal

def check_all_balances_audit(file_name, ids=None, assets=None, check_match=None, single_index = -1, rangetx=-1):
    bank = utils.load_bank_from_file(file_name)
    ledger = PadlEVM(secret_key=bank.sk, contract_address=bank.contract_address, contract_tx_name=bank.contract_tx_name, file_name_contract=bank.file_name_contract)
    zls = ledger.get_all_zerolines()

    bals = []

    ledger.pull_txs()
    all_txs = ledger.txs
    if rangetx==-1:
        rangetx=len(all_txs)
    print("len of tx:",len(all_txs))
    bals=[]
    if ids is None:
        ids = range(0,len(ledger.pub_keys))
    for id in ids:
        if id == bank.id: continue
        zl=zls[id]
        
        if assets is None:
            assets = range(0, len(zl))
        for ai in assets:
            try:
                if single_index > -1:
                    print(single_index)
                    print(ai)
                    print(id)
                    c = zkbp.from_str(all_txs[single_index][ai][id].cm)
                    t = zkbp.to_token_from_str(all_txs[single_index][ai][id].meta_data['audit'])
                    for i in range(single_index+1,len(all_txs)):
                        c = zkbp.add(c, zkbp.from_str(all_txs[i][ai][id].cm))
                        t = zkbp.add_token(t, zkbp.to_token_from_str(all_txs[i][ai][id].meta_data['audit']))
                else:
                    c,t = ledger.sum_cms_tks_audit_pk(id, ai, all_txs[0:rangetx], zl)

            except KeyError:
                logging.warning("no asset audit-key for id: {0} and asset {1}".format(id, ai))
                continue
            print("party id:", id,', Encrypted values: ',(c.get,t.get))
            bal = zkbp.get_brut_v(c,t,ledger.gh, bank.sk_pk_obj, MAX)
            print(bank.asset_secret_map[str(ai)], bal)
            if check_match and  (check_match[ai]!=bal):
               logging.warning('doesnt match expected asset index '+str(ai)+ 'in: ' + str(check_match))

            bals.append(bal)
        print("-----------------------")
    return bals

def get_ledger_bank_padl(file_name):
    bank = utils.load_bank_from_file(file_name)
    ledger = PadlEVM(secret_key=bank.sk_ext,
                        contract_address=bank.contract_address,
                        contract_tx_name=bank.contract_tx_name,
                        file_name_contract=bank.file_name_contract,
                        redeploy=False)
    return ledger, bank


def send_coins(vals: list, file_name: str, audit_pk=None, sparse_tx=False, contract_tx_name=CONTRACT_FILE, file_name_contract=CONTRACT_FILE+".sol"):
    """
    To send coins to another participant, first we source the padl ledger,
    then we pull the transactions from the ledger. 
    """
    ledger, bank = get_ledger_bank_padl(file_name)
    ledger.pull_txs()
    tx = bank.create_asset_tx(vals_in=vals, n_banks=len(ledger.pub_keys), pub_keys=ledger.pub_keys, audit_pk=audit_pk, sparse_tx=sparse_tx)

    pre_n_itx = ledger.transform_tx_int(tx)
    ledger.add_int_commits_tokens(pre_n_itx)

    proof_hash = ledger.store_proofs_gkp(tx)
    print(proof_hash)
    
    ledger.add_commits_tokens(tx, proof_hash)
    bank.serialise()
    return tx

def send_injective_tx(vals:list, file_name: str, audit_pk=None):
    print(f"Preparing transaction")
    ledger, bank = get_ledger_bank_padl(file_name)

    bank.set_tx_type(InjectiveTxSmartContract())
    tx_solidity,tx = bank.create_asset_tx(vals=vals, ledger=ledger, pub_keys=ledger.pub_keys,audit_pk=audit_pk)
    
    proof_hash = ledger.store_proofs_gkp(tx)
    nonce = ledger.w3.eth.get_transaction_count(ledger.account_address)
    fn_call = ledger.testnet_dict['contract_obj'].functions.addstorageidentifier(proof_hash).buildTransaction({"chainId":ledger.chain, "from":ledger.account_address, "nonce":nonce, "gas":2000000})
    tx_receipt = ledger.send_txn_from_fn_call(fn_call)
    for a, txa in enumerate(tx_solidity):
        print("sending transaction")
        ledger.send_injective_txn_padlonchain(txa,asset_id=a)

    return tx_solidity, tx

def get_private_tx_str(pub_keys, vals, file_name, state, old_balance, audit_pk=None):
    ledger, bank = get_ledger_bank_padl(file_name)
    ledger.pub_keys = pub_keys
    bank.set_tx_type(ERCTx())
    tx = bank.create_asset_tx(vals, ledger, state, old_balance)
    """
    New function to write to create injective tx; 
    Only two cells: 
    cell a: [[cm, tk, PoA, PoC], [cm, tk, PoPC, PoC]]
    """
    return tx

def finalize_tx(file_name, contract_tx_name=CONTRACT_FILE, file_name_contract=CONTRACT_FILE+".sol", Issuer=False):
    ledger, bank = get_ledger_bank_padl(file_name)
    ledger.pull_txs()

    cmtk, tx, _ = ledger.retrieve_current_tx()

    for i in range(len(tx[0])):
        ledger.get_state_id(i) 

    ledger.audit_tx(tx)

    if Issuer:  # currently issuer address can add tx in smart contract, otherwise needs majority voting.
        ledger.add_txn_to_ledger_issuer()
    else:
        ledger.add_txn_to_ledger()

def vote_tx(file_name):
    ledger, bank = get_ledger_bank_padl(file_name)
    ledger.pull_txs()
    cmtk, tx, _ = ledger.retrieve_current_tx()
    ledger.voteTxn()

def add_proof(file_name):
    print("add proof", file_name)
    ledger, bank = get_ledger_bank_padl(file_name)
    ledger.pull_txs()
    # retrieve txn
    cmtk, tx, filename = ledger.retrieve_current_tx()
    # add proof
    ledger.get_state_id(bank.id)
    bank.approve_tx(tx, ledger)
    bank.serialise()
    ledger.store_proofs_gkp(tx, filename)
    return tx

