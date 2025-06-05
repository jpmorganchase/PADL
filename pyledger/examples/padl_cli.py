import argparse
from eth_account import Account
import os
import sys
from pathlib import Path
import json
import ast

# Adjust path to include project root
path = os.path.realpath(__file__)
parent_dir = str(Path(path).parents[2])
sys.path.append(parent_dir)

from pyledger.extras.evmnet.participant_scripts import (
    create_account, add_participant, deploy_new_contract,
    register_padl, send_injective_tx,
    check_balance, send_coins, add_proof, vote_tx,
    finalize_tx, check_balance_by_state
)

def generate_account():
    acct = Account.create()
    print(f"Address: {acct.address}")
    print(f"Private Key: {acct.key.hex()}")

def get_wallet(file_name):
    with open(file_name, "r") as f:
        data = json.load(f)
        print("Wallet Information:")
        print(f"  Address: {data.get('address')}")
        print(f"  Public Key: {data.get('pk')}")
        print(f"  Private Key: {data.get('sk')}")
        print(f"  Extended SK: {data.get('sk_ext')}")
        print("\nFull JSON Data:")
        print(json.dumps(data, indent=2))

def deploy_contract(private_key, v0=[1000, 1000], types={'0': 'x', '1': 'y'}):
    address = deploy_new_contract(private_key, v0=v0, types=types)
    print(f"Contract deployed at: {address}")
    return address

def add_party(account_address):
    add_participant(account_address, "Issuer 0")

def register(name, contract_address, private_key, address, v0=[0, 0], types={'0': 'x', '1': 'y'}):
    register_padl(
        name=name,
        v0=v0,
        types=types,
        account_dict={'private_key': private_key, 'contract_address': contract_address, 'address': address}
    )
    print(f"Bank '{name}' is registered")

def send_multi(file_name, val):
    tx = send_coins(vals=val, file_name=file_name)
    print(tx)

def send(file_name, val):
    tx = send_injective_tx(vals=val, file_name=file_name)
    print(tx)

def proof(file_name):
    add_proof(file_name)

def finalize(file_name):
    finalize_tx(file_name, Issuer=True)

def balance(name):
    check_balance(name)
    check_balance_by_state(name)

def main():
    parser = argparse.ArgumentParser(description="PADL CLI App")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("generate_account", help="Generate a new Ethereum account")

    deploy_parser = subparsers.add_parser("deploy_contract", help="Deploy new contract")
    deploy_parser.add_argument("private_key", help="Issuer private key")
    deploy_parser.add_argument("--v0", help='v0 vector, e.g. "[1000,1000]"', default="[1000,1000]")
    deploy_parser.add_argument("--types", help='Types dict, e.g. "{\"0\":\"x\",\"1\":\"y\"}"', default='{"0":"x","1":"y"}')

    register_parser = subparsers.add_parser("register", help="Register a new bank")
    register_parser.add_argument("name", help="Bank name")
    register_parser.add_argument("contract_address", help="Deployed contract address")
    register_parser.add_argument("private_key", help="Private key")
    register_parser.add_argument("address", help="Account address")
    register_parser.add_argument("--v0", help='v0 vector, e.g. "[0,0]"', default="[0,0]")
    register_parser.add_argument("--types", help='Types dict, e.g. "{\"0\":\"x\",\"1\":\"y\"}"', default='{"0":"x","1":"y"}')

    add_party_parser = subparsers.add_parser("add_party", help="Add a participant to the contract")
    add_party_parser.add_argument("address", help="Participant Ethereum address")

    tx_parser = subparsers.add_parser("send", help="Send a transaction")
    tx_parser.add_argument("file_name", help="Ledger file name (e.g., 'Issuer 0')")
    tx_parser.add_argument("--val", help='Value matrix, e.g., "[[-2,0,2],[-2,0,2]]"', required=True)

    txm_parser = subparsers.add_parser("send_multi", help="Send multi assets exchange transaction")
    txm_parser.add_argument("file_name", help="Ledger file name (e.g., 'Issuer 0')")
    txm_parser.add_argument("--val", help='Value matrix, e.g., "[[-2,0,2],[-2,0,2]]"', required=True)

    balance_parser = subparsers.add_parser("balance", help="Check bank balance")
    balance_parser.add_argument("name", help="Bank name (e.g., 'Bank 1')")

    wallet_parser = subparsers.add_parser("get_wallet", help="Get wallet information from a file")
    wallet_parser.add_argument("file_name", help="JSON file containing wallet data")

    proof_parser = subparsers.add_parser("proof", help="Send proofs and signature")
    proof_parser.add_argument("file_name", help="JSON file containing wallet data")

    finalize_parser = subparsers.add_parser("finalize", help="Issuer finalizes transaction")
    finalize_parser.add_argument("file_name", help="JSON file containing wallet data")

    args = parser.parse_args()

    if args.command == "generate_account":
        generate_account()
    elif args.command == "deploy_contract":
        v0 = ast.literal_eval(args.v0)
        types = ast.literal_eval(args.types)
        deploy_contract(args.private_key, v0, types)
    elif args.command == "register":
        v0 = ast.literal_eval(args.v0)
        types = ast.literal_eval(args.types)
        register(args.name, args.contract_address, args.private_key, args.address, v0, types)
    elif args.command == "send":
        try:
            val = ast.literal_eval(args.val)
            if not isinstance(val, list) or not all(isinstance(x, list) for x in val):
                raise ValueError
            send(args.file_name, val)
        except Exception:
            print("Invalid --val format. Example: --val \"[[-2,0,2],[-2,0,2]]\"")
    elif args.command == "send_multi":
        try:
            val = ast.literal_eval(args.val)
            if not isinstance(val, list) or not all(isinstance(x, list) for x in val):
                raise ValueError
            send_multi(args.file_name, val)
        except Exception:
            print("Invalid --val format. Example: --val \"[[-2,0,2],[-2,0,2]]\"")
    elif args.command == "balance":
        balance(args.name)
    elif args.command == "proof":
        proof(args.file_name)
    elif args.command == "add_party":
        add_party(args.address)
    elif args.command == "finalize":
        finalize(args.file_name)
    elif args.command == "get_wallet":
        get_wallet(args.file_name)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
