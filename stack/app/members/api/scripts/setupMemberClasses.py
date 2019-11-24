import json
import os
import logging
from pathlib import Path

import click

from env import get_env
from web3 import Web3
import eth_utils
import boto3
from eth_account import Account

ssm = boto3.client('ssm')

NAME_PREFIX = get_env('NAME_PREFIX', None)

groups = ['EX', 'SCALE', 'CORP', 'FELLOW', 'IND', 'STUD']
multi = ['EX', 'SCALE', 'CORP']
multi_ = ','.join(multi)

combos = [
    ['EX', 'SCALE', 'CORP'],
]

'''
We need 1 'Membership' contract per group.
Additionally, we need 
'''


def blank_tx(gas, nonce, bytecode):
    return {
        'to': '',
        'value': 0,
        'gas': gas,
        'gasPrice': 1,
        'nonce': nonce,
        'data': bytecode
    }


# def mk_tx(w3, acct, )


def get_param(name, **kwargs):
    return ssm.get_parameter(Name=name, **kwargs)['Parameter']['Value']


def load_sc(filename):
    with open(Path(os.path.dirname(__file__)) / 'sc' / filename, 'r') as f:
        return f.read()


@click.command()
def setup_member_classes(*args, **kwargs):
    _setup_member_classes(*args, **kwargs)


def _setup_member_classes(httpProvider, erc20_balance_proxy_addr):
    priv_key = get_param("sv-{}-nodekey-service-{}".format(NAME_PREFIX, "publish"), WithDecryption=True)
    account = Account.privateKeyToAccount(priv_key)
    print('Loaded account w/ address:', account.address)

    w3 = Web3(Web3.HTTPProvider(httpProvider))
    print('Balance:', w3.eth.getBalance(account.address))

    membership_bin = load_sc('Membership.bin')
    membership_abi = json.loads(load_sc('Membership.abi'))

    def mk_membership_sc(**kwargs):
        return w3.eth.contract(abi=membership_abi, bytecode=membership_bin, **kwargs)

    membership_bc = mk_membership_sc().constructor().bytecode

    def next_nonce():
        return w3.eth.getTransactionCount(account.address)

    def publish_bc(bc):
        tx = blank_tx(2000000, next_nonce(), membership_bc)
        signed_tx = account.signTransaction(tx)
        txid = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
        w3.eth.waitForTransactionReceipt(txid)
        return w3.eth.getTransactionReceipt(txid)

    def mk_bal_px(**kwargs):
        return w3.eth.contract(abi=json.loads(load_sc('Erc20BalanceProxy.abi')),
                               bytecode=load_sc('Erc20BalanceProxy.bin'), **kwargs)

    def step1():
        bal_px = mk_bal_px()
        bal_px_bc = bal_px.constructor().bytecode

        contracts_addrs = {multi_: publish_bc(bal_px_bc).contractAddress}
        for group in groups:
            contracts_addrs[group] = publish_bc(membership_bc).contractAddress

        print(json.dumps(contracts_addrs, indent=2))
        return contracts_addrs

    _contracts_addrs = step1()
    # _contracts_addrs_old = {
    #     "EX,SCALE,CORP": "0x7ad9737917A35c20eEe733ee1b4e906495954691",
    #     "EX": "0x645ffbbe9fF5B35051FCA578D9E0cafbcD7757AE",
    #     "SCALE": "0x06341257999e17E9259F610816D14d38eb1b17Ac",
    #     "CORP": "0x1a28509a0097e1060c8BE3CbDEF8cb6aE72e0869",
    #     "FELLOW": "0x69E96b9d5914BB1fe941b1d06e353f98052e51Cd",
    #     "IND": "0x6C523F0b17DE2095a87Bbf7FB4dE866173c00C04",
    #     "STUD": "0x5DBf72205F10fb2A02eCfA883de22b1F4531f9c3"
    # }

    def to_bytes32(_str):
        return b'\x00' * (32 - len(_str)) + _str.encode()

    def step2(contracts_addrs):
        contracts = {k: (mk_bal_px if ',' in k else mk_membership_sc)(address=v) for (k, v) in contracts_addrs.items()}

        for c_name, c in contracts.items():
            if ',' in c_name:
                groups = c_name.split(',')
                for g in groups:
                    f = c.functions
                    print(contracts_addrs[g], to_bytes32(g))
                    print(f.addToken(contracts_addrs[g], g).buildTransaction({'from': account.address, 'value': 0}))
                    print(dir(f.addToken(contracts_addrs[g], to_bytes32(g))))
                    # contracts[c_name]
        # print(dir(contracts[multi_].functions))
        # print(dir(contracts['IND'].functions))

    step2(_contracts_addrs)
