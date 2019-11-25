import json
import os
import logging
from pathlib import Path

import click

from env import get_env
from hexbytes import HexBytes
from web3 import Web3
import eth_utils
import boto3
from eth_account import Account

ssm = boto3.client('ssm')

NAME_PREFIX = get_env('NAME_PREFIX', None)
NONCE = None

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

    baseTx = lambda: {'from': account.address, 'value': 0, 'gas': 8000000, 'gasPrice': 1}

    w3 = Web3(Web3.HTTPProvider(httpProvider))
    print('Balance:', w3.eth.getBalance(account.address))

    membership_bin = load_sc('Membership.bin')
    membership_abi = json.loads(load_sc('Membership.abi'))

    def mk_membership_sc(**kwargs):
        return w3.eth.contract(abi=membership_abi, bytecode=membership_bin, **kwargs)

    membership_bc = mk_membership_sc().constructor().bytecode

    def next_nonce():
        global NONCE
        if NONCE is None:
            NONCE = w3.eth.getTransactionCount(account.address)
        else:
            NONCE += 1
        return NONCE

    def publish_bc(bc):
        tx = blank_tx(8000000, next_nonce(), bc)
        signed_tx = account.signTransaction(tx)
        txid = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
        return txid

    def wait_txid(txid):
        w3.eth.waitForTransactionReceipt(txid)
        receipt = w3.eth.getTransactionReceipt(txid)
        if receipt['status'] == 0:
            raise Exception(f'Tx failed! Status 0. Txid: {txid.hex()}')
        return receipt

    def mk_bal_px(**kwargs):
        return w3.eth.contract(abi=json.loads(load_sc('Erc20BalanceProxy.abi')),
                               bytecode=load_sc('Erc20BalanceProxy.bin'), **kwargs)

    bal_px = mk_bal_px()
    bal_px_bc = bal_px.constructor().bytecode

    def step1():
        contracts_txids = {multi_: publish_bc(bal_px_bc)}

        for group in groups:
            contracts_txids[group] = publish_bc(membership_bc)

        print("TXIDs", contracts_txids)

        contracts_addrs = {}
        for g, txid in contracts_txids.items():
            wait_txid(txid)
            contracts_addrs[g] = w3.eth.getTransactionReceipt(txid).contractAddress
            print("created:", g, contracts_addrs[g])

        return contracts_addrs

    _contracts_addrs = step1()
    # _contracts_addrs = {
    #     "EX,SCALE,CORP": "0xA314d5aE9c6f4F9a8e1969449E33A762bBDfc26B",
    #     "EX": "0xFBa7d684E31D3537433d7D385Ec8A218caf149B8",
    #     "SCALE": "0x74330077C3ca1a3BB7A9ab043F9e40cB6b64E4Ff",
    #     "CORP": "0xE09083ae054E7e8167080F54879da8aa562f71eA",
    #     "FELLOW": "0x0DBEf5F598e39e72c15870Ae872d6b03180e3a46",
    #     "IND": "0x47C6Ce20948512b229ECA90A31dF43B347CF802B",
    #     "STUD": "0x7C7261c54BFeE8368ab0Fddd492bf1FC3c285540"
    # }
    print(json.dumps(_contracts_addrs, indent=4))

    def to_bytes32(_str):
        return b'\x00' * (32 - len(_str)) + _str.encode()

    def step2(contracts_addrs):
        contracts = {k: (mk_bal_px if ',' in k else mk_membership_sc)(address=v) for (k, v) in contracts_addrs.items()}

        for c_name, c in contracts.items():
            if ',' in c_name:
                _groups = c_name.split(',')
                for g in _groups:
                    f = c.functions
                    print(w3.is_encodable('address', contracts_addrs[g]))
                    print(w3.is_encodable('bytes32', to_bytes32(g)))
                    print(contracts_addrs[g], g)
                    tx = f.addToken(_token=contracts_addrs[g], _name=g).buildTransaction(dict(baseTx()))
                    tx.update({'nonce': next_nonce()})
                    txid = w3.eth.sendRawTransaction(account.signTransaction(tx).rawTransaction)
                    receipt = w3.eth.waitForTransactionReceipt(txid)
                    print(receipt['status'])
                    print(f'Added {g} in {w3.toHex(txid)}')

    step2(_contracts_addrs)

    def test_balances():
        my_addr = account.address
        multi_c = mk_bal_px(address=_contracts_addrs[multi_])

        def get_bal():
            return multi_c.functions.balanceOf(account.address).call()

        def assert_bal(expected):
            curr_bal = get_bal()
            if curr_bal != expected:
                raise Exception(f'balances mismatch: current: {curr_bal}, expected: {expected}')

        def get_c(g):
            return mk_membership_sc(address=_contracts_addrs[g])

        def do_tx_f(tx_f):
            tx = tx_f.buildTransaction(dict(baseTx()))
            tx.update({'nonce': next_nonce()})
            txid = w3.eth.sendRawTransaction(account.signTransaction(tx).rawTransaction)
            wait_txid(txid)
            return txid

        def set_bal(g, bal):
            c_f = get_c(g).functions
            return do_tx_f(c_f.setMember(my_addr, bal, 1, 1674629200))

        if get_bal() > 0:
            print('resetting balances')
            set_bal('EX', 0)
            set_bal('CORP', 0)
            set_bal('IND', 0)

        assert_bal(0)
        do_tx_f(get_c('EX').functions.setMember(my_addr, 3, 1474629200, 1674629200))
        assert_bal(3)
        do_tx_f(get_c('CORP').functions.setMember(my_addr, 5, 0, 2000000000))
        assert_bal(8)
        do_tx_f(get_c('IND').functions.setMember(my_addr, 5, 0, 2000000000))
        assert_bal(8)

        print("BALANCES SEEM TO WORK FINE")

    # test_balances()
    #
    # c = mk_bal_px(address=_contracts_addrs[multi_])
    # c2 = mk_membership_sc(address=_contracts_addrs[multi_])
    #
    # print(c.functions.isAdmin(account.address).call())
    # print(c2.functions.isAdmin(account.address).call())
    #
    # try:
    #     print(c2.functions.balanceOf(account.address).call())
    # except:
    #     print('fail')
    #     pass
    #
    # try:
    #     print(c.functions.balanceOf(account.address).call())
    # except:
    #     print('fail')
    #     pass
    #
    # print(c.functions.addToken(account.address, "mine"))
    # addT = c.functions.addToken(account.address, "mine")
    # print(dir(addT))
    # # print(addT.estimateGas())
    # print(addT.buildTransaction({'value': 0, 'gas': 1000000, 'gasPrice': 1}))
    # print()
    # print(addT)
    # print(list([c.functions.tokens(r).call() for r in range(10)]))
    #
    # # at end we do this so it's easy to find.
    #
    # print(json.dumps(_contracts_addrs, indent=4))
