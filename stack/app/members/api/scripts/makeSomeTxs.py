import sys
from time import sleep

import click
import json
import os
from pathlib import Path

from env import get_env
from web3 import Web3
import boto3
from eth_account import Account

ssm = boto3.client('ssm')

NAME_PREFIX = get_env('NAME_PREFIX', None)
NONCE = None


def blank_tx(gas, nonce, bytecode=None):
    tx = {
        'value': 0,
        'gas': gas,
        'gasPrice': 1,
        'nonce': nonce,
    }
    tx.update({} if bytecode is None else {'data': bytecode})
    return tx


def get_param(name, **kwargs):
    return ssm.get_parameter(Name=name, **kwargs)['Parameter']['Value']


def load_sc(filename):
    with open(Path(os.path.dirname(__file__)) / 'sc' / filename, 'r') as f:
        return f.read()


def mk_sc(w3, abi, bin=None, address=None, **kwargs):
    return w3.eth.contract(abi=abi, bytecode=bin, address=address, **kwargs)


def _get_current_state_and_sc_w3_etc(http_provider, voter_address, member_erc20_address):
    assert http_provider is not None

    w3 = Web3(Web3.HTTPProvider(http_provider))
    membership_abi = json.loads(load_sc('Membership.abi'))
    sc = mk_sc(w3=w3, abi=membership_abi, address=member_erc20_address)
    (curr_weight, member_start_ts, member_end_ts) = sc.functions.getMember(voter_address).call()
    print('Current weight, start, and end for member:', curr_weight, member_start_ts, member_end_ts)
    return (curr_weight, member_start_ts, member_end_ts), w3, sc


@click.command()
@click.option('--http-provider')
def make_some_txs(http_provider):
    w3 = Web3(Web3.HTTPProvider(http_provider))
    priv_key = get_param("sv-{}-nodekey-service-{}".format(NAME_PREFIX, "publish"), WithDecryption=True)
    account = Account.privateKeyToAccount(priv_key)

    while True:
        sleep(15)
        tx = blank_tx(100000, w3.eth.getTransactionCount(account.address))
        tx.update({'value': 100000000000000, 'to': account.address})
        signed = account.signTransaction(tx)
        txid = w3.eth.sendRawTransaction(signed.rawTransaction)
        print(f"txid: {txid.hex()}")
