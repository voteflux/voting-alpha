# import json
# import os
# import logging
# from pathlib import Path
#
import click
#
# from env import get_env
# from hexbytes import HexBytes
# from web3 import Web3
# import eth_utils
# import boto3
# from eth_account import Account
#
# ssm = boto3.client('ssm')
#
# NAME_PREFIX = get_env('NAME_PREFIX', None)
# NONCE = None
#
# groups = ['EX', 'SCALE', 'CORP', 'FELLOW', 'IND', 'STUD']
# multi = ['EX', 'SCALE', 'CORP']
# multi_ = ','.join(multi)
#
# combos = [
#     ['EX', 'SCALE', 'CORP'],
# ]
#
# '''
# We need 1 'Membership' contract per group.
# Additionally, we need
# '''
#
#
# def blank_tx(gas, nonce, bytecode):
#     return {
#         'to': '',
#         'value': 0,
#         'gas': gas,
#         'gasPrice': 1,
#         'nonce': nonce,
#         'data': bytecode
#     }
#
#
# # def mk_tx(w3, acct, )
#
#
# def get_param(name, **kwargs):
#     return ssm.get_parameter(Name=name, **kwargs)['Parameter']['Value']
#
#
# def load_sc(filename):
#     with open(Path(os.path.dirname(__file__)) / 'sc' / filename, 'r') as f:
#         return f.read()


@click.command()
@click.option('--jsonrpc-provider', '-p', help='the ethereum jsonrpc provider')
@click.option('--to', '--to-address', '-t', help='address to send some coins to')
def send_coins(*args, **kwargs):
    pass
    # _send_coins(*args, **kwargs)

#
# def _send_coins(httpProvider, to_address):
#     priv_key = get_param("sv-{}-nodekey-service-{}".format(NAME_PREFIX, "publish"), WithDecryption=True)
#     account = Account.privateKeyToAccount(priv_key)
#     print('Loaded account w/ address:', account.address)
#
#     baseTx = {'from': account.address, 'value': 0, 'gas': 8000000, 'gasPrice': 1}
#
#     w3 = Web3(Web3.HTTPProvider(httpProvider))
#     print('Balance:', w3.eth.getBalance(account.address))
#
#     tx = dict(
#         to=to_address,
#         nonce=w3.eth.getTransactionCount(account.address),
#         **baseTx
#     )
#     tx['value'] = w3.toWei(1, 'ether')
#     txid = w3.eth.sendRawTransaction(account.signTransaction(tx).rawTransaction)
#     print(f'txid: {txid.hex()}')
#     r = w3.eth.waitForTransactionReceipt(txid)
#     assert r['status'] == 1
#     return
