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
@click.option('--http-provider', type=click.STRING, required=True)
@click.option('--member-erc20-address', type=click.STRING, required=True)
@click.option('--voter-address', type=click.STRING, required=True)
@click.option('--new-weight', type=click.INT, required=True)
@click.option('--confirm-old-weight', type=click.INT, required=True)
@click.option('--start-time', type=click.INT, required=True, default=0)
@click.option('--end-time', type=click.INT, required=True, default=2000000000)
def set_member_voting_weight(http_provider, member_erc20_address, voter_address, new_weight, confirm_old_weight,
                             start_time, end_time):
    _set_member_voting_weight(http_provider=http_provider, voter_address=voter_address, new_weight=new_weight,
                              confirm_old_weight=confirm_old_weight, member_erc20_address=member_erc20_address,
                              new_start_time=start_time, new_end_time=end_time)


@click.command()
@click.option('--http-provider', type=click.STRING, required=True)
@click.option('--member-erc20-address', type=click.STRING, required=True)
@click.option('--voter-address', type=click.STRING, required=True)
def get_member_voting_weight(http_provider, member_erc20_address, voter_address):
    _get_member_voting_weight(http_provider=http_provider, voter_address=voter_address,
                              member_erc20_address=member_erc20_address)


def _get_member_voting_weight(http_provider, voter_address, member_erc20_address):
    _get_current_state_and_sc_w3_etc(http_provider=http_provider, voter_address=voter_address,
                                     member_erc20_address=member_erc20_address)


def _set_member_voting_weight(http_provider, voter_address, new_weight, confirm_old_weight, member_erc20_address,
                              new_start_time, new_end_time):
    (curr_weight, start_ts, end_ts), w3, sc = \
        _get_current_state_and_sc_w3_etc(http_provider=http_provider, voter_address=voter_address,
                                         member_erc20_address=member_erc20_address)

    if curr_weight != confirm_old_weight:
        raise Exception(
            f"Current weight and conf weight are different: current:{curr_weight} vs provided:{confirm_old_weight}")

    priv_key = get_param("sv-{}-nodekey-service-{}".format(NAME_PREFIX, "publish"), WithDecryption=True)
    account = Account.privateKeyToAccount(priv_key)

    print(f'Calling setMember with args: {[voter_address, new_weight, new_start_time, new_end_time]}')
    tx = sc.functions.setMember(voter_address, new_weight, new_start_time, new_end_time).buildTransaction(
        blank_tx(1000000, w3.eth.getTransactionCount(account.address)))
    signed = account.signTransaction(tx)
    txid = w3.eth.sendRawTransaction(signed.rawTransaction)
    print(w3.toHex(txid))
