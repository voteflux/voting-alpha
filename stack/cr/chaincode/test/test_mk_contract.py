import json
import sys, os
import time

main_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
one_up_dir = os.path.dirname(main_dir)
sys.path.insert(0, main_dir)
sys.path.insert(0, os.path.join(main_dir, 'deps'))
sys.path.insert(0, os.path.join(one_up_dir, 'common/deps'))
sys.path.insert(0, os.path.join(one_up_dir, 'common'))
print(sys.path)

import binascii
import functools
import logging

from hexbytes import HexBytes

from web3.datastructures import AttributeDict
from web3 import Web3, EthereumTesterProvider
from eth_account import Account
from eth_utils import keccak

import boto3
boto3.setup_default_session(region_name='ap-southeast-2')
from chaincode import mk_contract, is_tx_confirmed

logging.basicConfig(level=logging.INFO)
log = logging.getLogger('TestChaincode')
log.setLevel(logging.DEBUG)


def getTransactionReceipt(txid: bytes):
    addr = "0x" + keccak(txid)[:20].hex()
    return AttributeDict({
        'contractAddress': addr,
        'gasUsed': 8888,
    })


def sendRawTransaction(raw_tx: HexBytes):
    log.debug(f"sendRawTransaction - len: {len(raw_tx)}")
    return (b"txid:" + keccak(raw_tx))[:32]


def getBlock(*args):
    return AttributeDict({
        'gasLimit': 8000000
    })


# w3 = AttributeDict({
#     'eth': AttributeDict({
#         'getTransactionReceipt': getTransactionReceipt,
#         'sendRawTransaction': sendRawTransaction,
#         'getBlock': getBlock,
#         # 'contract':
#     })
# })


from eth_tester import PyEVMBackend, EthereumTester
pyevm_backend = PyEVMBackend(genesis_parameters=PyEVMBackend._generate_genesis_params({'gas_limit': 8000000}))
test_chain = EthereumTester(backend=pyevm_backend)
w3 = Web3(EthereumTesterProvider(ethereum_tester=test_chain))


def mk_deploy(name, inputs=None, libs=None):
    libs = dict() if libs is None else dict(libs)
    inputs = list() if inputs is None else list(inputs)
    return {'Name': name, 'Inputs': inputs, 'Libraries': libs, 'Type': 'deploy'}


def mk_calltx(name, function, inputs=None, value=None):
    ret = {'Name': name, 'Function': function, 'Inputs': inputs if inputs is not None else [], 'Type': 'calltx'}
    if value is not None:
        ret['Value'] = value
    return ret


def mk_call(name, function, inputs=[], ret_types=[]):
    return {'Name': name, 'Function': function, 'Inputs': inputs, 'Type': 'call', 'ReturnTypes': ret_types}


def test_mk_contract():
    name_prefix = "tnalpha"
    acct = Account.privateKeyToAccount("0x" + b"aedufghieuhiughekjudsdfahskljdhf".hex())
    tx_resp = w3.eth.sendTransaction({'to': acct.address, 'from': w3.eth.accounts[0], 'value': 10 * 10 ** 18})
    log.info(f'tx_resp: {tx_resp}')
    log.info(w3.eth.getTransaction(tx_resp))
    w3.personal.importRawKey("0x" + b"aedufghieuhiughekjudsdfahskljdhf".hex(), 'asdf')
    w3.personal.unlockAccount(acct.address, 'asdf')
    chainid = None  # needed for testrpc
    nonce = 0

    smart_contracts_to_deploy = [
        mk_deploy('membership'),
        mk_calltx('membership-add-admin', '$membership.addAdmin', inputs=['_members']),
        mk_deploy('bblib-v7'),
        mk_deploy('bbfarm', libs={"__./contracts/BBLib.v7.sol:BBLibV7______": '$bblib-v7'}),
        mk_deploy('sv-payments', inputs=['^self']),
        mk_deploy('sv-backend'),
        mk_deploy('sv-comm-auction'),
        mk_deploy('sv-index', inputs=['$sv-backend','$sv-payments','^addr-ones','$bbfarm','$sv-comm-auction',]),
        mk_calltx('ix-backend-perms', '$sv-backend.setPermissions', ['$sv-index','bool:true']),
        mk_calltx('ix-payments-perms', '$sv-payments.setPermissions', ['$sv-index','bool:true']),
        mk_calltx('ix-bbfarm-perms', '$bbfarm.setPermissions', ['$sv-index','bool:true']),
        mk_calltx('ix-mk-democ', '$sv-index.dInit', ['$membership', 'bool:true'], value=1),
        mk_call('democ-hash', '$sv-backend.getGDemoc', [ 'uint256:0' ], [ 'bytes32' ]),
        mk_calltx('democ-add-admin', '$sv-index.setDEditor', ['$democ-hash', '_members', 'bool:true']),
        mk_deploy('apg-voting-alpha'),
        mk_calltx('apg-va-init', '$apg-voting-alpha.initVotingAlpha', []),
        mk_calltx('apg-va-self-op', '$apg-voting-alpha.initAddOperator', []),
    ]

    # smart_contracts_to_deploy += smart_contracts_to_deploy

    processed_scs = functools.reduce(mk_contract(name_prefix, w3, acct, chainid, nonce=nonce, dry_run=True),
                                     smart_contracts_to_deploy, dict())

    print(json.dumps({k: repr(op) for k, op in processed_scs.items()}, indent=2))
    return True


if __name__ == "__main__":
    tests = [test_mk_contract]

    for t in tests:
        print(f"{t.__name__}: {t()}")
