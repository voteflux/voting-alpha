import sys, os
main_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, main_dir)
sys.path.insert(0, os.path.join(main_dir, 'deps'))
print(sys.path)

import binascii
import functools
import logging

from hexbytes import HexBytes

from web3.datastructures import AttributeDict
from eth_account import Account
from eth_utils import keccak

from chaincode import mk_contract


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


w3 = AttributeDict({
    'eth': AttributeDict({
        'getTransactionReceipt': getTransactionReceipt,
        'sendRawTransaction': sendRawTransaction,
        'getBlock': getBlock,
    })
})


def mk_deploy(name, inputs=None, libs=None):
    libs = dict() if libs is None else dict(libs)
    inputs = list() if inputs is None else list(inputs)
    return {'Name': name, 'Inputs': inputs, 'Libraries': libs, 'Type': 'deploy'}


def test_mk_contract():
    name_prefix = "test"
    acct = Account.privateKeyToAccount("0x" + b"aedufghieuhiughekjudsdfahskljdhf".hex())
    chainid = 38459863
    nonce = 1

    smart_contracts_to_deploy = [
        mk_deploy('membership'),
        mk_deploy('bblib-v7'),
        mk_deploy('bbfarm', libs={"__./contracts/BBLib.v7.sol:BBLibV7______": '$bblib-v7'})
    ]

    processed_scs = functools.reduce(mk_contract(name_prefix, w3, acct, chainid, nonce=nonce, dry_run=True),
                                     smart_contracts_to_deploy, dict())

    print(processed_scs)
    return True


if __name__ == "__main__":
    tests = [test_mk_contract]

    for t in tests:
        print(f"{t.__name__}: {t()}")