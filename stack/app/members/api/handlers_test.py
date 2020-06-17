import json
import logging
from datetime import datetime

from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider
from .handlers import handle_quickchain_upgrade, mk_raw_membership_tx, create_ballot, get_ix_address

log = logging.getLogger(__name__)


def test_shortcut_handler():
    resp = handle_quickchain_upgrade({"body": '{"method": "signup", "payload": { "voterAddr": "0x11" }}'}, {})
    log.info(f"handle_quickchain_upgrade resp: {json.dumps(resp, indent=2)}")


def test_membership_raw():
    w3 = Web3(EthereumTesterProvider())
    a1 = w3.eth.account.from_key("0x0000000000000000000000000000000000000000000000000000000000001100")
    a2 = w3.eth.account.from_key("0x0000000000000000000000000000000000000000000000000000000000002200")
    a3 = w3.eth.account.from_key("0x0000000000000000000000000000000000000000000000000000000000003300")
    tx = mk_raw_membership_tx(w3, a3.address, a1.address, a2.address)
    log.info(f"test_membership_raw got tx: {json.dumps(tx)}")


def test_create_ballot():
    bspec_part1 = bytes(datetime.now().isoformat(), 'ascii')[:32].hex()
    spec_hash = '0x' + '0'*(64 - len(bspec_part1)) + bspec_part1
    log.info(f"test_create_ballot: spec_hash: {spec_hash}")
    create_ballot(spec_hash)


def test_ix_addr():
    get_ix_address()
