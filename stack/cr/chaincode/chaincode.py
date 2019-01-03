import time

from cfnwrapper import *

from web3 import Web3
from eth_account import Account
from eth_account.signers.local import LocalAccount
import boto3
from typing import List

from lib import gen_ssm_nodekey_service, SVC_CHAINCODE, gen_ssm_networkid, gen_ssm_sc_addr, \
    get_ssm_param_no_enc, get_ssm_param_with_enc, put_param_no_enc, put_param_with_enc, ssm_param_exists, \
    Timer

ssm = boto3.client('ssm')


class Contract:
    def __init__(self, name, bytecode, ssm_param_name, addr=None, gas_used=None):
        self.name = name
        self.bytecode = bytecode
        self.ssm_param_name = ssm_param_name
        self.addr = addr
        self.gas_used = gas_used

    def init_args(self):
        # matches function signature of __init__
        return [self.name, self.bytecode, self.ssm_param_name, self.addr, self.gas_used]

    def set_addr(self, addr):
        self.addr = addr

    def set_gas_used(self, gas_used):
        self.gas_used = gas_used

    @classmethod
    def from_contract(cls, contract):
        return cls(*contract.init_args())


def load_privkey(name_prefix: str, service_name: str) -> LocalAccount:
    _privkey = ssm.get_parameter(Name=gen_ssm_nodekey_service(name_prefix, service_name), WithDecryption=True)['Parameter']['Value']
    return Account.privateKeyToAccount(_privkey)


def get_next_nonce(w3: Web3, acct: LocalAccount):
    addr = acct.address
    nonce = w3.eth.getTransactionCount(addr)
    return nonce


def get_chainid(name_prefix: str) -> str:
    return ssm.get_parameter(Name=gen_ssm_networkid(name_prefix))['Parameter']['Value']


def deploy_many_contracts(w3: Web3, acct: LocalAccount, orig_contracts: List[Contract], chainid: int) -> List[Contract]:
    nonce = get_next_nonce(w3, acct)

    def not_confirmed(_tx_id) -> bool:
        _tx_r = w3.eth.getTransactionReceipt(_tx_id)
        # return _tx_r is None or _tx_r.blockNumber is None
        return _tx_r is None

    new_contracts = list([Contract.from_contract(c) for c in orig_contracts])

    for contract in new_contracts:
        if ssm_param_exists(contract.ssm_param_name):
            contract.set_addr(get_ssm_param_no_enc(contract.ssm_param_name))
            continue

        signed_tx = acct.signTransaction({
            'to': '',
            'value': 0,
            'gas': 4000000,
            'gasPrice': 1,
            'nonce': nonce,
            'chainId': chainid,
            'data': contract.bytecode
        })
        nonce += 1

        with Timer(f"Send+Confirm contract: {contract.name}") as t:
            tx_id = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
            while not_confirmed(tx_id):
                time.sleep(0.05)

        tx_r = w3.eth.getTransactionReceipt(tx_id)
        contract.set_addr(tx_r.contractAddress)
        contract.set_gas_used(tx_r.gasUsed)

        put_param_no_enc(contract.ssm_param_name, contract.addr, description=f"Address for contract {contract.name}")

    return new_contracts


SC_MEMBERSHIP = 'membership'


@wrap_handler
def chaincode_handler(event, ctx, **params):
    name_prefix = params['pNamePrefix']
    # hosted_zone_domain = params['pDomain'].rstrip('.')
    # subdomain = params['pSubdomain']
    public_node_domain = params['pPublicNodeDomain'].rstrip('.')
    physical_id = f"sv-{name_prefix}-chaincode-2-cr"

    smart_contracts_to_deploy = params.get('pSmartContracts', [])
    logging.info(f"Smart Contracts: {smart_contracts_to_deploy}")

    def do_idempotent_deploys():
        acct = load_privkey(name_prefix, SVC_CHAINCODE)
        # w3 = Web3(Web3.WebsocketProvider(f"ws://public-node-0.{subdomain}.{hosted_zone_domain}:8546"))
        w3 = Web3(Web3.WebsocketProvider(f"ws://{public_node_domain}:8546"))
        chainid = int(get_chainid(name_prefix))

        with open('membership.bytecode', 'r') as f:
            bc_membership = f.read()

        # prepped_scs = list([mk_contract(c) for c in smart_contracts_to_deploy])

        # deployed_contracts = deploy_many_contracts(w3, acct, prepped_scs, chainid)

        deployed_contracts = deploy_many_contracts(w3, acct, [
            Contract(SC_MEMBERSHIP, bc_membership, gen_ssm_sc_addr(name_prefix, SC_MEMBERSHIP)),
            # Contract('')
        ], chainid)

        data = {f"{c.name.title()}Addr": c.addr for c in deployed_contracts}

        return CrResponse(CfnStatus.SUCCESS, data=data, physical_id=physical_id)

    if event['RequestType'] == 'Create':
        return do_idempotent_deploys()
    elif event['RequestType'] == 'Update':
        return do_idempotent_deploys()
    else:
        return CrResponse(CfnStatus.SUCCESS, data={}, physical_id=physical_id)




