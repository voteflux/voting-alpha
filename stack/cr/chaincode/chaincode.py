import functools
import itertools
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
    _privkey = \
        ssm.get_parameter(Name=gen_ssm_nodekey_service(name_prefix, service_name), WithDecryption=True)['Parameter'][
            'Value']
    return Account.privateKeyToAccount(_privkey)


def get_next_nonce(w3: Web3, acct: LocalAccount):
    addr = acct.address
    nonce = w3.eth.getTransactionCount(addr)
    return nonce


def get_chainid(name_prefix: str) -> str:
    return ssm.get_parameter(Name=gen_ssm_networkid(name_prefix))['Parameter']['Value']


def is_tx_confirmed(w3: Web3, _tx_id) -> bool:
    _tx_r = w3.eth.getTransactionReceipt(_tx_id)
    # return _tx_r is None or _tx_r.blockNumber is None
    return _tx_r is not None


def deploy_contract(w3: Web3, acct: LocalAccount, chainid: int, nonce: int, init_contract: Contract,
                    inputs=dict()) -> Contract:
    c_out = Contract.from_contract(init_contract)

    if ssm_param_exists(c_out.ssm_param_name):
        c_out.set_addr(get_ssm_param_no_enc(c_out.ssm_param_name))

    else:
        max_gas = w3.eth.getBlock('latest').gasLimit * 0.9 // 1
        signed_tx = acct.signTransaction({
            'to': '',
            'value': 0,
            'gas': max_gas,
            'gasPrice': 1,
            'nonce': nonce,
            'chainId': chainid,
            'data': c_out.bytecode
        })

        MAX_SEC = 120
        with Timer(f"Send+Confirm contract: {c_out.name}") as t:
            tx_id = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
            while not is_tx_confirmed(w3, tx_id) and t.curr_interval < MAX_SEC:
                time.sleep(0.05)

        tx_r = w3.eth.getTransactionReceipt(tx_id)
        if tx_r is None:
            raise Exception(f"Contract took longer than {MAX_SEC}s to confirm!")

        c_out.set_addr(tx_r.contractAddress)
        c_out.set_gas_used(tx_r.gasUsed)

        put_param_no_enc(c_out.ssm_param_name, c_out.addr, description=f"Address for contract {c_out.name}")
    return c_out


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


def get_bytecode(filepath):
    with open(filepath, 'r') as f:
        bc = f.read()
    if bc[:2] != '0x':
        bc = '0x' + bc
    return bc


def process_inputs(prev_outs, inputs, func_name=None, libs=dict()):
    '''Constructs an ABI on the fly based on Value,Type of inputs, resolves variables (e.g. SC addrs) which need to be,
     and returns encoded+packed arguments as a hex string with no 0x prefix. Also resolves/adds libraries if need be.'''
    if len(libs) > 0:
        # stuff here
        pass
    return ''


def mk_contract(name_prefix, w3, acct, chainid, nonce):
    def do_fold(prev_outputs, next):
        nonlocal nonce
        ret = dict(prev_outputs)
        entry_name = next['Name']
        inputs = next.get('Inputs', [])
        libs = next.get('Libraries', {})

        # TODO: implement the SC deploy pattern
        if next['Type'] == 'local':
            # local deploy
            bc = get_bytecode(f"{entry_name}.bytecode")
            extra_bc = process_inputs(prev_outputs, inputs, libs=libs)
            c_done = deploy_contract(w3, acct, chainid, nonce,
                                     Contract(entry_name, bc + extra_bc, gen_ssm_sc_addr(name_prefix, entry_name)))
            nonce += 1
            ret[entry_name] = c_done
        elif next['Type'] == 'remote':
            raise Exception('remote deploys not yet supported')
        else:
            raise Exception(f'SC Deploy/Call type {next["Type"]} is not recognised as a valid type of operation.')

        return ret

    return do_fold


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

        bc_membership = get_bytecode('membership.bytecode')

        if len(set([c['Name'] for c in smart_contracts_to_deploy])) != len(smart_contracts_to_deploy):
            raise Exception("All 'Name' params must be unique in SC deploy plans")

        processed_scs = functools.reduce(mk_contract(name_prefix, w3, acct, chainid, nonce=get_next_nonce(w3, acct)),
                                       smart_contracts_to_deploy, dict())

        # deployed_contracts = deploy_many_contracts(w3, acct, [
        #     Contract(SC_MEMBERSHIP, bc_membership, gen_ssm_sc_addr(name_prefix, SC_MEMBERSHIP)),
        #     # Contract('')
        # ], chainid)

        data = {f"{c.name.title()}Addr": c.addr for c in deployed_contracts}

        return CrResponse(CfnStatus.SUCCESS, data=data, physical_id=physical_id)

    if event['RequestType'] == 'Create':
        return do_idempotent_deploys()
    elif event['RequestType'] == 'Update':
        return do_idempotent_deploys()
    else:
        return CrResponse(CfnStatus.SUCCESS, data={}, physical_id=physical_id)
