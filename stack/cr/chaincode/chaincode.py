import functools
import itertools
import time
import logging

from cfnwrapper import *

from eth_utils import remove_0x_prefix
from toolz.functoolz import curry, pipe
from web3 import Web3
from eth_account import Account
from eth_account.signers.local import LocalAccount
import boto3
from typing import List, Dict, Iterable, Callable, Union, TypeVar

from lib import gen_ssm_nodekey_service, SVC_CHAINCODE, gen_ssm_networkid, gen_ssm_sc_addr, \
    get_ssm_param_no_enc, get_ssm_param_with_enc, put_param_no_enc, put_param_with_enc, ssm_param_exists, \
    Timer, update_dict

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("chaincode")
log.setLevel(logging.INFO)
log.info("Chaincode logger initialized.")

ssm = boto3.client('ssm')


Acc = TypeVar('Acc')
T = TypeVar('T')


class ResolveVarValError(Exception):
    pass


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

    def __str__(self):
        return f"<Contract({self.name}): [Addr:{self.addr}]>"
        # return f"<Contract({self.name}): [Addr:{self.addr}, BytecodeLen:{len(self.bytecode)}, SSMParamName:{self.ssm_param_name}]>"

    def __repr__(self):
        return f"<Contract({self.name}): [Addr:{self.addr},BC(len):{len(self.bytecode)}]>"


def reduce(func: Callable[[Acc, T], Acc], xs: Iterable[T], init: Acc) -> Acc:
    return functools.reduce(func, xs, init)


def load_privkey(name_prefix: str, service_name: str) -> LocalAccount:
    ssm_name = gen_ssm_nodekey_service(name_prefix, service_name)
    _privkey = ssm.get_parameter(Name=ssm_name, WithDecryption=True)['Parameter']['Value']
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
                    inputs=dict(), dry_run=False) -> Contract:
    log.info(f"[deploy_contract]: processing {init_contract.name}")
    c_out = Contract.from_contract(init_contract)

    if not dry_run and ssm_param_exists(c_out.ssm_param_name):
        c_out.set_addr(get_ssm_param_no_enc(c_out.ssm_param_name))
        log.info(f"[deploy_contract] Found cached address for {c_out.name}: {c_out.addr}")

    else:
        max_gas = int(w3.eth.getBlock('latest').gasLimit * 0.9 // 1)
        unsigned_tx = {
            'to': '',
            'value': 0,
            'gas': max_gas,
            'gasPrice': 1,
            'nonce': nonce,
            'chainId': chainid,
            'data': c_out.bytecode
        }
        # log.info(f"Signing transaction: {update_dict(dict(unsigned_tx), {'data': f'<Data, len: {len(c_out.bytecode)}>'})}")
        signed_tx = acct.signTransaction(unsigned_tx)

        MAX_SEC = 120
        with Timer(f"Send+Confirm contract: {c_out.name}") as t:
            tx_id = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
            log.info(f"Sent transaction; txid: {tx_id.hex()}")
            while not is_tx_confirmed(w3, tx_id) and t.curr_interval < MAX_SEC:
                time.sleep(0.05)

        tx_r = w3.eth.getTransactionReceipt(tx_id)
        if tx_r is None:
            raise Exception(f"Contract took longer than {MAX_SEC}s to confirm!")

        c_out.set_addr(tx_r.contractAddress)
        c_out.set_gas_used(tx_r.gasUsed)

        put_param_no_enc(c_out.ssm_param_name, c_out.addr, description=f"Address for contract {c_out.name}",
                         dry_run=dry_run)
    return c_out


def get_bytecode(filepath) -> str:
    log.info(f"[get_bytecode] Opening bytecode from: {os.path.realpath(filepath)}")
    with open(filepath, 'r') as f:
        bc = f.read()
    log.info(f"[get_bytecode] BC len: {len(bc)}")
    if bc[:2] != '0x':
        bc = '0x' + bc
    return bc


def resolve_var_val(prev_outs: Dict[str, Contract], var_val):
    try:
        if var_val[0] == '$':  # SC addr
            return prev_outs[var_val[1:]].addr
        return var_val
    except Exception as e:
        raise ResolveVarValError(f"Unknown error occured: {repr(e)}")


def process_bytecode(raw_bc: str, prev_outs, inputs, func_name=None, libs=dict()):
    '''Constructs an ABI on the fly based on Value,Type of inputs, resolves variables (e.g. SC addrs) which need to be,
     and returns encoded+packed arguments as a hex string with no 0x prefix. Also resolves/adds libraries if need be.'''

    def sub_libs(_bc, libtuple):
        lib_hole, var_val = libtuple
        val = resolve_var_val(prev_outs, var_val)
        return _bc.replace(lib_hole, remove_0x_prefix(val))

    def do_inputs(_bc):
        '''Take inputs and process/pack them and add to end of bytecode.'''
        return _bc

    do_libs = curry(reduce)(sub_libs)(libs.items())

    return pipe(raw_bc,
                do_libs,
                do_inputs
                )


def mk_contract(name_prefix, w3, acct, chainid, nonce, dry_run=False):
    def do_fold(prev_outputs, next):
        nonlocal nonce
        ret = dict(prev_outputs)
        entry_name = next['Name']
        inputs = next.get('Inputs', [])
        libs = next.get('Libraries', {})

        if next['Type'] == 'deploy':
            if 'URL' in next:
                # remote
                raise Exception('remote deploys not yet supported')
            else:
                # local deploy
                raw_bc = get_bytecode(f"{entry_name}.bytecode")
            bc = process_bytecode(raw_bc, prev_outputs, inputs, libs=libs)
            log.info(f"Processed bytecode for {entry_name}; lengths: raw({len(raw_bc)}), processed({len(bc)})")
            c_done = deploy_contract(w3, acct, chainid, nonce,
                                     Contract(entry_name, bc, gen_ssm_sc_addr(name_prefix, entry_name)),
                                     dry_run=dry_run)
            nonce += 1
            ret[entry_name] = c_done
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
        log.info(f'')

        chainid = int(get_chainid(name_prefix))

        if len(set([c['Name'] for c in smart_contracts_to_deploy])) != len(smart_contracts_to_deploy):
            raise Exception("All 'Name' params must be unique in SC deploy plans")

        processed_scs = functools.reduce(mk_contract(name_prefix, w3, acct, chainid, nonce=get_next_nonce(w3, acct)),
                                         smart_contracts_to_deploy, dict())

        data = {f"{c.name.title()}Addr": c.addr for c in processed_scs}

        return CrResponse(CfnStatus.SUCCESS, data=data, physical_id=physical_id)

    if event['RequestType'] == 'Create':
        return do_idempotent_deploys()
    elif event['RequestType'] == 'Update':
        return do_idempotent_deploys()
    else:
        return CrResponse(CfnStatus.SUCCESS, data={}, physical_id=physical_id)
