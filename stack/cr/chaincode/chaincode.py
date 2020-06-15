import functools
import itertools
import time
import logging
import os, sys
from enum import Enum
from pathlib import Path

import bootstrap

from common import *

from eth_utils import remove_0x_prefix, add_0x_prefix
from toolz.functoolz import curry, pipe
from web3 import Web3
from web3.middleware import http_retry_request_middleware, attrdict_middleware, pythonic_middleware
from web3.datastructures import AttributeDict
from eth_account import Account
from eth_account.signers.local import LocalAccount
import boto3
from typing import List, Dict, Iterable, Callable, Union, TypeVar

from lib import gen_ssm_nodekey_service, SVC_CHAINCODE, gen_ssm_networkid, gen_ssm_sc_addr, \
    get_ssm_param_no_enc, get_ssm_param_with_enc, put_param_no_enc, put_param_with_enc, ssm_param_exists, \
    Timer, update_dict, list_ssm_params_starting_with, del_ssm_param, gen_ssm_inputs, gen_ssm_calltx, gen_ssm_send, \
    gen_ssm_call, gen_ssm_service_pks

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("chaincode")
log.setLevel(logging.INFO)
log.info("Chaincode logger initialized.")

ssm = boto3.client('ssm')

Acc = TypeVar('Acc')
T = TypeVar('T')


name_prefix = None


class InvalidInput(Exception):
    pass


class ResolveVarValError(Exception):
    pass


class OpType(Enum):
    Deploy = "deploy"
    CallTx = "calltx"
    Call = "call"
    Send = "send"


class CfnOutput:
    def mk_output_name(self):
        if 'Output' not in self.op:
            raise Exception(f"Cannot no `Output` specified for op: {self.op['Name']}")
        return self.op['Output']


class CallTxResult(CfnOutput):
    def __init__(self, name, function, txid, inputs=None, cached=False, op=None):
        self.name = name
        self.txid = txid
        self.function = function
        self.cached = cached
        self.inputs = [] if inputs is None else inputs
        self.op = op

    def mk_output(self):
        return self.mk_output_name(), self.txid

    def get_val(self):
        return self.txid

    def __str__(self):
        return f"<CallTxResult({self.name}): [Txid:{self.txid}]>"

    def __repr__(self):
        return f"<CallTxResult({self.name}): [Txid:{self.txid}, Func:{self.function}, Inputs:{self.inputs}]>"


class CallResult(CfnOutput):
    def __init__(self, name, function, inputs, output, ret_types, cached=False, op=None):
        self.name = name
        self.function = function
        self.inputs = [] if inputs is None else inputs
        self.output = output
        self.ret_types = ret_types
        self.cached = cached
        self.op = op

    def mk_output(self):
        return self.mk_output_name(), self.output

    def get_val(self):
        return self.output

    def get_ty(self):
        if len(self.ret_types) == 1:
            return self.ret_types[0]
        return self.ret_types

    def __str__(self):
        return f"<CallResult({self.name}): [Txid:{self.output}]>"

    def __repr__(self):
        return f"<CallResult({self.name}): [Func:{self.function}, Inputs:{self.inputs}, Output:{self.output}]>"

class SendResult(CfnOutput):
    def __init__(self, name, to, value, txid, cached=False, op=None):
        self.name = name
        self.to = to
        self.value = value
        self.txid = txid
        self.cached = cached
        self.op = op

    def mk_output(self):
        return self.mk_output_name(), self.txid

    def get_val(self):
        return self.txid

class Contract(CfnOutput):
    def __init__(self, name, bytecode, ssm_param_name, ssm_param_inputs, addr=None, inputs=None, gas_used=None,
                 cached=False, op=None):
        self.name = name
        self.bytecode = bytecode
        self.addr = addr
        self.inputs = inputs
        self.gas_used = gas_used
        self.cached = cached
        self.ssm_param_name = ssm_param_name
        self.ssm_param_inputs = ssm_param_inputs
        self.op = op

    def init_args(self):
        # matches function signature of __init__
        return [self.name, self.bytecode, self.ssm_param_name, self.ssm_param_inputs, self.addr, self.inputs,
                self.gas_used, self.cached, self.op]

    def mk_output(self):
        return self.mk_output_name(), self.addr

    def get_val(self):
        return self.addr

    def get_ty(self):
        return 'address'

    def ssm_names(self, name_prefix):
        # return (gen_ssm_sc_addr(name_prefix, self.name), gen_ssm_sc_inputs(name_prefix, self.name))
        return self.ssm_param_name, self.ssm_param_inputs

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
        return f"<Contract({self.name}): [Addr:{self.addr}, BC(len):{len(self.bytecode)}, Inputs:{self.inputs}]>"


op_str_to_ty = {
    OpType.Deploy.value: Contract,
    OpType.CallTx.value: CallTxResult,
    OpType.Call.value: CallResult,
    OpType.Send.value: SendResult,
}


class Op:
    def __init__(self, ty: OpType, result: Union[Contract, CallTxResult, CallResult, SendResult]):
        expected_type = op_str_to_ty[ty.value]
        if type(result) is not expected_type:
            raise TypeError(f'Incorrect types passed to Op. ty: {ty.value}, result: {str(type(result))}')

        self.ty = ty
        self.result = result


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


def send_raw_bump_nonce(w3, acct, tx: dict):
    try:
        tx['nonce'] = get_next_nonce(w3, acct)
        signed_tx = acct.signTransaction(tx)
        tx_id = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
        w3.eth.waitForTransactionReceipt(tx_id)
        return signed_tx, tx_id
    except ValueError as e:
        if "Transaction nonce is too low" in str(e):
            time.sleep(0.1)
            return send_raw_bump_nonce(w3, acct, tx)


def wait_for_tx_confirmed(w3: Web3, _tx_id, timeout=120, poll_rate=0.1) -> bool:
    _tx_r = w3.eth.waitForTransactionReceipt(_tx_id, timeout, poll_rate)
    return True
    # return _tx_r is None or _tx_r.blockNumber is None


def deploy_contract(w3: Web3, acct: LocalAccount, chainid: int, nonce: int, init_contract: Contract,
                    dry_run=False) -> Contract:
    log.info(f"[deploy_contract]: processing {init_contract.name}")
    c_out = Contract.from_contract(init_contract)

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
    log.info(f"Signing transaction: {update_dict(dict(unsigned_tx), {'data': f'<Data, len: {len(c_out.bytecode)}>'})}")
    signed_tx = acct.signTransaction(unsigned_tx)
    log.info(f"Signed transaction: {signed_tx}")

    MAX_SEC = 120
    with Timer(f"Send+Confirm contract: {c_out.name}") as t:
        tx_id = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
        log.info(f"Sent transaction; txid: {tx_id.hex()}")
        wait_for_tx_confirmed(w3, tx_id, timeout=MAX_SEC, poll_rate=0.1)

    tx_r = w3.eth.getTransactionReceipt(tx_id)
    if tx_r is None:
        raise Exception(f"Contract took longer than {MAX_SEC}s to confirm!")

    c_out.set_addr(tx_r.contractAddress)
    c_out.set_gas_used(tx_r.gasUsed)

    put_param_no_enc(c_out.ssm_param_name, c_out.addr, description=f"Address for sc deploy operation {c_out.name}",
                     dry_run=dry_run, overwrite=True)
    put_param_no_enc(c_out.ssm_param_inputs, c_out.inputs, encode_json=True, overwrite=True,
                     description=f"Inputs for sc operation {c_out.name}", dry_run=dry_run)

    return c_out


def get_bytecode(filepath: str) -> str:
    fp = Path('/', *(__file__.split('/')[:-1])) / Path(filepath)
    log.info(f"[get_bytecode] Opening bytecode from: {fp}")
    with fp.open('r') as f:
        bc = f.read().strip('\n')
    log.info(f"[get_bytecode] BC len: {len(bc)}")
    if bc[:2] != '0x':
        bc = '0x' + bc
    return bc


def _varval_is_addr_pointer(varval: str) -> bool:
    return type(varval) is str and varval[0] == "$"


def _varval_is_special_addr(varval: str) -> bool:
    return type(varval) is str and varval[0] == "^"


def _varval_is_ssm_pointer(varval: str) -> bool:
    return type(varval) is str and varval[0] == "_"


def _resolve_special_addr(acct, varval):
    return {
        'self': acct.address,
        'addr-zero': '0x0000000000000000000000000000000000000000',
        'addr-ones': '0x1111111111111111111111111111111111111111'
    }[varval[1:]]


def _resolve_ssm_pointer(varval, dry_run=False):
    global name_prefix
    if dry_run:
        return '0x2222222222222222222222222222222222222222'
    return get_ssm_param_no_enc(gen_ssm_service_pks(name_prefix), decode_json=True)[varval[1:]]


def is_varval(varval) -> bool:
    return _varval_is_addr_pointer(varval) or _varval_is_special_addr(varval) or _varval_is_ssm_pointer(varval)


def resolve_var_val(acct, prev_outs: Dict[str, Contract], var_val, default_ty='unknown-type', dry_run=False) -> (str, str):
    try:
        if _varval_is_addr_pointer(var_val):  # SC addr
            return prev_outs[var_val[1:]].get_val()
        if _varval_is_special_addr(var_val):
            return _resolve_special_addr(acct, var_val)
        if _varval_is_ssm_pointer(var_val):
            return _resolve_ssm_pointer(var_val, dry_run=dry_run)
        return var_val
    except Exception as e:
        log.error(f"Unknown error occured: {repr(e)}")
        raise e


def _get_input_type(_prevs, _input):
    try:
        return _input.split(':')[0] if ':' in _input else {
            '$': lambda: _prevs[_input[1:]].get_ty(),
            '^': lambda: 'address',
            '_': lambda: 'address',
        }[_input[0]]()
    except Exception as e:
        raise InvalidInput(f"`{_input}` is not valid. {repr(e)}")


def _varval_type_conv(ty, val):
    return {
        'bool': lambda v: str(v).lower() == 'true',
        'address': str,
        'uint256': int,
        'bytes32': str,
    }[ty](val)


def varval_from_input(_input):
    try:
        if type(_input) is not str:
            raise ResolveVarValError(f'values other than strings not yet supported: {_input}')
        if ':' in _input:
            return _varval_type_conv(*_input.split(':', 1))
        return _input
    except Exception as e:
        log.error(f"Error converting input to varval; _input: {_input}")
        raise e


def transform_output(ty, out):
    print(ty, out)
    if 'bytes' in ty:
        return add_0x_prefix(out.hex())
    return out


def transform_outputs(ret_types, outputs):
    if len(ret_types) == 1 and type(outputs) is not list:
        outputs = [outputs]
    _outputs = [transform_output(ty, out) for (ty, out) in zip(ret_types, outputs)]
    logging.info(f"returning transformed outputs: {ret_types, _outputs}")
    if len(_outputs) == 1:
        return _outputs[0]
    return _outputs


def process_bytecode(w3, acct, raw_bc: str, prev_outs, inputs, func=None, libs=dict(), sc_op=dict(), dry_run=False) -> (Dict, List):
    '''Constructs an ABI on the fly based on Value,Type of inputs, resolves variables (e.g. SC addrs) which need to be,
     and returns encoded+packed arguments as a hex string with no 0x prefix. Also resolves/adds libraries if need be.'''

    def sub_libs(_bc, libtuple):
        lib_hole, var_val = libtuple
        val = resolve_var_val(acct, prev_outs, var_val, dry_run=dry_run)
        return _bc.replace(lib_hole, remove_0x_prefix(val))

    def do_inputs(_bc):
        '''Take inputs and process/pack them and add to end of bytecode.'''
        tx_res = {'data': _bc}
        _inputs = []
        if len(inputs) > 0 or True:  # TODO: If this works for empty Inputs, remove condition
            abi = {'inputs': [{"name": f"_{i}", "type": _get_input_type(prev_outs, _input)} for (i, _input) in enumerate(inputs)]}
            abi.update({'payable': False, "stateMutability": "nonpayable", "constant": False})
            tx = {'gasPrice': 1, 'gas': 7500000}
            if 'Value' in sc_op:
                abi.update({'payable': True, 'stateMutability': 'payable', "constant": False})
                tx.update({'value': int(sc_op['Value'])})
            _inputs = list(map(curry(resolve_var_val)(acct)(prev_outs)(dry_run=dry_run), [varval_from_input(i) for i in inputs]))
            log.info(f'inputs to constructor/function: {_inputs}')
            # construct the abi
            log.info(f"do_inputs: func:{func}, _inputs:{_inputs}")
            if func is not None:  # is not constructor
                func_addr_ptr, func_name = func.split('.')
                func_addr = resolve_var_val(acct, prev_outs, func_addr_ptr, dry_run=dry_run)
                abi.update({"type": "function", "name": func_name, "outputs": []})
                if abi['stateMutability'] == "nonpayable" and sc_op['Type'] == "call":
                    abi.update({"constant": True, 'stateMutability': 'view'})
                ret_types = sc_op.get('ReturnTypes', None)
                if ret_types:
                    abi.update({'outputs': [{'name': '', 'type': r} for r in ret_types], 'stateMutability': 'view', "constant": True})
                log.info(f"do_inputs: {func_addr}.{func_name}({', '.join(map(str, _inputs))}) w/ abi: {abi} returns {ret_types}")
                if ret_types:
                    resp = w3.eth.contract(abi=[abi], address=func_addr).functions[func_name](*_inputs).call()
                    tx_res = transform_outputs(ret_types, resp)
                    log.info(f'call: {func_addr}.{func_name}({", ".join(map(str, _inputs))}) w/ resp: {tx_res, transform_outputs(ret_types, resp)}')
                else:
                    tx_res.update(
                        w3.eth.contract(abi=[abi], address=func_addr).functions[func_name](*_inputs).buildTransaction(tx))
                    log.info(f'calltx: {func_addr}.{func_name}({", ".join(map(str, _inputs))}) w/ resp: {tx_res}')
            else:
                abi.update({"type": "constructor"})
                log.info(f"do_inputs: constructor({', '.join(map(str, _inputs))}) w/ abi: {abi}")
                tx_res.update(w3.eth.contract(abi=[abi], bytecode=_bc).constructor(*_inputs).buildTransaction(tx))
        return tx_res, _inputs

    do_libs = curry(reduce)(sub_libs)(libs.items())

    return pipe(raw_bc,
                do_libs,
                do_inputs  # this returns tx w/ at least the 'data' param
                )


def mk_contract(_name_prefix, w3, acct, chainid, nonce, dry_run=False):
    global name_prefix
    name_prefix = _name_prefix

    def do_fold(prev_outputs: Dict[str, Contract], next):
        nonlocal nonce

        ret = dict(prev_outputs)
        entry_name = next['Name']
        inputs = next.get('Inputs', [])
        libs = next.get('Libraries', {})
        ssm_deploy = gen_ssm_sc_addr(name_prefix, entry_name)  # ssm param name for address of contracts via deploy ops
        ssm_calltx = gen_ssm_calltx(name_prefix, entry_name)  # ssm param name to store txid of calltx ops
        ssm_call = gen_ssm_call(name_prefix, entry_name)  # ssm param name to store json encoded output of call ops
        ssm_send = gen_ssm_send(name_prefix, entry_name)  # ssm param name to store txid of send ops
        ssm_inputs = gen_ssm_inputs(name_prefix, entry_name)  # ssm param name to store inputs

        def relies_only_on_cached(_prevs):
            # currently the only dependant outputs possible are addresses; TODO: add output values from function calls
            to_check = [x for x in (inputs + list(libs.values())) if _varval_is_addr_pointer(x)]
            for i in to_check:
                # note: val[1:] should always exit in prev_outputs at this point
                sc = i[1:]
                if sc in prev_outputs and not prev_outputs[sc].cached:
                    log.info(f"not cached as {sc} is not cached")
                    return False
            try:
                cached_inputs = get_ssm_param_no_enc(ssm_inputs, decode_json=True)
                for (a, b) in zip(inputs, cached_inputs):
                    if resolve_var_val(acct, _prevs, varval_from_input(a), dry_run=dry_run) != b:
                        log.info(f"not cached as {a} != {b} for inputs: {inputs}, (cached:) {cached_inputs}")
                        return False
            except Exception as e:
                log.warning(f"Exception checking for cached inputs: {repr(e)}")
                return False
            return True

        def deploy(_prevs, _next):
            nonlocal nonce
            if not dry_run and ssm_param_exists(ssm_deploy) and ssm_param_exists(
                    ssm_inputs) and relies_only_on_cached(_prevs):
                # we don't want to deploy
                log.info(f"Skipping deploy of {entry_name} as it is cached and relies only on cached ops.")
                return Contract(entry_name, '', ssm_deploy, ssm_inputs, addr=get_ssm_param_no_enc(ssm_deploy),
                                inputs=get_ssm_param_no_enc(ssm_inputs, decode_json=True), cached=True, op=_next)

            log.info(f"Deploying {entry_name} - not cached.")
            if 'URL' in _next:
                # remote
                raise Exception('remote deploys not yet supported')
            else:
                # local deploy
                raw_bc = get_bytecode(f"bytecode/{entry_name}.bin")
            tx, _inputs = process_bytecode(w3, acct, raw_bc, _prevs, inputs, libs=libs, sc_op=_next, dry_run=dry_run)
            bc = tx['data']
            log.info(f"Processed bytecode for {entry_name}; lengths: raw({len(raw_bc)}), processed({len(bc)})")
            c_done = deploy_contract(w3, acct, chainid, nonce,
                                     Contract(entry_name, bc, ssm_deploy, ssm_inputs, inputs=_inputs, op=_next),
                                     dry_run=dry_run)
            nonce += 1
            return c_done

        # def ssm_get_calltx():
        #     return dict(map(lambda pss: (pss[0], get_ssm_param_no_enc(**pss[1])), [
        #         ('calltx', [gen_ssm_calltx(name_prefix, entry_name), False]),
        #         ('inputs', [gen_ssm_inputs(name_prefix, entry_name), True])
        #     ]))
        #
        # def ssm_set_calltx(calltx=None, inputs=None):
        #     if calltx is None or inputs is None:
        #         raise Exception("null inputs provided to ssm_set")
        #     return dict(map(lambda pss: (pss[0], put_param_no_enc(**pss[1])), [('calltx', calltx), ('inputs', inputs)]))

        def calltx(_prevs, _next):
            nonlocal nonce
            if not dry_run and ssm_param_exists(ssm_calltx) and ssm_param_exists(
                    ssm_inputs) and relies_only_on_cached(_prevs):
                # we don't want to make tx
                log.info(f"Skipping tx {entry_name} as it is cached and relies only on cached ops.")
                return CallTxResult(entry_name, _next['Function'], get_ssm_param_no_enc(ssm_calltx),
                                    inputs=get_ssm_param_no_enc(ssm_inputs, decode_json=True), cached=True, op=_next)

            log.info(f"CallTx: {entry_name} - not cached")
            tx, _inputs = process_bytecode(w3, acct, '', _prevs, inputs, func=_next['Function'], sc_op=_next, dry_run=dry_run)
            log.info(f"CallTx got from process_bytecode: {tx}, {_inputs}")

            signed_tx, tx_id = send_raw_bump_nonce(w3, acct, tx)
            w3.eth.waitForTransactionReceipt(tx_id)
            log.info(f"CallTx got txid: {tx_id.hex()} with raw transaction: {signed_tx['rawTransaction']}")
            with Timer(f'calltx {entry_name}') as t:
                tx_r = w3.eth.getTransactionReceipt(tx_id)
            time.sleep(4)

            log.info(f"Saving txid under in parameter store under {ssm_calltx}")
            put_param_no_enc(ssm_calltx, tx_id.hex(), description=f"TXID for {entry_name} (calltx) operation",
                             overwrite=True, dry_run=dry_run)
            put_param_no_enc(ssm_inputs, _inputs, description=f"Inputs for {entry_name} (calltx) operation",
                             overwrite=True, encode_json=True, dry_run=dry_run)

            return CallTxResult(entry_name, _next['Function'], tx_id.hex(), inputs=_inputs, op=_next)

        def call(_prevs, _next):
            if not dry_run and ssm_param_exists(ssm_call) and ssm_param_exists(ssm_inputs) and relies_only_on_cached(_prevs):
                log.info(f"skipping {entry_name} - cached")
                return CallResult(entry_name, _next['Function'], get_ssm_param_no_enc(ssm_inputs, decode_json=True),
                                  get_ssm_param_no_enc(ssm_call, decode_json=True), ret_types=_next['ReturnTypes'], cached=True, op=_next)

            log.info(f"Call: {entry_name} - not cached")
            tx_resp, _inputs = process_bytecode(w3, acct, '', _prevs, inputs, func=_next['Function'], sc_op=_next, dry_run=dry_run)
            log.info(f"Call got from process_bytecode: {tx_resp}")

            put_param_no_enc(ssm_call, tx_resp, description=f"TXID for {entry_name} (call) operation",
                             overwrite=True, encode_json=True, dry_run=dry_run)
            put_param_no_enc(ssm_inputs, _inputs, description=f"Inputs for {entry_name} (call) operation",
                             overwrite=True, encode_json=True, dry_run=dry_run)

            return CallResult(entry_name, _next['Function'], _inputs, tx_resp, ret_types=_next['ReturnTypes'], op=_next)

        ops = AttributeDict({
            OpType.Deploy.value: deploy,
            OpType.CallTx.value: calltx,
            OpType.Call.value: call,
        })

        if next['Type'] not in ops:
            raise Exception(f'SC Deploy/Call type {next["Type"]} is not recognised as a valid type of operation. '
                            f'Valid Types: {set(ops.values())}')
        ret[entry_name] = ops[next['Type']](prev_outputs, next)
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
        ws_connect_url = f"ws://{public_node_domain}:8546"
        http_connect_url = f"http://{public_node_domain}:8545"
        log.info(f"Connecting to: {http_connect_url}")
        # w3 = Web3(Web3.WebsocketProvider(ws_connect_url))
        w3 = Web3(Web3.HTTPProvider(http_connect_url))  #, middlewares=[http_retry_request_middleware, attrdict_middleware, pythonic_middleware])
        log.info(f"w3.eth.getBlock('latest'): {dict(w3.eth.getBlock('latest'))}")

        chainid = int(get_chainid(name_prefix))

        if len(set([c['Name'] for c in smart_contracts_to_deploy])) != len(smart_contracts_to_deploy):
            raise Exception("All 'Name' params must be unique in SC deploy plans")

        processed_scs = functools.reduce(mk_contract(name_prefix, w3, acct, chainid, nonce=get_next_nonce(w3, acct)),
                                         smart_contracts_to_deploy, dict())

        log.info(f"processed_scs: {processed_scs}")

        data = dict([c.mk_output() for c in processed_scs.values() if 'Output' in c.op])

        return CrResponse(CfnStatus.SUCCESS, data=data, physical_id=physical_id)

    if event['RequestType'] == 'Create':
        return do_idempotent_deploys()
    elif event['RequestType'] == 'Update':
        cr = do_idempotent_deploys()
        do_deletes(name_prefix, keep_scs=smart_contracts_to_deploy)
        return cr
    else:
        do_deletes(name_prefix, keep_scs=smart_contracts_to_deploy)
        return CrResponse(CfnStatus.SUCCESS, data={}, physical_id=physical_id)


def do_deletes(name_prefix, keep_scs: List):
    keep_names = set() \
        .union({gen_ssm_sc_addr(name_prefix, op['Name']) for op in keep_scs}) \
        .union({gen_ssm_inputs(name_prefix, op['Name']) for op in keep_scs}) \
        .union({gen_ssm_calltx(name_prefix, op['Name']) for op in keep_scs}) \
        .union({gen_ssm_call(name_prefix, op['Name']) for op in keep_scs}) \
        .union({gen_ssm_send(name_prefix, op['Name']) for op in keep_scs})
    params = list_ssm_params_starting_with(gen_ssm_sc_addr(name_prefix, '')) + \
        list_ssm_params_starting_with(gen_ssm_inputs(name_prefix, '')) + \
        list_ssm_params_starting_with(gen_ssm_calltx(name_prefix, '')) + \
        list_ssm_params_starting_with(gen_ssm_call(name_prefix, '')) + \
        list_ssm_params_starting_with(gen_ssm_send(name_prefix, ''))
    for param in params:
        ssm_name = param['Name']
        if ssm_name in keep_names:
            log.info(f"Skipping delete of {ssm_name}")
        else:
            log.info(f"Deleting {ssm_name}")
            del_ssm_param(ssm_name)
