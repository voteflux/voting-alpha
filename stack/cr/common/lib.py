import binascii
import json
import logging
import os, secrets
import string
import time
import urllib
import hashlib
from base64 import b64encode
from datetime import datetime
from typing import List, NamedTuple

from botocore.exceptions import ClientError
from ecdsa import SigningKey, SECP256k1

import boto3
from env import env

from eth_account.account import Account

SsmParam = NamedTuple('SsmParam',
                      [('Name', str), ('Type', str), ('KeyId', str), ('LastModifiedDate', datetime),
                       ('Description', str), ('Version', int)])

SVC_CHAINCODE = "publish"
SVC_MEMBERS = "members"
SVC_CASTVOTE = "castvote"
SERVICES = [SVC_CHAINCODE, SVC_MEMBERS, SVC_CASTVOTE]

ssm = boto3.client('ssm')


class Timer:
    def __init__(self, name=''):
        self.name = name

    def __enter__(self):
        if self.name:
            logging.info(f"Timer starting for {self.name}")
        self.start = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end = time.time()
        self.interval = self.end - self.start
        if self.name:
            logging.info(f'{self.name} :: Duration was {self.interval} seconds.')

    @property
    def curr_interval(self):
        return time.time() - self.start


def update_dict(_dict, _new_fields):
    _dict.update(_new_fields)
    return _dict


def http_get(url: str) -> bytes:
    with urllib.request.urlopen(url) as r:
        return r.read()


def _hash(bs: bytes) -> bytes:
    return hashlib.sha512(bs).digest()


def _hash_str(s: str) -> str:
    return _hash(s.encode()).decode()


def get_some_entropy() -> bytes:
    '''Use various online sources + urandom to generate entropy'''
    sources = [
        secrets.token_bytes(128),
        os.urandom(128),
        b'' if env.get('DEBUG', False) else _hash(http_get("https://www.grc.com/passwords.htm"))
    ]
    return _hash(b''.join(sources))


def remove_s3_bucket_objs(StaticBucketName, **params):
    return {'DeletedS3Bucket': str(boto3.resource('s3').Bucket(StaticBucketName).objects.filter().delete())}


def generate_ec2_key(ShouldGenEc2SSHKey: bool, NamePrefix: str, SSHEncryptionPassword: str, AdminEmail, **kwargs):
    logging.info("gen_ec2_key: %s", {'ShouldGenEc2SSHKey': ShouldGenEc2SSHKey, 'NamePrefix': NamePrefix})
    ret = {'CreatedEc2KeyPair': False}
    KeyPairName = "sv-{}-node-ec2-ssh-key".format(NamePrefix)  # , int(time.time()))
    ret['KeyPairName'] = KeyPairName
    ec2 = boto3.client('ec2')
    kps = ec2.describe_key_pairs()
    if sum([kp['KeyName'] == KeyPairName for kp in
            kps['KeyPairs']]) == 0:  # this should always be 0 if we add a timestamp to the SSH key
        ret['CreatedEc2KeyPair'] = True
        if ShouldGenEc2SSHKey:
            raise Exception("ssh key gen not supported yet")
            # ssh_pem = ec2.create_key_pair(KeyName=KeyPairName)['KeyMaterial']
            # sns = boto3.client('sns')
        elif 'SSHKey' in kwargs and kwargs['SSHKey']:
            ec2.import_key_pair(KeyName=KeyPairName, PublicKeyMaterial=kwargs['SSHKey'].encode())
        else:
            raise Exception(
                "`SSHKey` must be provided or an SSH key must be generated which requires SSHEncryptionPassword.")
    else:
        # we already have a key with this name. Keep it?
        # We probs want to delete the key when we remove the stack...
        pass
    return ret


def priv_to_addr(_priv):
    return Account.privateKeyToAccount(_priv).address


def get_ssm_param_no_enc(name, decode_json=False):
    try:
        value = ssm.get_parameter(Name=name)['Parameter']['Value']
    except Exception as e:
        logging.warning(f"Error during get_parameter: {repr(e)}")
        return None
    if decode_json:
        value = json.loads(value)
    return value


def get_ssm_param_with_enc(name):
    try:
        return ssm.get_parameter(Name=name, WithDecryption=True)['Parameter']['Value']
    except Exception as e:
        logging.warning(f"Error during get_parameter: {repr(e)}")
        return None


def put_param_no_enc(name, value, description='', encode_json=False, overwrite=False, dry_run=False):
    if dry_run:
        logging.debug(f'[dry_run] put_param: {name}, value: {value}')
        return {}
    if encode_json:
        value = json.dumps(value)
    return ssm.put_parameter(Name=name, Value=value, Type="String", Description=description, Overwrite=overwrite)


def put_param_with_enc(name, value, description='', overwrite=False):
    return ssm.put_parameter(Name=name, Value=value, Type="SecureString", Description=description, Overwrite=overwrite)


def delete_ssm_param(name):
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as e:
        if "ParameterNotFound" not in str(e):
            raise e


def ssm_param_exists(name):
    return get_ssm_param_no_enc(name) is not None


def gen_ssm_nodekey_consensus(NamePrefix, i):
    return "sv-{}-nodekey-consensus-{}".format(NamePrefix, i)


def gen_ssm_enodekey_public(NamePrefix, i):
    return "sv-{}-enodekey-public-{}".format(NamePrefix, i)


def gen_ssm_nodekey_service(NamePrefix, eth_service):
    return "sv-{}-nodekey-service-{}".format(NamePrefix, eth_service)


def gen_ssm_key_poa_pks(NamePrefix):
    return 'sv-{}-param-poa-pks'.format(NamePrefix)


def gen_ssm_service_pks(NamePrefix):
    return 'sv-{}-param-service-pks'.format(NamePrefix)


def gen_ssm_enode_pks(NamePrefix):
    return 'sv-{}-param-enode-pks'.format(NamePrefix)


def gen_ssm_networkid(NamePrefix):
    return 'sv-{}-param-networkid'.format(NamePrefix)


def gen_ssm_eth_stats_secret(NamePrefix):
    return 'sv-{}-param-ethstatssecret'.format(NamePrefix)


def gen_ssm_sc_addr(name_prefix, sc_name):
    return f"sv-{name_prefix}-param-sc-addr-{sc_name}"


def gen_ssm_inputs(name_prefix, sc_name):
    return f"sv-{name_prefix}-param-sc-inputs-{sc_name}"


def gen_ssm_calltx(name_prefix, sc_name):
    return f"sv-{name_prefix}-param-sc-calltx-{sc_name}"


def gen_ssm_call(name_prefix, sc_name):
    return f"sv-{name_prefix}-param-sc-call-{sc_name}"


def gen_ssm_send(name_prefix, sc_name):
    return f"sv-{name_prefix}-param-sc-send-{sc_name}"


def list_ssm_params_starting_with(*args, next_token='', max_results=50) -> List[SsmParam]:
    filters = [{'Key': 'Name', 'Option': 'BeginsWith', 'Values': args}]
    extra = {} if not next_token else {'NextToken': next_token}
    res = ssm.describe_parameters(ParameterFilters=filters, MaxResults=max_results, **extra)
    params = res['Parameters']
    if len(params) >= max_results:
        params += list_ssm_params_starting_with(*args, next_token=res['NextToken'], max_results=max_results)
    return params


def del_ssm_param(name):
    try:
        return ssm.delete_parameter(Name=name)
    except Exception as e:
        if "ParameterNotFound" not in str(e):
            raise e


def create_node_keys(NConsensusNodes, NamePrefix, NPublicNodes, **kwargs) -> (list, list, list):
    _e = get_some_entropy()

    def gen_next_key(hex_prefix="0x"):
        nonlocal _e
        _h = _hash(_e)
        _privkey = hex_prefix + binascii.hexlify(_h[:32]).decode()
        _e = _h[32:]
        assert len(_e) >= 32
        pk = priv_to_addr(_privkey)
        return _privkey, pk

    keys = []
    poa_pks = []
    service_pks = {}
    enode_pks = []
    for i in range(int(NConsensusNodes)):  # max nConsensusNodes
        (_privkey, pk) = gen_next_key()
        keys.append({'Name': gen_ssm_nodekey_consensus(NamePrefix, i),
                     'Description': "Private key for consensus node #{}".format(i),
                     'Value': _privkey, 'Type': 'SecureString'})
        poa_pks.append(pk)

    logging.info(f"poa_pks: {poa_pks}")

    for eth_service in SERVICES:
        (_privkey, pk) = gen_next_key()
        keys.append({'Name': gen_ssm_nodekey_service(NamePrefix, eth_service),
                     'Description': "Private key for service lambda: {}".format(eth_service),
                     'Value': _privkey, 'Type': 'SecureString'})
        service_pks[eth_service] = pk

    logging.info(f"service_pks: {service_pks}")

    for i in range(int(NPublicNodes)):
        (_privkey, _) = gen_next_key(hex_prefix='')
        pk = SigningKey.from_string(bytes.fromhex(_privkey), curve=SECP256k1).get_verifying_key().to_string().hex()
        keys.append({'Name': gen_ssm_enodekey_public(NamePrefix, i),
                     'Description': "ENODE Private key for public node #{} (not address)".format(i),
                     'Value': _privkey, 'Type': 'SecureString'})
        enode_pks.append(pk)

    logging.info(f"enode_pks: {enode_pks}")

    return {'ssm_keys': keys, 'poa_pks': poa_pks, 'service_pks': service_pks, 'enode_pks': enode_pks}


def save_node_keys(keys: list, NamePrefix, **kwargs):
    existing_ssm = list_ssm_params_starting_with("sv-{}-nodekey-consensus".format(NamePrefix),
                                                 "sv-{}-param-poa-pk".format(NamePrefix))
    existing_ssm_names = {p['Name'] for p in existing_ssm}
    logging.info('existing_ssm_names: %s', existing_ssm_names)
    skipped_params = []
    for k in keys:
        if k['Name'] in existing_ssm_names:
            logging.info("Skipping SSM Param as it exists: {}".format(k['Name']))
            skipped_params.append(k['Name'])
        else:
            logging.info("Creating SSM param: %s", k['Name'])
            ssm.put_parameter(**k)
    return {'SavedConsensusNodePrivKeys': True, 'SkippedConsensusNodePrivKeys': skipped_params}


def save_poa_pks(poa_pks, NamePrefix, **props):
    ssm.put_parameter(Name=gen_ssm_key_poa_pks(NamePrefix),
                      Description="PoA addresses (as in chainspec)",
                      Value=json.dumps(poa_pks),
                      Type='String')
    return {"SavedPoaPks": True}


def save_service_pks(service_pks, NamePrefix, **props):
    ssm.put_parameter(Name=gen_ssm_service_pks(NamePrefix),
                      Description="Eth Services (Lambda) addresses (as in chainspec)",
                      Value=json.dumps(service_pks),
                      Type='String')
    return {"SavedPoaPks": True}


def save_enode_pks(enode_pks, NamePrefix, **props):
    ssm.put_parameter(Name=gen_ssm_enode_pks(NamePrefix),
                      Description="Public nodes ENODE ids (for chainspec)",
                      Value=json.dumps(enode_pks),
                      Type='String')
    return {"SavedPublicEnodes": True}


def delete_all_node_keys(NamePrefix, NConsensusNodes, NPublicNodes, **props):
    def try_del(name):
        try:
            ssm.delete_parameter(Name=name)
        except Exception as e:
            if 'ParameterNotFound' not in repr(e):
                raise e

    try_del(gen_ssm_key_poa_pks(NamePrefix))
    consensus_node_keys = [gen_ssm_nodekey_consensus(NamePrefix, i) for i in range(int(NConsensusNodes))]
    public_enode_keys = [gen_ssm_enodekey_public(NamePrefix, i) for i in range(int(NPublicNodes))]
    for name in consensus_node_keys + public_enode_keys:
        try_del(name)
    try_del(gen_ssm_service_pks(NamePrefix))
    try_del(gen_ssm_enode_pks(NamePrefix))
    for n in [gen_ssm_nodekey_service(NamePrefix, service) for service in SERVICES]:
        try_del(n)
    return {"DeletedAllNodeKeys": True}


def gen_network_id(NamePrefix, **kwargs):
    network_id = secrets.randbits(32)
    ret = {'NetworkId': network_id}
    ssm.put_parameter(Name=gen_ssm_networkid(NamePrefix), Value=str(network_id),
                      Description='NetworkId for eth network', Type='String')
    return ret


def gen_eth_stats_secret(NamePrefix, **kwargs):
    ret = {
        'EthStatsSecret': ''.join([secrets.choice(string.ascii_letters + string.digits) for _ in range(20)])
    }
    ssm.put_parameter(Name=gen_ssm_eth_stats_secret(NamePrefix), Value=ret['EthStatsSecret'],
                      Description='Secret for EthStats',
                      Type='SecureString')
    return ret


def del_ssm_networkid_ethstats(NamePrefix, **props):
    delete_ssm_param(gen_ssm_eth_stats_secret(NamePrefix))
    delete_ssm_param(gen_ssm_networkid(NamePrefix))
    return {'DeletedSSMNetworkIdAndEthStats': True}


def upload_endpoint_details(NamePrefix, StaticBucketName, **params):
    # todo: just copy of chain config atm
    # this should (eventually) store the details of addresses etc of on-chain contracts.
    poa_pks = json.loads(ssm.get_parameter(Name=gen_ssm_key_poa_pks(NamePrefix))['Parameter']['Value'])
    service_pks: dict = json.loads(ssm.get_parameter(Name=gen_ssm_service_pks(NamePrefix))['Parameter']['Value'])
    enode_pks = json.loads(ssm.get_parameter(Name=gen_ssm_enode_pks(NamePrefix))['Parameter']['Value'])

    chainspec = json.dumps(gen_chainspec_json(poa_pks, list(service_pks.values()), enode_pks, NamePrefix=NamePrefix, **params))
    ret = {'ChainSpecGenerated': True}
    obj_key = 'chain/chainspec.json'
    s3 = boto3.client('s3')
    put_resp = s3.put_object(Key=obj_key, Body=chainspec, Bucket=StaticBucketName, ACL='public-read')
    ret['ChainSpecUrl'] = '{}/{}/{}'.format(s3.meta.endpoint_url, StaticBucketName, obj_key)
    return ret


def upload_chain_config(NamePrefix, StaticBucketName, **params):
    poa_pks = json.loads(ssm.get_parameter(Name=gen_ssm_key_poa_pks(NamePrefix))['Parameter']['Value'])
    service_pks: dict = json.loads(ssm.get_parameter(Name=gen_ssm_service_pks(NamePrefix))['Parameter']['Value'])
    enode_pks = json.loads(ssm.get_parameter(Name=gen_ssm_enode_pks(NamePrefix))['Parameter']['Value'])

    chainspec = json.dumps(gen_chainspec_json(poa_pks, list(service_pks.values()), enode_pks, NamePrefix=NamePrefix, **params))
    ret = {'ChainSpecGenerated': True}
    obj_key = 'chain/chainspec.json'
    s3 = boto3.client('s3')
    put_resp = s3.put_object(Key=obj_key, Body=chainspec, Bucket=StaticBucketName, ACL='public-read')
    ret['ChainSpecUrl'] = '{}/{}/{}'.format(s3.meta.endpoint_url, StaticBucketName, obj_key)
    return ret


def gen_chainspec_json(poa_addresses: list, service_addresses: list, enode_pks: list, pEnodeIps, **params) -> dict:
    """
    :param poa_addresses: list of addresses for the proof of authority nodes
    :param service_addresses: list of addresses for services (i.e the lambdas that do things like onboarding members)
    :return: dict: the chainspec
    """

    NamePrefix = params['NamePrefix']
    gas_limit = hex(int(params['BlockGasLimit']))

    NetworkId = params['NetworkId']
    hex_network_id = hex(NetworkId)

    INIT_BAL = hex(160693804425899027554196209234)

    builtins = {"0000000000000000000000000000000000000001": {
        "balance": "1", "builtin": {"name": "ecrecover", "pricing": {"linear": {"base": 3000, "word": 0}}}},
        "0000000000000000000000000000000000000002": {
            "balance": "1", "builtin": {"name": "sha256", "pricing": {"linear": {"base": 60, "word": 12}}}},
        "0000000000000000000000000000000000000003": {
            "balance": "1", "builtin": {"name": "ripemd160", "pricing": {"linear": {"base": 600, "word": 120}}}},
        "0000000000000000000000000000000000000004": {
            "balance": "1", "builtin": {"name": "identity", "pricing": {"linear": {"base": 15, "word": 3}}}},
        "0000000000000000000000000000000000000005": {
            "balance": "1", "builtin": {"name": "modexp", "pricing": {"modexp": {"divisor": 20}}}},
        "0000000000000000000000000000000000000006": {
            "balance": "1", "builtin": {"name": "alt_bn128_add", "pricing": {"linear": {"base": 500, "word": 0}}}},
        "0000000000000000000000000000000000000007": {
            "balance": "1", "builtin": {"name": "alt_bn128_mul", "pricing": {"linear": {"base": 40000, "word": 0}}}},
        "0000000000000000000000000000000000000008": {
            "balance": "1", "builtin": {"name": "alt_bn128_pairing",
                                        "pricing": {"alt_bn128_pairing": {"base": 100000, "pair": 80000}}}}}

    accounts = {addr: {"balance": INIT_BAL} for addr in service_addresses}
    accounts.update(builtins)

    enodes = list(["enode://{pk}@{ip}:30303".format(pk=pk, ip=ip) for (pk, ip) in zip(enode_pks, pEnodeIps.split(','))])

    return {
        "name": "{} PoA Network - Powered by SecureVote and Flux".format(NamePrefix),
        "dataDir": "sv-{}-poa-net".format(NamePrefix),
        "engine": {
            "authorityRound": {
                "params": {
                    "stepDuration": "5",
                    "blockReward": "0x4563918244F40000",
                    "validators": {
                        "multi": {
                            "0": {
                                "list": poa_addresses
                            }
                        }
                    },
                    "maximumUncleCountTransition": 0,
                    "maximumUncleCount": 0
                }
            }
        },
        "genesis": {
            "seal": {
                "authorityRound": {
                    "step": "0x0",
                    "signature": "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                }
            },
            "difficulty": "0x20000",
            "gasLimit": gas_limit,
            "timestamp": 1546128058,
            "extraData": "0x" + "{}-PoweredBySecureVote".format(NamePrefix)[:32].encode().hex()
        },
        "params": {
            "networkID": hex_network_id,
            "chainID": hex_network_id,
            "maximumExtraDataSize": "0x20",
            "minGasLimit": "0x3fffff",
            "gasLimitBoundDivisor": "0x400",
            # "registrar": "0xfAb104398BBefbd47752E7702D9fE23047E1Bca3",
            "maxCodeSize": 65536,
            "maxCodeSizeTransition": 0,
            "validateChainIdTransition": 0,
            "validateReceiptsTransition": 0,
            "eip140Transition": 0,
            "eip211Transition": 0,
            "eip214Transition": 0,
            "eip658Transition": 0,
            "wasmActivationTransition": 0
        },
        "accounts": accounts,
        "nodes": enodes
        # "nodes": [
        #     "enode://304c9dbcca45409785539b227f273c3329197c86de6cc8d73252870f91176eb3588db2774fc7db4a6011519faa5fa4f39d63aeb341db672901ebdf3555fda095@13.238.183.223:30303",
        #     "enode://7a75777e450bd552ff55b08746a10873e141ba15984fbd1d89cc132e468d4f9ed5ddf011008fbf39be2e45c03b0930328faa074b6c040d46b1a543a49b47ee06@52.213.81.2:30303",
        #     "enode://828d0acaad0e9dc726ceac4d0a6e21451d80cbcfb24931c92219b9be713c2f66fa2ca5dd81d19a660ef182c94758e2ff0e2ad94b27fe78dbce9d107027ae5a68@13.211.132.131:30303"
        # ]
    }
