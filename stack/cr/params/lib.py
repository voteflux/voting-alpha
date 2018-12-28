import binascii
import logging
import os, secrets
import string
import time
import urllib
import hashlib

import boto3


def http_get(url: str) -> bytes:
    with urllib.request.urlopen(url) as r:
        return r.read()


def _hash(bs: bytes) -> bytes:
    return hashlib.sha512(bs).digest()


def get_some_entropy() -> bytes:
    '''Use various online sources + urandom to generate entropy'''
    sources = [ secrets.token_bytes(128), _hash(http_get("https://www.grc.com/passwords.htm")) ]
    return _hash(b''.join(sources))


def generate_ec2_key(ShouldGenEc2SSHKey: bool, NamePrefix: str, SSHEncryptionPassword: str, AdminEmail, **kwargs):
    logging.info("gen_ec2_key: %s", {'ShouldGenEc2SSHKey': ShouldGenEc2SSHKey, 'NamePrefix': NamePrefix})
    ret = {'CreatedEc2KeyPair': False}
    KeyPairName = "{}-sv-node-ec2-ssh-key".format(NamePrefix) #, int(time.time()))
    ec2 = boto3.client('ec2')
    kps = ec2.describe_key_pairs()
    if sum([kp['KeyName'] == KeyPairName for kp in kps['KeyPairs']]) == 0:  # this should always be 0 if we add a timestamp to the SSH key
        ret['CreatedEc2KeyPair'] = True
        if ShouldGenEc2SSHKey:
            raise Exception("ssh key gen not supported yet")
            # ssh_pem = ec2.create_key_pair(KeyName=KeyPairName)['KeyMaterial']
            # sns = boto3.client('sns')
        elif 'SSHKey' in kwargs:
            ec2.import_key_pair(KeyName=KeyPairName, PublicKeyMaterial=kwargs['SSHKey'].encode())
        else:
            raise Exception("`SSHKey` must be provided or an SSH key must be generated which requires SSHEncryptionPassword.")
    else:
        # we already have a key with this name. Keep it?
        # We probs want to delete the key when we remove the stack...
        pass
    return ret


def generate_node_keys(NConsensusNodes, NamePrefix, **kwargs) -> list:
    _e = get_some_entropy()
    keys = []
    for i in range(20):  # max nConsensusNodes
        _h = _hash(_e)
        _privkey = '0x' + binascii.hexlify(_h[:32])
        _e = _h[32:]
        assert len(_e) >= 32
        keys.append({'Name': "{}-nodekey-consensus-{}".format(NamePrefix, i),
                     'Description': "Private key for consensus node #{}".format(i),
                     'Value': _privkey, 'Type': 'SecureString'})
    return keys


def save_node_keys(keys):
    ssm = boto3.client('ssm')
    for k in keys:
        ssm.put_parameter(**k)
    return {'GeneratedKeys': True}


def gen_network_id(**kwargs):
    return { 'NetworkId': secrets.randbits(32) }


def gen_eth_stats_secret(**kwargs):
    return {
        'EthStatsSecret': ''.join([secrets.choice(string.ascii_letters + string.digits) for _ in range(20)])
    }


def upload_chain_config(StaticBucketName, **kwargs):
    chainspec = ''
    ret = { 'ChainSpec': chainspec }
    s3 = boto3.client('s3')
    s3.put_object(Key='chain/chainspec.toml', Body=chainspec, Bucket=StaticBucketName, ACL='public-read')
    return ret
