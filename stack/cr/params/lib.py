import boto3


def generate_ec2_key(ShouldGenEc2SSHKey: bool, KeyPairName: str, AdminEmail, **kwargs):
    ret = { 'CreatedEc2KeyPair': False }
    ec2 = boto3.client('ec2')
    kps = ec2.describe_key_pairs()
    if sum([kp['KeyName'] == KeyPairName for kp in kps['KeyPairs']]) == 0:
        ret['CreatedEc2KeyPair'] = True
        if ShouldGenEc2SSHKey:
            raise Exception("ssh key gen not supported yet")
            ssh_pem = ec2.create_key_pair(KeyName=KeyPairName)['KeyMaterial']
            sns = boto3.client('sns')
        elif 'SSHKey' in kwargs:
            ec2.import_key_pair(KeyName=KeyPairName, PublicKeyMaterial=bytes(kwargs['SSHKey']))
        else:
            raise Exception("`SSHKey` must be provided or an SSH key must be generated.")
    return ret


def generate_node_keys(**kwargs):
    ret = {}
    return ret


def gen_network_id(**kwargs):
    ret = {}
    return ret


def gen_eth_stats_secret(**kwargs):
    ret = {}
    return ret


def upload_chain_config(StaticBucketName, **kwargs):
    ret = {}
    s3 = boto3.client('s3')
    s3.put_object(Key='chain/chainspec.toml', Body='', Bucket=StaticBucketName)
    return ret
