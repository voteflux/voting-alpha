import click


@click.command()
def create_ballots(**kwargs):
    import json
    import os
    from pathlib import Path

    from env import get_env
    from web3 import Web3
    import boto3
    from eth_account import Account
    import hashlib

    def _create_ballots(http_provider, ix_address, democ_hash):
        key_name = "publish"
        priv_key = get_param(f"sv-{NAME_PREFIX}-nodekey-service-{key_name}", WithDecryption=True)
        account = Account.privateKeyToAccount(priv_key)
        print('Loaded account w/ address:', account.address)

        def base_tx():
            return {'from': account.address, 'value': 0, 'gas': 8000000, 'gasPrice': 1}

        w3 = Web3(Web3.HTTPProvider(http_provider))
        print('Balance:', w3.eth.getBalance(account.address))

        # ixAbi = json.loads(load_sc('SVLightIndex.abi.json'))
        # ix = w3.eth.contract(abi=ixAbi, address=ix_address)

        voting_alpha_sc_abi = json.loads(load_sc('apguerrera/VotingAlpha.abi.json'))
        ix = w3.eth.contract(abi=voting_alpha_sc_abi, address=ix_address)
        ix.functions()

    ssm = boto3.client('ssm')

    NAME_PREFIX = get_env('NAME_PREFIX', None)
    NONCE = None

    groups = ['EX', 'SCALE', 'CORP', 'FELLOW', 'IND', 'STUD']
    multi = ['EX', 'SCALE', 'CORP']
    multi_ = ','.join(multi)

    combos = [
        ['EX', 'SCALE', 'CORP'],
    ]

    def get_param(name, **kwargs):
        return ssm.get_parameter(Name=name, **kwargs)['Parameter']['Value']

    def load_sc(filename):
        with open(Path(os.path.dirname(__file__)) / 'sc' / filename, 'r') as f:
            return f.read()

    ballots = [{
        "ballotVersion": 1,
        "ballotInner": {
            "ballotTitle": "Quorum",
            "shortDesc": "This establishes a quorum is present. A minimum of ten (10) members combined from the following classes are required: Digital Exchange Members, Blockchain Scale Up Members, Corporate & Advisory Members.",
            "longDesc": "This establishes a quorum is present. A minimum of ten (10) members combined from the following classes are required: Digital Exchange Members, Blockchain Scale Up Members, Corporate & Advisory Members.",
            "erc20Addr": "0x012a9Db1184C054Ad933aD6A951d925a0004Df8b"
        },
        "optionsVersion": 3,
        "optionsInner": {},
    }]

    # ttt = {
    #   "ballotVersion": 2,
    #   "ballotInner": {
    #     "ballotTitle": "Quorum",
    #     "shortDesc": "This establishes a quorum is present. A minimum of ten (10) members combined from the following classes are required: Digital Exchange Members, Blockchain Scale Up Members, Corporate & Advisory Members.",
    #     "longDesc": "This establishes a quorum is present. A minimum of ten (10) members combined from the following classes are required: Digital Exchange Members, Blockchain Scale Up Members, Corporate & Advisory Members.",
    #     "subgroup": null,
    #     "discussionLink": null,
    #     "encryptionPK": null,
    #     # "erc20"
    #   },
    #   "optionsVersion": 3,
    #   "optionsInner": {
    #     "options": null,
    #     "aux": null
    #   }
    # }

    def sha256_hex(o):
        return '0x' + hashlib.sha256(o).hexdigest()

    # ballots_encoded = list([json.dumps(b).encode() for b in ballots])
    # print(ballots_encoded)
    # hashed = list([sha256_hex(be) for be in ballots_encoded])
    # print(hashed)

    _create_ballots(**kwargs)

