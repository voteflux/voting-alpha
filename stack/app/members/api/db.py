import binascii
import os
import uuid
from base64 import b64encode, b64decode

import boto3

import jwt
import eth_utils
import web3
from attrdict import AttrDict
from lib import _hash, get_some_entropy
from .models import SessionState, SessionModel
from .lib import mk_logger


log = mk_logger('db')
env = AttrDict(os.environ)


def provide_jwt_secret(f):
    def inner(*args, **kwargs):
        ssm = boto3.client('ssm')
        ssm_jwt = f'sv-{env.pNamePrefix}-members-api-jwt-secret'
        try:
            jwt_secret = b64decode(ssm.get_parameter(Name=ssm_jwt, WithDecryption=True)['Parameter']['Value'])
        except Exception as e:
            log.warning(f"GET SSM JWT SECRET EXCEPTION: {e}")
            if "ParameterNotFound" in str(e):
                log.warning(f"Creating and saving JWT secret")
                jwt_secret = os.urandom(32)
                ssm.put_parameter(Name=ssm_jwt, Value=b64encode(jwt_secret), Type='SecureString')
            else:
                raise e
        f(jwt_secret, *args, **kwargs)
    return inner


def hash_up(*args):
    return _hash(b''.join(map(_hash, args)))


def gen_session_anon_id(session_token: str, email_addr: str, eth_address: str):
    return hash_up(session_token, email_addr.lower(), eth_address.lower())


def gen_otp_hash(email_addr: str, eth_address: str, token: str):
    return hash_up(email_addr.lower(), eth_address.lower(), token)


@provide_jwt_secret
def new_session(jwt_secret, email_addr, eth_address):
    session_token = b64encode(get_some_entropy())
    session = SessionModel.from_raw_data({
        'session_id': uuid.uuid4(),
        'session_anon_id': gen_session_anon_id(session_token, email_addr, eth_address),
        'state': SessionState.s010_SENT_OTP_EMAIL,
    })
    jwt.encode({'token': session_token}, )
