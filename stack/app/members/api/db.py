import binascii
import datetime
import os
import uuid
from base64 import b64encode, b64decode
from typing import List, Union

import six

import boto3

import jwt
import eth_utils
import web3
from attrdict import AttrDict
from hexbytes import HexBytes
from pymonad.Maybe import Nothing
from .common.lib import _hash, get_some_entropy
from pymonad import Maybe
from .models import SessionState, SessionModel, OtpState
from .lib import mk_logger, now, bs_to_base64
from .env import get_env

log = mk_logger('db')


def provide_jwt_secret(f):
    async def inner(*args, **kwargs):
        ssm = boto3.client('ssm')
        ssm_jwt = f'sv-{get_env("pNamePrefix")}-members-api-jwt-secret'
        try:
            jwt_secret = b64decode(ssm.get_parameter(Name=ssm_jwt, WithDecryption=True)['Parameter']['Value'])
        except Exception as e:
            log.warning(f"GET SSM JWT SECRET EXCEPTION: {e}")
            if "ParameterNotFound" in str(e):
                log.warning(f"Creating and saving JWT secret")
                jwt_secret = _hash(os.urandom(32))
                ssm.put_parameter(Name=ssm_jwt, Value=b64encode(jwt_secret).decode(), Type='SecureString')
            else:
                raise e
        return await f(*args, jwt_secret=jwt_secret, **kwargs)
    return inner


def hash_up(*args: Union[str, bytes]) -> bytes:
    return _hash(b''.join(map(lambda a: _hash(a if type(a) in [bytes, HexBytes] else a.encode()), args)))


def gen_session_anon_id(session_token: str, email_addr: str, eth_address: str) -> str:
    return bs_to_base64(hash_up(session_token, email_addr.lower(), eth_address.lower()))


def gen_otp_and_otp_hash(email_addr: str, eth_address: str, token: str):
    otp = f"{int.from_bytes(get_some_entropy()[:5], byteorder='big') % 10**8:0>8d}"
    return otp, gen_otp_hash(email_addr, eth_address, token, otp)


def gen_otp_hash(email_addr: str, eth_address: str, token: str, otp: str) -> bytes:
    print('gen_otp_hash with args:', email_addr, eth_address, token, otp)
    res = hash_up(email_addr.lower(), eth_address.lower(), token, otp)
    print('gen_otp_hash result:', res)
    return res


@provide_jwt_secret
async def new_session(email_addr, eth_address, jwt_secret=None) -> (bytes, SessionModel):
    session_token = bs_to_base64(get_some_entropy()[:16])
    session = SessionModel(
        session_anon_id=gen_session_anon_id(session_token, email_addr, eth_address),
        state=SessionState.s000_NEWLY_CREATED,
        not_valid_after=datetime.datetime.now() + datetime.timedelta(hours=24),
    )
    jwt_token = jwt.encode({'token': session_token, 'anon_id': session.session_anon_id}, jwt_secret, algorithm='HS256').decode()
    session.save()
    return jwt_token, session


@provide_jwt_secret
async def verify_session_token(encoded_token, email_addr, eth_address, jwt_secret=None):
    claim = AttrDict(jwt.decode(encoded_token, jwt_secret, algorithms=['HS256']))
    anon_id = gen_session_anon_id(claim.token, email_addr, eth_address)
    session = SessionModel.get_maybe(anon_id)
    if session == Nothing:
        return None, None
    session = session.getValue()
    session_valid = session.not_valid_after > now() > session.not_valid_before
    log.warning(f"[DEBUG] {dict(session_valid=session_valid, session=session, nva=session.not_valid_after, nvb=session.not_valid_before, claim=claim)}")
    return (claim, session) if session_valid and anon_id == claim.anon_id else (None, None)


def get_session_otp(anon_id):
    return SessionModel.get_maybe(anon_id)
