import datetime
import json
import os
import sys
import time

import boto3

from .bootstrap import *

import jwt
from eth_account import Account
from eth_account.messages import encode_defunct, SignableMessage
import eth_utils
from api.exceptions import LambdaError
from attrdict import AttrDict
from hexbytes import HexBytes
from pymonad.Maybe import Nothing
from pynamodb.attributes import BooleanAttribute, MapAttribute
from utils import can_base64_decode
from web3 import Web3, HTTPProvider
from .common.lib import _hash
from .send_mail import send_email, format_backup
from .db import new_session, gen_otp_hash, gen_otp_and_otp_hash, gen_session_anon_id, hash_up
from .models import SessionModel, OtpState, SessionState, TimestampMap, VoterEnrolmentModel
from .handler_utils import post_common, Message, RequestTypes, verify, ensure_session, \
    verifyDictKeys, encode_and_sign_msg
from .lib import mk_logger, now, bs_to_base64
from .env import get_env

log = mk_logger('members-onboard')
LAST_GENERATED_OTP = None


ssm = boto3.client('ssm')


# 8am Monday 25th
starting_timestamp = 1574629200

# 7:30am Wednesday 4th December 2019 ADST
ending_timestamp = 1575405000


@post_common
@ensure_session
async def message_handler(event, ctx, msg: Message, eth_address, jwt_claim, session):
    _h = {
        RequestTypes.ESTABLISH_SESSION.value: establish_session,
        RequestTypes.PROVIDE_OTP.value: provide_otp,
        RequestTypes.RESEND_OTP.value: resend_otp,
        RequestTypes.PROVIDE_BACKUP.value: send_backup_email,
        RequestTypes.FINAL_CONFIRM.value: confirm_and_finalize_onboarding,
    }
    log.info(f"Running {msg.request} for {eth_address}")
    return await _h[msg.request](event, ctx, msg, eth_address, jwt_claim, session)


async def establish_session(event, ctx, msg, eth_address, jwt_claim, session, *args, **kwargs):
    global LAST_GENERATED_OTP

    # check times first
    verify(time.time() >= starting_timestamp, 'early rego attempt', 'Cannot register voters before 8am Monday 25th.')
    # verify(time.time() <= ending_timestamp, 'late rego attempt', 'Cannot register voters after 10.45am Monday 25th.')

    verify(verifyDictKeys(msg.payload, ['email_addr', 'address']), 'establish_session: verify session payload')
    verify(eth_address == msg.payload.address, f'verify ethereum addresses match: calc:{eth_address} provided:{msg.payload.address}')
    verify(msg.payload.email_addr.lower() == msg.payload.email_addr, 'email must be lowercase')

    voter_enrolled_m = VoterEnrolmentModel.get_maybe(msg.payload.email_addr)
    verify(voter_enrolled_m != Nothing, 'member does not exist in db', 'Email not found.')
    voter_enrolled = voter_enrolled_m.getValue()
    verify(voter_enrolled.claimed is False, 'member claimed vote already', 'Voting rights already claimed.')

    sess = await new_session(msg.payload.email_addr, eth_address)
    jwt_token, session = sess
    claim = AttrDict(jwt.decode(jwt_token, algorithms=['HS256'], verify=False))
    otp, otp_hash = gen_otp_and_otp_hash(msg.payload.email_addr, eth_address, claim.token)

    session.update([
        SessionModel.otp.set(OtpState(
            not_valid_before=datetime.datetime.now(),
            not_valid_after=datetime.datetime.now() + datetime.timedelta(minutes=15),
            otp_hash=otp_hash,
            succeeded=False,
        ))
    ])

    LAST_GENERATED_OTP = otp

    resp = send_email(
        source=get_env('pAdminEmail', 'test@api.secure.vote'),
        to_addrs=[msg.payload.email_addr],
        subject="Confirm your Identity for the Blockchain Australia AGM",
        body_txt=f"""
Your OTP is:

{otp}
""")
    if not resp:
        raise LambdaError(500, "Failed to send email OTP email")
    else:
        session.update([
            SessionModel.otp.emails_sent_at.set(SessionModel.otp.emails_sent_at.prepend([TimestampMap()])),
            SessionModel.state.set(SessionState.s010_SENT_OTP_EMAIL)
        ])
        return {'result': 'success', 'jwt': jwt_token}


async def resend_otp(event, ctx, msg, eth_address, jwt_claim, session, *args, **kwargs):
    raise LambdaError(555, 'unimplemented')


"""
Example payload:
{
  // NOTE: the value of 'msg' below is a string, not an object.
  'msg': '{
    "payload": {
      "email_addr": "max-test@xk.io", 
      "otp": "77549721"
    }, 
    "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbiI6IkZvdXVBRVlJWEl3ZlBmOFQxMUJQcEE9PSIsImFub25faWQiOiJCWnd2T1V1VkhkWXU5TUtXYWVocytGUVhuUzhCTXJGSDhaUm1Qbzg3aWZydUdwWkhEN2dDdzM0WG1idVB0N3hQQ2N4WUVmZFVRQ2xEZWlNaklMWW54QT09In0.Wxe5hDmZgDRlT1sZ2cdinuw8RdugfC5aIptTRVEme14", 
    "request": "PROVIDE_OTP"
  }', 
  'sig': '0xaaefcc8170a923a5ed4c3870cd2a7fa8185f5982ccdb0cc907f0577b7c104c2042e45e8e50b1fe733a9c67e5ee48047fab83ecf6b52e01c8156628c21a998e201b'
}

"""
async def provide_otp(event, ctx, msg, eth_address, jwt_claim, session, *args, **kwargs):
    verify(verifyDictKeys(msg.payload, ['email_addr', 'otp']), 'payload keys')
    verify(session.state == SessionState.s010_SENT_OTP_EMAIL, 'session state is as expected')
    verify(msg.payload.email_addr.lower() == msg.payload.email_addr, 'email must be lowercase')

    voter_enrolled_m = VoterEnrolmentModel.get_maybe(msg.payload.email_addr)
    verify(voter_enrolled_m != Nothing, 'member does not exist in db', 'Email not found.')
    voter_enrolled = voter_enrolled_m.getValue()
    verify(voter_enrolled.claimed is False, 'member claimed vote already', 'Voting rights already claimed.')

    if session.otp.incorrect_attempts >= 10:
        raise LambdaError(429, 'too many incorrect otp attempts', {'error': "TOO_MANY_OTP_ATTEMPTS"})

    otp_hash = gen_otp_hash(msg.payload.email_addr, eth_address, jwt_claim.token, msg.payload.otp)
    if bs_to_base64(otp_hash) != session.otp.otp_hash.decode():
        session.update([SessionModel.otp.incorrect_attempts.set(SessionModel.otp.incorrect_attempts + 1)])
        if session.otp.incorrect_attempts >= 10:
            raise LambdaError(429, 'too many incorrect otp attempts', {'error': "TOO_MANY_OTP_ATTEMPTS"})
        raise LambdaError(422, "otp hash didn't match", {'error': "OTP_MISMATCH"})

    session.update([
        SessionModel.otp.succeeded.set(SessionModel.otp.succeeded.set(True)),
        SessionModel.state.set(SessionState.s020_CONFIRMED_OTP)
    ])

    return {'result': 'success'}


'''
Example payload:
{
  'msg': '{
    "payload": {
      "email_addr": "max-test@xk.io", 
      "encrypted_backup": "nDvW7Rik5IsZoKO7c...(lots of bytes)...A5y98TCkqiLPw="
    }, 
    "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbiI6IkZvdXVBRVlJWEl3ZlBmOFQxMUJQcEE9PSIsImFub25faWQiOiJCWnd2T1V1VkhkWXU5TUtXYWVocytGUVhuUzhCTXJGSDhaUm1Qbzg3aWZydUdwWkhEN2dDdzM0WG1idVB0N3hQQ2N4WUVmZFVRQ2xEZWlNaklMWW54QT09In0.Wxe5hDmZgDRlT1sZ2cdinuw8RdugfC5aIptTRVEme14",
    "request": "PROVIDE_BACKUP"
  }', 
  'sig': '0x7faf86494a9c882be60105c16f0e701043797481831762646709b87301e5130e13568d1c36ac85b9976545c23fdaba135f68c7fefa275a41b30c51ee66456eda1c'
}
'''
async def send_backup_email(event, ctx, msg, eth_address, jwt_claim, session, *args, **kwargs):
    verify(verifyDictKeys(msg.payload, ['email_addr', 'encrypted_backup']), 'payload keys')
    verify(session.state == SessionState.s020_CONFIRMED_OTP, 'expected state')
    verify(msg.payload.email_addr.lower() == msg.payload.email_addr, 'email must be lowercase')
    verify(len(msg.payload.encrypted_backup) < 2000, 'expected size of backup')
    verify(can_base64_decode(msg.payload.encrypted_backup), 'backup is base64 encoded')

    voter_enrolled_m = VoterEnrolmentModel.get_maybe(msg.payload.email_addr)
    verify(voter_enrolled_m != Nothing, 'member does not exist in db', 'Email not found.')
    voter_enrolled = voter_enrolled_m.getValue()
    verify(voter_enrolled.claimed is False, 'member claimed vote already', 'Voting rights already claimed.')

    send_email(to_addrs=[msg.payload.email_addr], subject="Blockchain Australia AGM Elections Voting Identity Backup",
               body_txt=f"""
Below you will find a backup of your voting identity for use in the Blockchain Australia 2019 AGM.
Combined with the password shown to you during the registration stage, this backup provides an
important means of support, audit, and dispute resolution if such needs would ever arise.

It is important you retain the password shown to you on your voting device.

{format_backup(msg.payload.encrypted_backup)}
""")

    backup_hash = _hash(msg.payload.encrypted_backup.encode())

    session.update([
        SessionModel.state.set(SessionState.s030_SENT_BACKUP_EMAIL),
        SessionModel.backup_hash.set(backup_hash)
    ])
    return {'result': 'success'}


def get_ssm_param(name, decode_json=False, with_decryption=False):
    try:
        value = ssm.get_parameter(Name=name, WithDecryption=with_decryption)['Parameter']['Value']
    except Exception as e:
        log.warning(f"Error during get_parameter(Name='{name}'): {repr(e)}")
        return None
    if decode_json:
        value = json.loads(value)
    return value


MEMBERSHIP_C_ABI = [{"constant":False,"inputs":[{"name":"votingAddr","type":"address"},{"name":"weight","type":"uint32"},{"name":"startTime","type":"uint48"},{"name":"endTime","type":"uint48"}],"name":"setMember","outputs":[],"payable":False,"stateMutability":"nonpayable","type":"function"}]
GET_BALANCE_ABI = [{"constant":True,"inputs":[{"name":"v","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"payable":False,"stateMutability":"view","type":"function"}]


def lookup_group_contract(group):
    log.info(f"Env value for pVoterGroupToAddressMapJson: {get_env('pVoterGroupToAddressMapJson')} || {repr(get_env('pVoterGroupToAddressMapJson'))}")
    log.info(f"Group provided: {group}, {repr(group)}, {type(group)}")
    group_map = json.loads(get_env('pVoterGroupToAddressMapJson'))
    log.info(f"Result of json.loads: {type(group_map)} {group_map}")
    # if len(group_map) == 0 or type(group_map) is not dict:
    return group_map.get(group)


def mk_weighting_allocation(w3, my_addr, to_addr, group, weight):
    log.info(f'mk_weighting_allocation: {w3}, {my_addr}, {to_addr}, {group}, {weight}')
    log.info(f'mk_weighting_allocation: {w3}, {repr(my_addr)}, {repr(to_addr)}, {repr(group)}, {repr(weight)}')
    membership_addr = lookup_group_contract(group)
    c = w3.eth.contract(address=membership_addr, abi=MEMBERSHIP_C_ABI)
    tx = c.functions.setMember(to_addr, weight, 1572526800, 1604149200).buildTransaction({'from': my_addr, 'gas': 8000000, 'gasPrice': 1})
    return tx


class OnboardingException(Exception):
    pass


async def confirm_and_finalize_onboarding(event, ctx, msg, eth_address, jwt_claim, session, *args, **kwargs):
    verify(verifyDictKeys(msg.payload, ['email_addr']), 'payload keys')
    verify(msg.payload.email_addr.lower() == msg.payload.email_addr, 'email must be lowercase')
    verify(session.state == SessionState.s030_SENT_BACKUP_EMAIL, 'expected state')

    voter_enrolled_m = VoterEnrolmentModel.get_maybe(msg.payload.email_addr)
    verify(voter_enrolled_m != Nothing, 'member does not exist in db', 'Email not found.')
    voter_enrolled = voter_enrolled_m.getValue()
    verify(voter_enrolled.claimed is False, 'member claimed vote already', 'Voting rights already claimed.')
    verify(time.time() <= ending_timestamp, 'late rego attempt', 'Cannot register voters after 10.45am Monday 25th.')

    finished_web3 = False

    # setup
    try:
        priv_key = get_ssm_param(f"sv-{get_env('pNamePrefix')}-nodekey-service-publish", with_decryption=True)
        account = Account.privateKeyToAccount(priv_key)
        my_addr = account.address
        w3 = Web3(HTTPProvider(get_env('pEthHost')))
        voter_weights: MapAttribute = voter_enrolled.weightingMap
        unsigned_transactions = [mk_weighting_allocation(w3, my_addr, eth_address, g, w) for (g, w) in
                                 voter_weights.attribute_values.items() if w > 0]
        unsigned_transactions.append(
            {'from': my_addr, 'to': eth_address, 'value': w3.toWei(1, 'ether'), 'gas': 8000000, 'gasPrice': 1})
        log.info(f'unsigned transactions: {json.dumps(unsigned_transactions, indent=2)}')
    except Exception as e:
        log.error(f'got exception during finalization setup: {e}')
        raise LambdaError(500, msg=f"Unexpected error: {e}", client_response="Unexpected error occured. Please try again.")

    # main
    try:
        start = datetime.datetime.now().isoformat()
        log.info(f"main start: {start}")
        # we can use the condition to avoid a race condition, but need to do this first.
        voter_enrolled.update([
            VoterEnrolmentModel.claimed.set(True)
        ], condition=VoterEnrolmentModel.claimed == False)

        out_txs = {}
        txids = []
        for unsigned_tx in unsigned_transactions:
            next_nonce = w3.eth.getTransactionCount(my_addr)
            # txs = list([dict(nonce=next_nonce + i, **prev_tx) for (i, prev_tx) in enumerate(unsigned_transactions)])
            raw_tx = account.signTransaction(dict(nonce=next_nonce, **unsigned_tx)).rawTransaction
            # raw_txs = list([account.signTransaction(tx).rawTransaction for tx in txs])
            txid = w3.eth.sendRawTransaction(raw_tx)
            txids.append(txid)
            # txids = list([w3.eth.sendRawTransaction(tx) for tx in raw_txs])
            w3.eth.waitForTransactionReceipt(txid, poll_latency=0.05)
            log.info(f'confirmed: {txid}')
            # await_all = list([w3.eth.waitForTransactionReceipt(txid) for txid in txids])
            txr = w3.eth.getTransactionReceipt(txid)
            out_txs[txid] = txr
            # txrs = list([w3.eth.getTransactionReceipt(txid) for txid in txids])
            # if any([txr['status'] == 0 for txr in txrs]):
            if txr['status'] == 0:
                raise OnboardingException()

        log.info(f'first txid in out_txs: {out_txs[txids[0]]}')
        log.info(f'last txid in out_txs: {out_txs[txids[-1]]}')

        session.update([
            SessionModel.state.set(SessionState.s040_MADE_ID_CONF_TX),
            # SessionModel.tx_proof.set(hash_up(membership_txid, eth_address, msg.payload.email_addr, jwt_claim.token))
        ])

        log.info(f"main start: {start}")
        log.info(f"main end: {datetime.datetime.now().isoformat()}")
        return {'result': 'success', 'txids': ','.join(txid.hex() for txid in txids)}
    except Exception as e:
        # this would be bad, need to have the above as atomic as possible.
        log.error(e)
        if "An error occurred (ConditionalCheckFailedException)" in str(e):
            # this means we couldn't update the enrolment table with the claim
            pass
        raise LambdaError(400, {'result': 'failure', 'exception': [str(e), repr(e)]})


async def test_establish_session():
    addr = '0x1234'
    r = await establish_session('', '', AttrDict(payload={'email_addr': 'max-test@xk.io', 'address': addr}), addr, AttrDict(token='asdf'))
    print(r)


def mk_msg(msg_to_sign, sig):
    return {'body': {'msg': msg_to_sign.body.decode(), 'sig': sig.hex()}}


def test_establish_session_via_handler():
    if get_env('VOTING_ALPHA_TEST_ENV', '') != "True":
        log.error("set VOTING_ALPHA_TEST_ENV to 'True' to test.")
        sys.exit(1)

    global LAST_GENERATED_OTP

    ctx = AttrDict(loop='loop')
    acct = Account.privateKeyToAccount(_hash(b'hello')[:32])
    log.info(f"tests using account {acct.address} with privkey {acct.privateKey}")
    test_email_addr = 'test-ba-123@xk.io'

    VoterEnrolmentModel(
        email_addr=test_email_addr,
        first_name="max",
        weightingMap={'EX': 0, 'SCALE': 1, 'CORP': 1, 'FELLOW': 3, 'IND': 1, 'STUD': 0},
        claimed=False
    ).save()

    def test_email(_email_addr, expected_status: int, expected_error_msg: str = None):
        msg = AttrDict(
            payload={'email_addr': _email_addr, 'address': acct.address},
            request=RequestTypes.ESTABLISH_SESSION.value
        )
        msg_to_sign, full_msg, signed = encode_and_sign_msg(msg, acct)

        sig: HexBytes = signed.signature
        # r looks like a coroutine but isn't (due to lambda library)
        r = message_handler(mk_msg(msg_to_sign, sig), ctx)
        # if status==200 and we expect that it's all g
        if not (r['statusCode'] == 200 and expected_status == 200):
            print(r)
            raise Exception(f"should have failed: expected: {(expected_status, expected_error_msg)}; got: {r}")

    # maybe we should think about using this one day
    # test_email('definitely_doesnt_exist', expected_status=444)

    for expect_suceed, email_addr in [(False, 'mAX-test@xk.io'), (True, test_email_addr)]:
        msg = AttrDict(
            payload={'email_addr': email_addr, 'address': acct.address},
            request=RequestTypes.ESTABLISH_SESSION.value
        )
        msg_to_sign, full_msg, signed = encode_and_sign_msg(msg, acct)

        print(signed)
        print(msg_to_sign)
        # print('recover msg', Account.recover_message(msg_to_sign, signature=signed.signature))
        # print('recover hash1', Account.recoverHash(signed.messageHash, signature=signed.signature))
        # print('recover hash2', Account.recoverHash(eth_utils.keccak(b'\x19' + full_msg), signature=signed.signature))

        sig: HexBytes = signed.signature
        r = message_handler(mk_msg(msg_to_sign, sig), ctx)
        print(r)
        if (r['statusCode'] == 200) != expect_suceed:
            raise Exception("we should have failed here.")

    body = AttrDict(json.loads(r['body']))
    jwt_token = body.jwt
    otp = LAST_GENERATED_OTP

    msg_2, _, sig_2 = encode_and_sign_msg(AttrDict(
        payload={'email_addr': test_email_addr, 'otp': otp}, jwt=jwt_token,
        request=RequestTypes.PROVIDE_OTP.value
    ), acct)

    r = message_handler(mk_msg(msg_2, sig_2.signature), ctx)
    print(r)

    encrypted_backup = bs_to_base64(os.urandom(512))

    msg_3, _, sig_3 = encode_and_sign_msg(AttrDict(
        payload={'email_addr': test_email_addr, 'encrypted_backup': encrypted_backup},
        jwt=jwt_token, request=RequestTypes.PROVIDE_BACKUP.value
    ), acct)

    r = message_handler(mk_msg(msg_3, sig_3.signature), ctx)

    backup_hash = bs_to_base64(_hash(encrypted_backup.encode()))
    msg_4, _, sig_4 = encode_and_sign_msg(AttrDict(
        payload={'email_addr': test_email_addr},  # 'backup_hash': backup_hash
        jwt=jwt_token, request=RequestTypes.FINAL_CONFIRM.value
    ), acct)

    r = message_handler(mk_msg(msg_4, sig_4.signature), ctx)

    print('final done?', r)


def tests(loop):
    # await test_establish_session()
    test_establish_session_via_handler()


if __name__ == "__main__":
    if get_env('VOTING_ALPHA_TEST_ENV', '') != "True":
        log.error("set VOTING_ALPHA_TEST_ENV to 'True' to test.")
        sys.exit(1)
    else:
        tests('')
