import asyncio
import datetime
import json

from eth_account.messages import encode_defunct, SignableMessage
import eth_utils
from api.exceptions import LambdaError
from attrdict import AttrDict
from hexbytes import HexBytes
from pymonad.Maybe import Nothing
from .common.lib import _hash
from web3.auto import w3
from .send_mail import send_email
from .db import new_session, gen_otp_hash, gen_otp_and_otp_hash, gen_session_anon_id
from .models import SessionModel, OtpState, SessionState, TimestampMap
from .handler_utils import post_common, Message, RequestTypes, verify, ensure_session, encode_sv_signed_msg, \
    verifyDictKeys, encode_and_sign_msg
from .lib import mk_logger
from .env import env

log = mk_logger('members-onboard')


@post_common
@ensure_session
async def message_handler(event, ctx, msg: Message, eth_address, jwt_claim):
    _h = {
        RequestTypes.ESTABLISH_SESSION.value: establish_session,
        RequestTypes.PROVIDE_OTP.value: provide_otp,
        RequestTypes.RESEND_OTP.value: resend_otp,
    }
    return await _h[msg.request](event, ctx, msg, eth_address, jwt_claim)


async def resend_otp(event, ctx, msg, eth_address, jwt_claim, *args, **kwargs):
    raise LambdaError(555, 'unimplemented')


async def provide_otp(event, ctx, msg, eth_address, jwt_claim, *args, **kwargs):
    verify(verifyDictKeys(msg.payload, ['email_addr', 'otp']), 'payload keys')
    session_anon_id = gen_session_anon_id(jwt_claim.token, msg.payload.email_addr, eth_address)
    session_m = SessionModel.get_maybe(session_anon_id)
    if session_m == Nothing:
        raise LambdaError(404, 'OTP not found.')
    session = session_m.getValue()
    verify(session.state == SessionState.s010_SENT_OTP_EMAIL, 'session state is as expected')
    print(session.to_python())
    print('original msg:', msg)

    raise LambdaError(555, 'unimplemented')


async def establish_session(event, ctx, msg, eth_address, jwt_claim, *args, **kwargs):
    verify(verifyDictKeys(msg.payload, ['email_addr', 'address']), 'establish_session: verify session payload')
    verify(eth_address == msg.payload.address, 'verify ethereum addresses match')

    print(msg, msg.payload.email_addr, eth_address)
    sess = await new_session(msg.payload.email_addr, eth_address)
    print(sess)
    jwt_token, session = sess
    otp, otp_hash = gen_otp_and_otp_hash(msg.payload.email_addr, eth_address, jwt_token)

    session.update([
        SessionModel.otp.set(OtpState(
            not_valid_before=datetime.datetime.now(),
            not_valid_after=datetime.datetime.now() + datetime.timedelta(minutes=15),
            otp_hash=otp_hash,
            succeeded=False,
        ))
    ])
    resp = send_email(source=env.get('pAdminEmail', 'test@api.secure.vote'), to_addrs=[msg.payload.email_addr], subject="Test Email", body_txt=f"""
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
        print('session updated!:', session.to_python())
        return { 'jwt': jwt_token, 'otp_unsafe_todo_remove': otp }









async def test_establish_session():
    addr = '0x1234'
    r = await establish_session('', '', AttrDict(payload={'email_addr': 'max-test@xk.io', 'address': addr}), addr, AttrDict(token='asdf'))
    print(r)


def mk_msg(msg_to_sign, sig):
    return {'body': {'msg': msg_to_sign.body.decode(), 'sig': sig.hex()}}


def test_establish_session_via_handler():
    ctx = AttrDict(loop='loop')
    acct = w3.eth.account.privateKeyToAccount(_hash(b'hello')[:32])
    test_email_addr = 'max-test@xk.io'

    msg = AttrDict(
        payload={'email_addr': test_email_addr, 'address': acct.address},
        request=RequestTypes.ESTABLISH_SESSION.value
    )
    msg_to_sign, full_msg, signed = encode_and_sign_msg(msg, acct)

    print(signed)
    print(msg_to_sign)
    print('recover msg', w3.eth.account.recover_message(msg_to_sign, signature=signed.signature))
    print('recover hash1', w3.eth.account.recoverHash(signed.messageHash, signature=signed.signature))
    print('recover hash2', w3.eth.account.recoverHash(eth_utils.keccak(b'\x19' + full_msg), signature=signed.signature))

    sig: HexBytes = signed.signature
    r = message_handler(mk_msg(msg_to_sign, sig), ctx)
    print(r)

    body = AttrDict(json.loads(r['body']))
    jwt_token = body.jwt
    otp = body.otp_unsafe_todo_remove

    msg_2, _, sig_2 = encode_and_sign_msg(AttrDict(
        payload={'email_addr': test_email_addr, 'otp': otp}, jwt=jwt_token,
        request=RequestTypes.PROVIDE_OTP.value
    ), acct)

    r = message_handler(mk_msg(msg_2, sig_2.signature), ctx)
    print(r)




def tests(loop):
    # await test_establish_session()
    test_establish_session_via_handler()


if __name__ == "__main__":
    tests('')
    # loop = asyncio.new_event_loop()
    # tests(loop)
    # loop.run_forever()

