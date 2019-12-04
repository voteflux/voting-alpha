import asyncio

import boto3
import os
import logging
import hashlib

# from mako.template import Template
from utils import chunk
from .env import get_env
from .lib import mk_logger

ses = boto3.client('ses', region_name='ap-southeast-2')
log = mk_logger('email')

default_params = {
    'source': get_env('pAdminEmail', 'elections@api.secure.vote')
}


# def render_factory(path):
#     def inner(format, **params):
#         filename = '.'.join([path, format])
#         return Template(filename=f'{os.path.dirname(__file__)}/email_templates/{filename}').render(**params)
#
#     return inner


failing_email_hashes = [
    "51fcc86d9ca7e66a04edae8f2caca59645445b6d8b06c3dd0a7280fe9e16d33f",
    "adcef7ccb7868b712d3b25f19e7952891d678222fd223579e9a465cab7804dd6"
]


def failure_tform(to_email):
    if do_hash(to_email) in failing_email_hashes:
        a = list(map(lambda s: s.replace('.', '-'), to_email.split('@')))
        return f"max+{a[0]}@secure.vote"


def s256(msg: str) -> str:
    _msg = msg.encode('UTF8') if type(msg) is str else msg
    return hashlib.sha256(_msg).hexdigest()


def do_hash(email):
    return s256(s256(email) + s256(get_env('pHashSalt')))


def send_email(source=None, to_addrs=None, cc_addrs=None, bcc_addrs=None, subject=None, body_txt=None, body_html=None,
               reply_tos=None):
    final_to_addrs = to_addrs + list(filter(lambda e: e is not None, map(failure_tform, to_addrs)))
    log.info(f'Sending email to {final_to_addrs} with subject {subject}')
    email_send_result = ses.send_email(
        Source=source or default_params['source'],
        Destination={
            'ToAddresses': final_to_addrs or [],
            'CcAddresses': cc_addrs or [],
            'BccAddresses': bcc_addrs or [],
        }, Message={
            'Subject': {'Data': subject},
            'Body': {
                'Text': {'Data': body_txt},
                # 'Html': {'Data': body_html or body_txt}
            }
        }, ReplyToAddresses=reply_tos or [source or default_params['source']],
        ConfigurationSetName=get_env('SesConfigurationSetName'))
    log.info(f'Sent email to {to_addrs} with result {email_send_result}')
    return email_send_result


def format_backup(backup: str) -> str:
    stripped_backup = "".join(backup.split())
    hard_wrapped = "\n".join(map(lambda _c: "".join(_c), chunk(stripped_backup, 64)))
    return "\n".join([
        f"-----START VOTER ID BACKUP-----",
        hard_wrapped,
        f"-----END VOTER ID BACKUP-----"
    ])
