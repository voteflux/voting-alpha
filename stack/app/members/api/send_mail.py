import asyncio

import boto3
import os
import logging

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


def send_email(source=None, to_addrs=None, cc_addrs=None, bcc_addrs=None, subject=None, body_txt=None, body_html=None,
               reply_tos=None):
    return ses.send_email(Source=source or default_params['source'], Destination={
        'ToAddresses': to_addrs or [],
        'CcAddresses': cc_addrs or [],
        'BccAddresses': bcc_addrs or [],
    }, Message={
        'Subject': {'Data': subject},
        'Body': {
            'Text': {'Data': body_txt},
            # 'Html': {'Data': body_html or body_txt}
        }
    }, ReplyToAddresses=reply_tos or [source or default_params['source']])


def format_backup(backup: str) -> str:
    stripped_backup = "".join(backup.split())
    hard_wrapped = "\n".join(map(lambda _c: "".join(_c), chunk(stripped_backup, 64)))
    return "\n".join([
        f"-----START VOTER ID BACKUP-----",
        hard_wrapped,
        f"-----END VOTER ID BACKUP-----"
    ])
