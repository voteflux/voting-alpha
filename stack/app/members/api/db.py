import os
import uuid

import eth_utils
import web3
from .models import SessionState, SessionModel


def new_session(email_addr, eth_address):
    session_token = eth_utils.crypto.keccak_256(get_some_entropy())
    SessionModel.from_raw_data({
        'session_id': uuid.uuid4(),
        'session_token_hash':
    })
