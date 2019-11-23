import datetime
import logging
from base64 import b64encode

logging.basicConfig(level=logging.INFO)


def mk_logger(name) -> logging.Logger:
    log = logging.getLogger(name)
    log.setLevel(logging.INFO)
    return log


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def bs_to_base64(bs: bytes) -> str:
    return b64encode(bs).decode()
