import datetime
import logging


logging.basicConfig(level=logging.INFO)


def mk_logger(name) -> logging.Logger:
    log = logging.getLogger(name)
    log.setLevel(logging.INFO)
    return log


def now():
    return datetime.datetime.now(datetime.timezone.utc)
