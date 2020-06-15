import json
import logging

from .handlers import handle_quickchain_upgrade

log = logging.getLogger(__name__)


def test_shortcut_handler():
    resp = handle_quickchain_upgrade({"body": '{"method": "signup", "payload": { "voterAddr": "0x11" }}'})
    log.info(f"handle_quickchain_upgrade resp: {json.dumps(resp, indent=2)}")
