from attrdict import AttrDict
from .bootstrap import *

from .handlers import message_handler

env = AttrDict(os.environ)
