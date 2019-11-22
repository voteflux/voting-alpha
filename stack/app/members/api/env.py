import os

from attrdict import AttrDict

env = AttrDict(os.environ)
env.AWS_REGION = 'ap-southeast-2'
