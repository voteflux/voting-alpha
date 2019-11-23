import os
from collections import defaultdict

from attrdict import AttrDefault

env = AttrDefault(lambda: None, os.environ)
env.AWS_REGION = env.get('AWS_REGION', 'ap-southeast-2')
