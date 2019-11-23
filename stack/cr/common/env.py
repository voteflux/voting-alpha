import os


defaults = {
    'AWS_REGION': 'ap-southeast-2',
    'DEBUG': False
}


def get_env(var_name, default=None):
    return os.environ.get(var_name, default=default or defaults.get(var_name, None))
