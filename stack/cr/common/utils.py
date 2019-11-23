import base64
import itertools


def chunk(xs, n):
    return list([xs[i * n:(i + 1) * n] for i in range(len(xs) // n + 1)])


def can_base64_decode(msg: str) -> bool:
    try:
        result = base64.b64decode(msg, validate=True)
        return result and True
    except Exception as e:
        return False
