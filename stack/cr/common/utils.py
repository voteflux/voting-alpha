import itertools


def chunk(xs, n):
    return list([xs[i * n:(i + 1) * n] for i in range(len(xs) // n + 1)])
