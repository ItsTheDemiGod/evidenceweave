"""Small statistics helpers for the evaluation scripts."""
from math import sqrt


def wilson(k: int, n: int, z: float = 1.96):
    """Wilson score interval (lo, hi) for k successes in n trials; (None, None) when n == 0."""
    if n <= 0:
        return (None, None)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, (c - h) / d), min(1.0, (c + h) / d))


def rate(k: int, n: int) -> dict:
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": (k / n if n else None), "ci_lo": lo, "ci_hi": hi}
