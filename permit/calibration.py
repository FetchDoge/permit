"""
Calibration score (Sol 6.1): an ADVISORY confidence signal for a permit.

ADVISORY ONLY. The score is recorded and displayed; it never decides a
spend. The authority check stays the four clauses in permit/permit.py:

    amount <= remaining AND merchant IN allowlist AND now < expiry
    AND NOT revoked

Nothing in the authority path reads advisory_verdict(); a score of 0 and
a score of 1 produce the same authority decision for the same attempt.

Formula (exactly as specified):

    x  = (remaining/cap, expiry_margin_hours, allowlist_coverage)
    R  = sum_i w_i * |x_i - x*_i| / s_i          (absolute residual)
    c  = 0                        if chain_ok is False
         min(1, n_receipts / n_min) otherwise
    S  = c * exp(-R)                              in [0, 1]

Known gap (G1, open question): the residual is absolute, so a permit that
is BETTER than spec on a clause (e.g. more expiry margin than x*) is
penalised the same as one that falls short.

FIXTURE_* values below are test fixtures, not calibrated values.

Pure and deterministic: no clock, no I/O, no PayPal import.
"""

from __future__ import annotations

import math
from numbers import Real

TAU_DEFAULT = 0.70
N_MIN = 50

# Fixtures (NOT calibrated): spec point, weights, scales for
# x = (remaining/cap, expiry_margin_hours, allowlist_coverage).
FIXTURE_SPEC_X = (1.0, 24.0, 1.0)
FIXTURE_WEIGHTS = (0.5, 0.25, 0.25)
FIXTURE_SCALES = (0.5, 24.0, 0.25)

MEETS = "MEETS"
BELOW = "BELOW"


def _finite_real(name: str, v) -> float:
    if isinstance(v, bool) or not isinstance(v, Real):
        raise ValueError(f"{name} must be a real number, got {type(v).__name__}: {v!r}")
    f = float(v)
    if not math.isfinite(f):
        raise ValueError(f"{name} must be finite, got {v!r}")
    return f


def _vector(name: str, v) -> tuple[float, ...]:
    try:
        items = tuple(v)
    except TypeError:
        raise ValueError(f"{name} must be a sequence of 3 numbers") from None
    if len(items) != 3:
        raise ValueError(f"{name} must have exactly 3 entries, got {len(items)}")
    return tuple(_finite_real(f"{name}[{i}]", x) for i, x in enumerate(items))


def _count(name: str, v, minimum: int) -> int:
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError(f"{name} must be an int, got {type(v).__name__}: {v!r}")
    if v < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {v}")
    return v


def validate_tau(tau) -> float:
    """tau must be a finite real in (0, 1]. Raises ValueError otherwise."""
    t = _finite_real("tau", tau)
    if not (0.0 < t <= 1.0):
        raise ValueError(f"tau must be in (0, 1], got {tau!r}")
    return t


def features(
    remaining_cents: int,
    cap_cents: int,
    expiry_margin_hours,
    allowlist_coverage,
) -> tuple[float, float, float]:
    """
    Build x = (remaining/cap, expiry_margin_hours, allowlist_coverage).
    Money stays in integer cents until this single ratio: cap_cents must be
    an int > 0 (bool and float rejected), remaining_cents an int.
    """
    if isinstance(cap_cents, bool) or not isinstance(cap_cents, int):
        raise ValueError(
            f"cap_cents must be a positive int, got {type(cap_cents).__name__}: {cap_cents!r}"
        )
    if cap_cents <= 0:
        raise ValueError(f"cap_cents must be > 0, got {cap_cents}")
    if isinstance(remaining_cents, bool) or not isinstance(remaining_cents, int):
        raise ValueError(
            f"remaining_cents must be an int, got {type(remaining_cents).__name__}: {remaining_cents!r}"
        )
    return (
        remaining_cents / cap_cents,
        _finite_real("expiry_margin_hours", expiry_margin_hours),
        _finite_real("allowlist_coverage", allowlist_coverage),
    )


def score(
    permit_x,
    spec_x,
    weights,
    scales,
    n_receipts: int,
    chain_ok: bool,
    n_min: int = N_MIN,
) -> float:
    """
    S = c * exp(-R). Returns a float in [0, 1]. Raises ValueError on any
    invalid input (non-finite values, weights negative or not summing to 1,
    a scale <= 0, n_receipts not an int >= 0, n_min not an int >= 1,
    chain_ok not a bool).
    """
    x = _vector("permit_x", permit_x)
    xs = _vector("spec_x", spec_x)
    w = _vector("weights", weights)
    s = _vector("scales", scales)
    if any(wi < 0 for wi in w):
        raise ValueError(f"weights must be non-negative, got {w}")
    if not math.isclose(sum(w), 1.0, rel_tol=1e-9, abs_tol=1e-12):
        raise ValueError(f"weights must sum to 1, got sum {sum(w)!r}")
    if any(si <= 0 for si in s):
        raise ValueError(f"every scale must be > 0, got {s}")
    n = _count("n_receipts", n_receipts, 0)
    nm = _count("n_min", n_min, 1)
    if not isinstance(chain_ok, bool):
        raise ValueError(f"chain_ok must be a bool, got {type(chain_ok).__name__}")

    # Tampered chain: confidence is zero, whatever the residual.
    if chain_ok is False:
        return 0.0
    c = min(1.0, n / nm)
    if c == 0.0:
        return 0.0

    r = 0.0
    for xi, xsi, wi, si in zip(x, xs, w, s):
        if wi == 0.0:
            continue  # zero weight contributes nothing (avoids 0 * inf)
        r += wi * abs(xi - xsi) / si
    if math.isnan(r):
        raise ValueError("residual is not a number")
    S = c * math.exp(-r)  # exp(-inf) == 0.0
    # Clamp guards float edge cases; mathematically S is already in [0, 1].
    return min(1.0, max(0.0, S))


def advisory_verdict(S, tau) -> str:
    """
    'MEETS' if S >= tau else 'BELOW'. Purely informational: the authority
    check never consults it, and 'BELOW' never blocks a spend.
    """
    s = _finite_real("S", S)
    if not (0.0 <= s <= 1.0):
        raise ValueError(f"S must be in [0, 1], got {S!r}")
    return MEETS if s >= validate_tau(tau) else BELOW
