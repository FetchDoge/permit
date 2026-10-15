"""Shared pytest hooks for the Permit suite.

Sandbox-live tests (marked ``sandbox_live``) hit the real PayPal sandbox and
must never run in CI without explicit credentials. They are skipped unless
both ``PERMIT_PAYPAL_CLIENT_ID`` and ``PERMIT_PAYPAL_CLIENT_SECRET`` are set.
No secrets are required for the default mock-rail suite.
"""

from __future__ import annotations

import os

import pytest

# Test-only acceptance key for the mock-rail suite (issue #35: the library
# has no fallback key, so tests configure one explicitly via env).
os.environ.setdefault(
    "PERMIT_ACCEPTANCE_KEY", "permit-test-only-acceptance-key-0123456789"
)

_SANDBOX_CREDS = (
    os.environ.get("PERMIT_PAYPAL_CLIENT_ID"),
    os.environ.get("PERMIT_PAYPAL_CLIENT_SECRET"),
)
_HAS_SANDBOX_CREDS = all(_SANDBOX_CREDS)


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "sandbox_live: hits PayPal sandbox; skipped unless "
        "PERMIT_PAYPAL_CLIENT_ID and PERMIT_PAYPAL_CLIENT_SECRET are set",
    )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if _HAS_SANDBOX_CREDS:
        return
    skip = pytest.mark.skip(
        reason=(
            "sandbox-live: set PERMIT_PAYPAL_CLIENT_ID and "
            "PERMIT_PAYPAL_CLIENT_SECRET to run against the PayPal sandbox"
        )
    )
    for item in items:
        if item.get_closest_marker("sandbox_live"):
            item.add_marker(skip)
