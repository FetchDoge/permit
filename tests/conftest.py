"""Shared pytest hooks for the Permit suite.

Sandbox-live tests (marked ``sandbox_live``) hit the real PayPal sandbox and
must never run in CI without explicit credentials. They are skipped unless
both ``PERMIT_PAYPAL_CLIENT_ID`` and ``PERMIT_PAYPAL_CLIENT_SECRET`` are set.
No secrets are required for the default mock-rail suite.
"""

from __future__ import annotations

import os
import tempfile

import pytest

# Stable HMAC key for the suite (outside the DB). Production must set its own.
# Minimum 32 bytes. Demo-key fallback is NOT used here — env is set explicitly.
_TEST_MAC_KEY = "test-retry-rate-mac-key-NOT-FOR-PRODUCTION"  # 42 bytes
os.environ.setdefault("PERMIT_RETRY_RATE_MAC_KEY", _TEST_MAC_KEY)

# High-water sidecar (outside the DB). Shared across the suite / spawn workers.
_HW_DIR = tempfile.mkdtemp(prefix="permit-retry-rate-hw-")
_HW_FILE = os.path.join(_HW_DIR, "retry_rate.hw")
os.environ.setdefault("PERMIT_RETRY_RATE_MAC_HW_FILE", _HW_FILE)

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


@pytest.fixture(autouse=True)
def _isolate_retry_rate_hw_dir():
    """Reset HW path to the suite default and wipe counter files each test."""
    import permit.retry_rate_store as rrs

    def _wipe(base: str | None) -> None:
        if not base:
            return
        root = base if os.path.isdir(base) else base + ".d"
        if not os.path.isdir(root):
            return
        for name in os.listdir(root):
            if name.endswith(".hw") or name.endswith(".lock") or name.startswith(
                ".hwtmp."
            ):
                try:
                    os.remove(os.path.join(root, name))
                except OSError:
                    pass

    # Always restore the suite HW root so a prior test's per-ledger override
    # cannot leak orphans into the next SqliteLedger open.
    os.environ["PERMIT_RETRY_RATE_MAC_HW_FILE"] = _HW_FILE
    _wipe(_HW_FILE)
    rrs.clear_retry_rate_mac_key_cache()
    os.environ.setdefault("PERMIT_RETRY_RATE_MAC_KEY", _TEST_MAC_KEY)
    try:
        rrs.load_retry_rate_mac_key(refresh=True)
    except Exception:
        pass
    yield
    _wipe(os.environ.get("PERMIT_RETRY_RATE_MAC_HW_FILE"))
    os.environ["PERMIT_RETRY_RATE_MAC_HW_FILE"] = _HW_FILE
    rrs.clear_retry_rate_mac_key_cache()


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
