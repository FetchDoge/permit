"""REA seq 1854: kill survived mutants on durable demo-key hardening.

Each test fails if the named defence is dropped. A companion sweep script
(see test_mutant_sweep_report / scripts) re-applies the mutants and counts
kills.
"""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path
from unittest import mock

import pytest

import settlement.verifier as verifier_mod
from settlement.verifier import load_or_create_demo_key

MIN = 32


def test_mutant_nofollow_symlink_swapped_after_precheck(monkeypatch, tmp_path):
    """Dropping O_NOFOLLOW on the read: symlink swapped in after pre-check."""
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    path = tmp_path / "key.acceptance_key"
    target = tmp_path / "target.key"
    target.write_bytes(os.urandom(MIN))
    os.chmod(target, 0o600)
    path.write_bytes(os.urandom(MIN))
    os.chmod(path, 0o600)

    real_reject = verifier_mod._reject_foreign_demo_key_owner

    def swap_after_precheck(key_path):
        real_reject(key_path)
        # TOCTOU: replace the regular file with a symlink after lstat/owner.
        os.unlink(key_path)
        os.symlink(target, key_path)

    monkeypatch.setattr(
        verifier_mod, "_reject_foreign_demo_key_owner", swap_after_precheck
    )
    with pytest.raises(ValueError, match="must not be a symlink"):
        load_or_create_demo_key(path)


def test_mutant_o_excl_required_on_create(monkeypatch, tmp_path):
    """Dropping O_EXCL on create: spy asserts O_EXCL is passed to os.open."""
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    path = tmp_path / "new.acceptance_key"
    flags_seen: list[int] = []
    real_open = verifier_mod._os.open

    def spy_open(p, flags, mode=0o777):
        flags_seen.append(flags)
        return real_open(p, flags, mode)

    monkeypatch.setattr(verifier_mod._os, "open", spy_open)
    load_or_create_demo_key(path)
    assert flags_seen, "expected at least one os.open during create"
    assert any(f & os.O_EXCL for f in flags_seen), (
        f"O_EXCL missing from create opens: {flags_seen!r}"
    )
    assert any(f & os.O_CREAT for f in flags_seen)


def test_mutant_file_and_dir_fsync_order(monkeypatch, tmp_path):
    """Dropping file/dir fsync: spy asserts file fsync then directory fsync."""
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    path = tmp_path / "sync.acceptance_key"
    events: list[str] = []
    real_fsync = verifier_mod._os.fsync
    real_fsync_dir = verifier_mod._fsync_dir

    def spy_fsync(fd):
        events.append("file_fsync")
        return real_fsync(fd)

    def spy_fsync_dir(dir_path):
        events.append("dir_fsync")
        return real_fsync_dir(dir_path)

    monkeypatch.setattr(verifier_mod._os, "fsync", spy_fsync)
    monkeypatch.setattr(verifier_mod, "_fsync_dir", spy_fsync_dir)
    load_or_create_demo_key(path)
    assert "file_fsync" in events, events
    assert "dir_fsync" in events, events
    assert events.index("file_fsync") < events.index("dir_fsync"), events


def test_mutant_fchmod_0600_on_create(monkeypatch, tmp_path):
    """Dropping chmod/fchmod: umask would leave non-0600 without fchmod."""
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    path = tmp_path / "mode.acceptance_key"
    old = os.umask(0o177)  # open(..., 0o600) → 0o400 without fchmod
    try:
        key, mode = load_or_create_demo_key(path)
    finally:
        os.umask(old)
    assert mode == 0o600
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert len(key) == MIN


def test_mutant_precheck_oserror_mapped_clean(monkeypatch, tmp_path):
    """Dropping pre-check error mapping: lstat OSError must become ValueError."""
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    path = tmp_path / "io.acceptance_key"
    path.write_bytes(os.urandom(MIN))
    os.chmod(path, 0o600)

    def boom(_p):
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(verifier_mod._os, "lstat", boom)
    with pytest.raises(ValueError, match="cannot be opened") as excinfo:
        load_or_create_demo_key(path)
    assert "PermissionError" not in type(excinfo.value).__name__
    assert not isinstance(excinfo.value, OSError) or isinstance(
        excinfo.value, ValueError
    )


def test_mutant_symlink_error_message_text(monkeypatch, tmp_path):
    """Symlink refusal must use the exact message text."""
    monkeypatch.delenv("PERMIT_ACCEPTANCE_KEY", raising=False)
    real = tmp_path / "real.key"
    link = tmp_path / "link.acceptance_key"
    real.write_bytes(os.urandom(MIN))
    os.chmod(real, 0o600)
    link.symlink_to(real)
    with pytest.raises(ValueError, match="must not be a symlink") as excinfo:
        load_or_create_demo_key(link)
    assert str(excinfo.value) == (
        f"demo acceptance key at {link} must not be a symlink"
    )
