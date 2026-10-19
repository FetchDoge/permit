#!/usr/bin/env python3
"""Re-apply survived demo-key mutants and report killed/total (REA seq 1854).

Mutants:
  1. drop O_NOFOLLOW on read open
  2. drop O_EXCL on create
  3. drop file fsync
  4. drop directory fsync
  5. drop fchmod on create
  6. drop pre-check OSError → ValueError mapping (re-raise raw)
  7. soften symlink error message text

Each is applied in-process via monkeypatch, then the matching killer test
runs. Exit 0 only if every mutant is killed.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# (mutant_id, killer_test_nodeid, apply_snippet_that_patches_verifier_mod)
MUTANTS = [
    (
        "drop_O_NOFOLLOW_on_read",
        "tests/test_demo_key_mutants.py::test_mutant_nofollow_symlink_swapped_after_precheck",
        """
        import settlement.verifier as v
        real = v._open_demo_key_readonly
        def open_no_nofollow(key_path):
            v._reject_foreign_demo_key_owner(key_path)
            flags = v._os.O_RDONLY | getattr(v._os, "O_NONBLOCK", 0)  # no NOFOLLOW
            try:
                return v._os.open(key_path, flags)
            except FileNotFoundError:
                raise
            except OSError as exc:
                raise v._key_oserror(key_path, exc) from None
        v._open_demo_key_readonly = open_no_nofollow
        """,
    ),
    (
        "drop_O_EXCL_on_create",
        "tests/test_demo_key_mutants.py::test_mutant_o_excl_required_on_create",
        """
        import settlement.verifier as v
        real = v._create_demo_key_file
        def create_no_excl(key_path):
            key = v._secrets.token_bytes(v.MIN_ACCEPTANCE_KEY_BYTES)
            key_path.parent.mkdir(parents=True, exist_ok=True)
            flags = (
                v._os.O_WRONLY
                | v._os.O_CREAT
                # O_EXCL dropped
                | getattr(v._os, "O_NOFOLLOW", 0)
            )
            try:
                fd = v._os.open(key_path, flags, 0o600)
            except OSError as exc:
                raise v._key_oserror(key_path, exc) from None
            try:
                try:
                    v._os.write(fd, key)
                    v._os.fchmod(fd, 0o600)
                    v._os.fsync(fd)
                except OSError as exc:
                    raise v._key_oserror(key_path, exc) from None
                mode = v._require_demo_key_fstat(fd, key_path)
            finally:
                v._os.close(fd)
            v._fsync_dir(key_path.parent)
            return key, mode
        v._create_demo_key_file = create_no_excl
        # Also patch load_or_create to use mutated create
        real_load = v.load_or_create_demo_key
        def load(path, *, db_nonempty=False):
            key_path = v._Path(path)
            try:
                fd = v._open_demo_key_readonly(key_path)
            except FileNotFoundError:
                if db_nonempty:
                    raise ValueError("missing")
                return create_no_excl(key_path)
            try:
                mode = v._require_demo_key_fstat(fd, key_path)
                v._clear_nonblock(fd)
                key = v._read_exact_demo_key(fd, key_path)
                return key, mode
            finally:
                v._os.close(fd)
        v.load_or_create_demo_key = load
        """,
    ),
    (
        "drop_file_fsync",
        "tests/test_demo_key_mutants.py::test_mutant_file_and_dir_fsync_order",
        """
        import settlement.verifier as v
        real_create = v._create_demo_key_file
        def create_no_file_fsync(key_path):
            key = v._secrets.token_bytes(v.MIN_ACCEPTANCE_KEY_BYTES)
            key_path.parent.mkdir(parents=True, exist_ok=True)
            flags = (
                v._os.O_WRONLY | v._os.O_CREAT | v._os.O_EXCL
                | getattr(v._os, "O_NOFOLLOW", 0)
            )
            fd = v._os.open(key_path, flags, 0o600)
            try:
                v._os.write(fd, key)
                v._os.fchmod(fd, 0o600)
                # file fsync dropped
                mode = v._require_demo_key_fstat(fd, key_path)
            finally:
                v._os.close(fd)
            v._fsync_dir(key_path.parent)
            return key, mode
        v._create_demo_key_file = create_no_file_fsync
        real_load = v.load_or_create_demo_key
        def load(path, *, db_nonempty=False):
            key_path = v._Path(path)
            try:
                fd = v._open_demo_key_readonly(key_path)
            except FileNotFoundError:
                if db_nonempty:
                    raise ValueError("missing")
                return create_no_file_fsync(key_path)
            try:
                mode = v._require_demo_key_fstat(fd, key_path)
                v._clear_nonblock(fd)
                return v._read_exact_demo_key(fd, key_path), mode
            finally:
                v._os.close(fd)
        v.load_or_create_demo_key = load
        """,
    ),
    (
        "drop_dir_fsync",
        "tests/test_demo_key_mutants.py::test_mutant_file_and_dir_fsync_order",
        """
        import settlement.verifier as v
        v._fsync_dir = lambda dir_path: None
        """,
    ),
    (
        "drop_fchmod",
        "tests/test_demo_key_mutants.py::test_mutant_fchmod_0600_on_create",
        """
        import settlement.verifier as v
        def create_no_fchmod(key_path):
            key = v._secrets.token_bytes(v.MIN_ACCEPTANCE_KEY_BYTES)
            key_path.parent.mkdir(parents=True, exist_ok=True)
            flags = (
                v._os.O_WRONLY | v._os.O_CREAT | v._os.O_EXCL
                | getattr(v._os, "O_NOFOLLOW", 0)
            )
            fd = v._os.open(key_path, flags, 0o600)
            try:
                v._os.write(fd, key)
                # fchmod dropped
                v._os.fsync(fd)
                mode = v._require_demo_key_fstat(fd, key_path)
            finally:
                v._os.close(fd)
            v._fsync_dir(key_path.parent)
            return key, mode
        v._create_demo_key_file = create_no_fchmod
        def load(path, *, db_nonempty=False):
            key_path = v._Path(path)
            try:
                fd = v._open_demo_key_readonly(key_path)
            except FileNotFoundError:
                if db_nonempty:
                    raise ValueError("missing")
                return create_no_fchmod(key_path)
            try:
                mode = v._require_demo_key_fstat(fd, key_path)
                v._clear_nonblock(fd)
                return v._read_exact_demo_key(fd, key_path), mode
            finally:
                v._os.close(fd)
        v.load_or_create_demo_key = load
        """,
    ),
    (
        "drop_precheck_oserror_map",
        "tests/test_demo_key_mutants.py::test_mutant_precheck_oserror_mapped_clean",
        """
        import settlement.verifier as v
        def reject_raw(key_path):
            st = v._os.lstat(key_path)  # raw OSError propagates
            if v._stat.S_ISLNK(st.st_mode):
                raise ValueError(
                    f"demo acceptance key at {key_path} must not be a symlink"
                )
            euid = v._os.geteuid()
            if st.st_uid != euid:
                raise ValueError(
                    f"demo acceptance key at {key_path} must be owned by euid "
                    f"{euid} (got uid {st.st_uid})"
                )
        v._reject_foreign_demo_key_owner = reject_raw
        """,
    ),
    (
        "soften_symlink_message",
        "tests/test_demo_key_mutants.py::test_mutant_symlink_error_message_text",
        """
        import settlement.verifier as v
        def reject_soft(key_path):
            try:
                st = v._os.lstat(key_path)
            except FileNotFoundError:
                raise
            except OSError as exc:
                raise v._key_oserror(key_path, exc) from None
            if v._stat.S_ISLNK(st.st_mode):
                raise ValueError(f"bad link at {key_path}")  # softened
            euid = v._os.geteuid()
            if st.st_uid != euid:
                raise ValueError(
                    f"demo acceptance key at {key_path} must be owned by euid "
                    f"{euid} (got uid {st.st_uid})"
                )
        v._reject_foreign_demo_key_owner = reject_soft
        """,
    ),
]


def _run_mutant(mutant_id: str, nodeid: str, apply_src: str) -> bool:
    """Return True if the killer test FAILS under the mutant (mutant killed)."""
    body = textwrap.dedent(
        f"""
        import sys
        sys.path.insert(0, {str(ROOT)!r})
        {textwrap.dedent(apply_src)}
        import pytest
        raise SystemExit(pytest.main(["-q", "--tb=no", {nodeid!r}]))
        """
    )
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
        fh.write(body)
        path = fh.name
    try:
        proc = subprocess.run(
            [sys.executable, path],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
    finally:
        os.unlink(path)
    # Killer test should FAIL under the mutant → non-zero pytest exit.
    killed = proc.returncode != 0
    status = "KILLED" if killed else "SURVIVED"
    print(f"{status:9} {mutant_id} (pytest rc={proc.returncode})")
    if not killed:
        print(proc.stdout[-500:] if proc.stdout else "")
        print(proc.stderr[-500:] if proc.stderr else "")
    return killed


def main() -> int:
    killed = 0
    total = len(MUTANTS)
    for mid, nodeid, apply_src in MUTANTS:
        if _run_mutant(mid, nodeid, apply_src):
            killed += 1
    print(f"MUTANT SWEEP: {killed}/{total} killed")
    return 0 if killed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
