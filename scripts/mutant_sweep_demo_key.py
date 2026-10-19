#!/usr/bin/env python3
"""Re-apply survived demo-key + REA round-5 mutants; report killed/total.

Demo-key mutants (seq 1854):
  1-7: O_NOFOLLOW, O_EXCL, file/dir fsync, fchmod, precheck map, symlink text

REA round-5 mutants (commitment / meta / rebind / ephemeral):
  8-31: silent rebind, corrupt-meta-as-empty, skip compare after bind,
        fail-open default, rebind without old-key check, etc.

Each is applied in-process via monkeypatch, then the matching killer test
runs. Exit 0 only if every mutant is killed (target: 31/31).
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
                # fchmod dropped — with umask 0o277 mode stays 0400
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
    # ----- REA round 5 (8-31) -----
    (
        "silent_rebind_skip_nonempty_check",
        "tests/test_rea_r5_commitment.py::test_sqlite_nonempty_without_commitment_refuses_silent_rebind",
        """
        import settlement.verifier as v
        from permit.sqlite_ledger import ACCEPTANCE_KEY_COMMITMENT_META
        def ensure_silent(db_ledger, key):
            digest = v.acceptance_key_commitment(key)
            stored = db_ledger.get_meta(ACCEPTANCE_KEY_COMMITMENT_META)
            if stored is None:
                db_ledger.set_meta(ACCEPTANCE_KEY_COMMITMENT_META, digest)
                return  # MUTANT: no nonempty check
            if not v.hmac.compare_digest(stored, digest):
                raise ValueError(v._ROTATION_REFUSE_MSG)
        v.ensure_acceptance_key_commitment = ensure_silent
        """,
    ),
    (
        "durable_silent_rebind_skip_nonempty",
        "tests/test_rea_r5_commitment.py::test_durable_nonempty_missing_meta_refuses_silent_rebind",
        """
        import settlement.verifier as v
        from permit.sqlite_ledger import ACCEPTANCE_KEY_COMMITMENT_META
        def ensure_silent(db_ledger, key):
            digest = v.acceptance_key_commitment(key)
            stored = db_ledger.get_meta(ACCEPTANCE_KEY_COMMITMENT_META)
            if stored is None:
                db_ledger.set_meta(ACCEPTANCE_KEY_COMMITMENT_META, digest)
                return
            if not v.hmac.compare_digest(stored, digest):
                raise ValueError(v._ROTATION_REFUSE_MSG)
        v.ensure_acceptance_key_commitment = ensure_silent
        """,
    ),
    (
        "corrupt_meta_returns_empty",
        "tests/test_rea_r5_commitment.py::test_corrupt_meta_json_refused_not_empty",
        """
        import json
        from permit.durability import DurableLedger
        def mutant_read(self):
            if self._meta_path is None or not self._meta_path.exists():
                return {}
            try:
                raw = json.loads(self._meta_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError, ValueError):
                return {}
            if not isinstance(raw, dict):
                return {}
            return {str(k): str(v) for k, v in raw.items()}
        DurableLedger._read_meta = mutant_read
        """,
    ),
    (
        "empty_meta_file_returns_empty",
        "tests/test_rea_r5_commitment.py::test_empty_meta_json_file_refused",
        """
        import json
        from permit.durability import DurableLedger
        def mutant_read(self):
            if self._meta_path is None or not self._meta_path.exists():
                return {}
            try:
                text = self._meta_path.read_text(encoding="utf-8")
                if not text.strip():
                    return {}
                raw = json.loads(text)
            except (json.JSONDecodeError, OSError, ValueError):
                return {}
            if not isinstance(raw, dict):
                return {}
            return {str(k): str(v) for k, v in raw.items()}
        DurableLedger._read_meta = mutant_read
        """,
    ),
    (
        "fail_open_bind_default",
        "tests/test_rea_r5_commitment.py::test_commitment_required_by_default_not_opt_in",
        """
        import settlement.verifier as v
        def bind_opt_in(ledger, key):
            requires = bool(getattr(ledger, "requires_acceptance_key_commitment", False))
            if not requires:
                return  # MUTANT: fail-open default
            v.ensure_acceptance_key_commitment(ledger, key)
        v._bind_ledger_acceptance_key_commitment = bind_opt_in
        """,
    ),
    (
        "memory_sqlite_still_binds",
        "tests/test_rea_r5_commitment.py::test_memory_sqlite_is_ephemeral",
        """
        import settlement.verifier as v
        def bind_always(ledger, key):
            # MUTANT: ignore ephemeral; always require meta bind
            if not (hasattr(ledger, "get_meta") and hasattr(ledger, "set_meta")):
                raise ValueError("refusing silent skip")
            v.ensure_acceptance_key_commitment(ledger, key)
        v._bind_ledger_acceptance_key_commitment = bind_always
        """,
    ),
    (
        "rebind_skips_old_key_check",
        "tests/test_rea_r5_commitment.py::test_rebind_refused_with_wrong_old_key",
        """
        import settlement.verifier as v
        from permit.sqlite_ledger import ACCEPTANCE_KEY_COMMITMENT_META
        def rebind_no_check(db_ledger, old_key, new_key):
            new = v._coerce_key(new_key)
            new = v._require_valid_key(new, what="new acceptance key")
            # MUTANT: no old-key verification
            db_ledger.set_meta(
                ACCEPTANCE_KEY_COMMITMENT_META,
                v.acceptance_key_commitment(new),
            )
        v.rebind_acceptance_key_commitment = rebind_no_check
        """,
    ),
    (
        "ensure_uses_set_meta_no_compare",
        "tests/test_rea_r5_commitment.py::test_sqlite_concurrent_first_boot_20_trials",
        """
        import settlement.verifier as v
        from permit.sqlite_ledger import ACCEPTANCE_KEY_COMMITMENT_META
        def ensure_racy(db_ledger, key):
            digest = v.acceptance_key_commitment(key)
            stored = db_ledger.get_meta(ACCEPTANCE_KEY_COMMITMENT_META)
            if stored is None:
                if len(db_ledger) > 0:
                    raise ValueError(v._SILENT_REBIND_MSG)
                # MUTANT: set_meta without try_bind / compare
                db_ledger.set_meta(ACCEPTANCE_KEY_COMMITMENT_META, digest)
                return
            if not v.hmac.compare_digest(stored, digest):
                raise ValueError(v._ROTATION_REFUSE_MSG)
        v.ensure_acceptance_key_commitment = ensure_racy
        """,
    ),
    (
        "harness_no_demo_key_path",
        "tests/test_rea_r5_commitment.py::test_k1_allow_demo_key_survives_reopen_without_env",
        """
        import harness.durability_harness as h
        from permit.durability import (
            DurableLedger, DurablePermitStore, DurableMockPayPalClient,
            DurableReleaseVerifier, DurableSpendPipeline,
        )
        def build_no_persist(durable_dir, *, allow_demo_key=False):
            ledger = DurableLedger(durable_dir=durable_dir)
            permits = DurablePermitStore(ledger=ledger, durable_dir=durable_dir)
            paypal = DurableMockPayPalClient(durable_dir=durable_dir)
            # MUTANT: no demo_key_path persistence
            verifier = DurableReleaseVerifier(
                paypal, permits, ledger=ledger, durable_dir=durable_dir,
                allow_demo_key=allow_demo_key,
            )
            flow = DurableSpendPipeline(
                permits, paypal, verifier, ledger=ledger, durable_dir=durable_dir
            )
            return ledger, permits, paypal, verifier, flow
        h._build = build_no_persist
        """,
    ),
    (
        "drop_ledger_ephemeral_flag",
        "tests/test_rea_r5_commitment.py::test_in_memory_ledger_is_ephemeral",
        """
        from permit import ledger as led
        led.Ledger.ephemeral_acceptance_key_commitment = False  # MUTANT
        """,
    ),
    (
        "file_sqlite_ephemeral_force_true",
        "tests/test_rea_r5_commitment.py::test_file_sqlite_cannot_turn_off_ephemeral",
        """
        from permit.sqlite_ledger import SqliteLedger
        # MUTANT: property always True (opts out of commitment)
        SqliteLedger.ephemeral_acceptance_key_commitment = property(
            lambda self: True
        )
        SqliteLedger.requires_acceptance_key_commitment = property(
            lambda self: False
        )
        """,
    ),
    (
        "meta_row_deleted_allows_rebind",
        "tests/test_rea_r5_commitment.py::test_sqlite_meta_row_deleted_nonempty_refuses",
        """
        import settlement.verifier as v
        from permit.sqlite_ledger import ACCEPTANCE_KEY_COMMITMENT_META
        def ensure_silent(db_ledger, key):
            digest = v.acceptance_key_commitment(key)
            stored = db_ledger.get_meta(ACCEPTANCE_KEY_COMMITMENT_META)
            if stored is None:
                db_ledger.set_meta(ACCEPTANCE_KEY_COMMITMENT_META, digest)
                return
            if not v.hmac.compare_digest(stored, digest):
                raise ValueError(v._ROTATION_REFUSE_MSG)
        v.ensure_acceptance_key_commitment = ensure_silent
        """,
    ),
    (
        "durable_meta_without_commitment_allows",
        "tests/test_rea_r5_commitment.py::test_durable_nonempty_meta_without_commitment_refuses",
        """
        import settlement.verifier as v
        from permit.sqlite_ledger import ACCEPTANCE_KEY_COMMITMENT_META
        def ensure_silent(db_ledger, key):
            digest = v.acceptance_key_commitment(key)
            stored = db_ledger.get_meta(ACCEPTANCE_KEY_COMMITMENT_META)
            if stored is None:
                db_ledger.set_meta(ACCEPTANCE_KEY_COMMITMENT_META, digest)
                return
            if not v.hmac.compare_digest(stored, digest):
                raise ValueError(v._ROTATION_REFUSE_MSG)
        v.ensure_acceptance_key_commitment = ensure_silent
        """,
    ),
    (
        "rebind_accepts_wrong_then_overwrites",
        "tests/test_rea_r5_commitment.py::test_rebind_refused_with_wrong_old_key",
        """
        import settlement.verifier as v
        from permit.sqlite_ledger import ACCEPTANCE_KEY_COMMITMENT_META
        def rebind_soft(db_ledger, old_key, new_key):
            old = v._coerce_key(old_key)
            new = v._require_valid_key(v._coerce_key(new_key), what="new acceptance key")
            stored = db_ledger.get_meta(ACCEPTANCE_KEY_COMMITMENT_META)
            # MUTANT: ignore mismatch
            db_ledger.set_meta(
                ACCEPTANCE_KEY_COMMITMENT_META,
                v.acceptance_key_commitment(new),
            )
        v.rebind_acceptance_key_commitment = rebind_soft
        """,
    ),
    (
        "mutant_killer_corrupt_meta_survives",
        "tests/test_rea_r5_commitment.py::test_mutant_corrupt_meta_treated_as_empty_is_killed",
        """
        import json
        from permit.durability import DurableLedger
        def mutant_read(self):
            if self._meta_path is None or not self._meta_path.exists():
                return {}
            try:
                text = self._meta_path.read_text(encoding="utf-8")
                if not text.strip():
                    return {}
                raw = json.loads(text)
            except (json.JSONDecodeError, OSError, ValueError):
                return {}
            if not isinstance(raw, dict):
                return {}
            return {str(k): str(v) for k, v in raw.items()}
        DurableLedger._read_meta = mutant_read
        """,
    ),
    (
        "harness_cli_no_persist",
        "tests/test_rea_r5_commitment.py::test_durability_harness_py_k1_allow_demo_key_no_env_exit_0",
        """
        import harness.durability_harness as h
        from permit.durability import (
            DurableLedger, DurablePermitStore, DurableMockPayPalClient,
            DurableReleaseVerifier, DurableSpendPipeline,
        )
        def build_no_persist(durable_dir, *, allow_demo_key=False):
            ledger = DurableLedger(durable_dir=durable_dir)
            permits = DurablePermitStore(ledger=ledger, durable_dir=durable_dir)
            paypal = DurableMockPayPalClient(durable_dir=durable_dir)
            verifier = DurableReleaseVerifier(
                paypal, permits, ledger=ledger, durable_dir=durable_dir,
                allow_demo_key=allow_demo_key,
            )
            flow = DurableSpendPipeline(
                permits, paypal, verifier, ledger=ledger, durable_dir=durable_dir
            )
            return ledger, permits, paypal, verifier, flow
        h._build = build_no_persist
        """,
    ),
    (
        "try_bind_skipped_set_meta_only",
        "tests/test_acceptance_key_commitment.py::test_commitment_mismatch_raises_valueerror",
        """
        import settlement.verifier as v
        from permit.sqlite_ledger import ACCEPTANCE_KEY_COMMITMENT_META
        real = v.ensure_acceptance_key_commitment
        def ensure_no_try_bind(db_ledger, key):
            digest = v.acceptance_key_commitment(key)
            stored = db_ledger.get_meta(ACCEPTANCE_KEY_COMMITMENT_META)
            if stored is None:
                if len(db_ledger) > 0:
                    raise ValueError(v._SILENT_REBIND_MSG)
                db_ledger.set_meta(ACCEPTANCE_KEY_COMMITMENT_META, digest)
                return  # MUTANT: no re-read/compare after first bind
            if not v.hmac.compare_digest(stored, digest):
                raise ValueError(v._ROTATION_REFUSE_MSG)
        v.ensure_acceptance_key_commitment = ensure_no_try_bind
        """,
    ),
    (
        "broken_durable_silently_skipped",
        "tests/test_durable_key_commitment.py::test_no_ledger_type_silently_skips_commitment",
        """
        import settlement.verifier as v
        def bind_skip(ledger, key):
            return  # MUTANT: always skip
        v._bind_ledger_acceptance_key_commitment = bind_skip
        """,
    ),
    (
        "rotation_message_softened",
        "tests/test_acceptance_key_commitment.py::test_commitment_mismatch_raises_valueerror",
        """
        import settlement.verifier as v
        from permit.sqlite_ledger import ACCEPTANCE_KEY_COMMITMENT_META
        def ensure_soft(db_ledger, key):
            digest = v.acceptance_key_commitment(key)
            stored = db_ledger.get_meta(ACCEPTANCE_KEY_COMMITMENT_META)
            if stored is None:
                if len(db_ledger) > 0:
                    raise ValueError(v._SILENT_REBIND_MSG)
                try_bind = getattr(db_ledger, "try_bind_meta", None)
                if callable(try_bind):
                    bound = try_bind(ACCEPTANCE_KEY_COMMITMENT_META, digest)
                else:
                    db_ledger.set_meta(ACCEPTANCE_KEY_COMMITMENT_META, digest)
                    bound = db_ledger.get_meta(ACCEPTANCE_KEY_COMMITMENT_META)
                if bound is None or not v.hmac.compare_digest(str(bound), digest):
                    raise ValueError("key changed")  # MUTANT softened
                return
            if not v.hmac.compare_digest(stored, digest):
                raise ValueError("key changed")  # MUTANT softened
        v.ensure_acceptance_key_commitment = ensure_soft
        """,
    ),
    (
        "rebind_wrong_still_ok_via_cli",
        "tests/test_rea_r5_commitment.py::test_rebind_cli_script",
        """
        import settlement.verifier as v
        from permit.sqlite_ledger import ACCEPTANCE_KEY_COMMITMENT_META
        def rebind_no_check(db_ledger, old_key, new_key):
            new = v._require_valid_key(v._coerce_key(new_key), what="new acceptance key")
            db_ledger.set_meta(
                ACCEPTANCE_KEY_COMMITMENT_META,
                v.acceptance_key_commitment(new),
            )
        v.rebind_acceptance_key_commitment = rebind_no_check
        """,
    ),
    (
        "drop_nonempty_check_on_deleted_meta",
        "tests/test_rea_r5_commitment.py::test_sqlite_meta_row_deleted_nonempty_refuses",
        """
        import settlement.verifier as v
        real = v.ensure_acceptance_key_commitment
        from permit.sqlite_ledger import ACCEPTANCE_KEY_COMMITMENT_META
        def ensure_allow(db_ledger, key):
            digest = v.acceptance_key_commitment(key)
            stored = db_ledger.get_meta(ACCEPTANCE_KEY_COMMITMENT_META)
            if stored is None:
                # MUTANT: bind even when nonempty
                try_bind = getattr(db_ledger, "try_bind_meta", None)
                if callable(try_bind):
                    bound = try_bind(ACCEPTANCE_KEY_COMMITMENT_META, digest)
                else:
                    db_ledger.set_meta(ACCEPTANCE_KEY_COMMITMENT_META, digest)
                    bound = digest
                return
            if not v.hmac.compare_digest(stored, digest):
                raise ValueError(v._ROTATION_REFUSE_MSG)
        v.ensure_acceptance_key_commitment = ensure_allow
        """,
    ),
    (
        "skip_load_meta_validation",
        "tests/test_rea_r5_commitment.py::test_corrupt_meta_json_refused_not_empty",
        """
        from permit.durability import DurableLedger
        real_load = DurableLedger._load
        def load_no_meta(self):
            # Call real load but skip our meta validation by temporarily
            # clearing meta path existence check via mutant _read_meta
            import json
            def soft_read(self2):
                if self2._meta_path is None or not self2._meta_path.exists():
                    return {}
                try:
                    return {
                        str(k): str(v)
                        for k, v in json.loads(
                            self2._meta_path.read_text(encoding="utf-8")
                        ).items()
                    }
                except Exception:
                    return {}
            DurableLedger._read_meta = soft_read
            return real_load(self)
        DurableLedger._load = load_no_meta
        """,
    ),
    (
        "plain_object_treated_ephemeral",
        "tests/test_rea_r5_commitment.py::test_commitment_required_by_default_not_opt_in",
        """
        import settlement.verifier as v
        def bind_default_ephemeral(ledger, key):
            # MUTANT: default ephemeral (fail-open)
            ephemeral = bool(
                getattr(ledger, "ephemeral_acceptance_key_commitment", True)
            )
            if ephemeral:
                return
            v.ensure_acceptance_key_commitment(ledger, key)
        v._bind_ledger_acceptance_key_commitment = bind_default_ephemeral
        """,
    ),
    (
        "rebind_success_path_noop",
        "tests/test_rea_r5_commitment.py::test_rebind_succeeds_with_correct_old_key",
        """
        import settlement.verifier as v
        def rebind_noop(db_ledger, old_key, new_key):
            raise ValueError(
                "old acceptance key does not match stored commitment; "
                "refusing rebind"
            )  # MUTANT: always refuse
        v.rebind_acceptance_key_commitment = rebind_noop
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
