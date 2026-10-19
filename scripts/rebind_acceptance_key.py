#!/usr/bin/env python3
"""One-time acceptance-key rebind for exact-32 upgrade (REA round 5).

Databases bound before the exact-32-byte rule (e.g. at 19b62ce with
``secrets.token_hex(32)`` → 64 UTF-8 bytes) store an HMAC commitment of that
longer key. After upgrade, startup refuses the long key. This command checks
the OLD key against the stored commitment, then binds a new exact-32-byte key.

Usage:
  python -m scripts.rebind_acceptance_key --db PATH \\
      --old-key-file OLD --new-key-file NEW

  # or via env (OLD may be any non-empty length; NEW must be exact 32 bytes):
  PERMIT_OLD_ACCEPTANCE_KEY=... PERMIT_ACCEPTANCE_KEY=... \\
      python -m scripts.rebind_acceptance_key --db PATH

  # DurableLedger / harness state dir:
  python -m scripts.rebind_acceptance_key --durable-dir DIR \\
      --old-key-file OLD --new-key-file NEW
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def _read_key_file(path: Path) -> bytes:
    data = path.read_bytes()
    if data.endswith(b"\n") and b"\n" not in data[:-1]:
        # Allow a single trailing newline from shell redirects; strip it.
        data = data[:-1]
    return data


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="One-time rebind of the durable acceptance-key commitment"
    )
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--db", type=str, help="SqliteLedger database path")
    g.add_argument(
        "--durable-dir",
        type=str,
        help="DurableLedger / harness state directory",
    )
    ap.add_argument(
        "--old-key-file",
        type=str,
        default=None,
        help="File containing the OLD acceptance key (any non-empty length)",
    )
    ap.add_argument(
        "--new-key-file",
        type=str,
        default=None,
        help="File containing the NEW acceptance key (exact 32 bytes)",
    )
    args = ap.parse_args(argv)

    if args.old_key_file:
        old_key = _read_key_file(Path(args.old_key_file))
    elif "PERMIT_OLD_ACCEPTANCE_KEY" in os.environ:
        old_key = os.environ["PERMIT_OLD_ACCEPTANCE_KEY"].encode("utf-8")
    else:
        ap.error(
            "pass --old-key-file or set PERMIT_OLD_ACCEPTANCE_KEY"
        )

    if args.new_key_file:
        new_key = _read_key_file(Path(args.new_key_file))
    elif "PERMIT_ACCEPTANCE_KEY" in os.environ:
        new_key = os.environ["PERMIT_ACCEPTANCE_KEY"].encode("utf-8")
    else:
        ap.error("pass --new-key-file or set PERMIT_ACCEPTANCE_KEY")

    from settlement.verifier import rebind_acceptance_key_commitment

    if args.db:
        from permit.sqlite_ledger import SqliteLedger

        ledger = SqliteLedger(args.db)
        try:
            rebind_acceptance_key_commitment(ledger, old_key, new_key)
        except (ValueError, RuntimeError) as exc:
            print(f"rebind failed: {exc}", file=sys.stderr)
            return 1
        finally:
            ledger.close()
    else:
        from permit.durability import DurableLedger

        ledger = DurableLedger(durable_dir=Path(args.durable_dir))
        try:
            rebind_acceptance_key_commitment(ledger, old_key, new_key)
        except (ValueError, RuntimeError) as exc:
            print(f"rebind failed: {exc}", file=sys.stderr)
            return 1
        finally:
            ledger.close()

    print("rebind ok: acceptance key commitment updated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
