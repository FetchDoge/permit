#!/usr/bin/env python3
"""Yield check: rerun the mock-rail targets N times and count passes.

Mock rail only. This script never runs launch_sandbox.py or
scripts/sandbox_smoke.py, and it strips PayPal credentials from the child
environment so the sandbox_live test tier stays skipped.

A run passes only if it exits 0 AND its stdout carries the expected proof:
  pytest   the summary line, with "0 failed" (skips are reported, not hidden)
  demo     "VERIFIED (16 receipts)"
  replay   "VERIFIED (26 receipts)" (six-beat replay, no --fast, as filmed)

Output is counts, never a percentage. On a failed run, stderr is printed.

    python scripts/yield.py                    # 5 runs of every target
    python scripts/yield.py -n 100 -t demo -t replay
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TARGETS = {
    "pytest": ([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"], None),
    "demo": ([sys.executable, "demo.py"], "ledger chain: VERIFIED (16 receipts)"),
    "replay": ([sys.executable, "demos/demo_six_beat.py", "--replay",
                "demos/fixtures/demo_transcript.jsonl"],
               "ledger chain: VERIFIED (26 receipts)"),
}

_FORBIDDEN = ("launch_sandbox", "sandbox_smoke")
_PYTEST_SUMMARY = re.compile(r"^=*\s*(\d+ (?:passed|failed|skipped|errors?).*?) in [\d.]+s", re.M)


def mock_env() -> dict:
    env = dict(os.environ)
    for k in list(env):
        if k.startswith(("PERMIT_PAYPAL_", "PAYPAL_SANDBOX_")):
            del env[k]
    return env


def pytest_counts(stdout: str) -> dict | None:
    m = _PYTEST_SUMMARY.search(stdout)
    if not m:
        return None
    counts = {"passed": 0, "skipped": 0, "failed": 0, "errors": 0}
    for n, word in re.findall(r"(\d+) (passed|skipped|failed|errors?)", m.group(1)):
        counts["errors" if word.startswith("error") else word] = int(n)
    return counts


def run_target(name: str, cmd: list[str], expect: str | None,
               runner=subprocess.run) -> tuple[bool, str]:
    """Run once. Returns (ok, detail)."""
    if any(f in part for part in cmd for f in _FORBIDDEN):
        raise ValueError(f"refusing sandbox command: {cmd}")
    proc = runner(cmd, cwd=ROOT, env=mock_env(),
                  capture_output=True, text=True)
    out = proc.stdout or ""
    if name == "pytest":
        c = pytest_counts(out)
        if c is None:
            ok, detail = False, "no pytest summary line"
        else:
            detail = (f"{c['passed']} passed, {c['skipped']} skipped, "
                      f"{c['failed']} failed" + (f", {c['errors']} errors" if c["errors"] else ""))
            ok = proc.returncode == 0 and c["failed"] == 0 and c["errors"] == 0
    else:
        found = expect in out
        detail = expect if found else f"missing {expect!r}"
        ok = proc.returncode == 0 and found
    if proc.returncode != 0:
        detail += f" (exit {proc.returncode})"
    if not ok:
        print(f"--- {name} FAILED: {detail}\n--- stderr:\n{proc.stderr or ''}"
              f"--- stdout tail:\n{out[-1500:]}", file=sys.stderr, flush=True)
    return ok, detail


def main(argv=None, runner=subprocess.run) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-n", "--runs", type=int, default=5)
    ap.add_argument("-t", "--target", action="append", choices=list(TARGETS),
                    help="repeatable; default: all targets")
    args = ap.parse_args(argv)
    if args.runs < 1:
        ap.error("--runs must be >= 1")
    all_ok = True
    for name in args.target or list(TARGETS):
        cmd, expect = TARGETS[name]
        passed = 0
        details = set()
        for _ in range(args.runs):
            ok, detail = run_target(name, cmd, expect, runner)
            passed += ok
            details.add(detail)
        failed = args.runs - passed
        all_ok &= failed == 0
        print(f"{name}: {passed} passed, {failed} failed of {args.runs} runs"
              f" | {'; '.join(sorted(details))}", flush=True)
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
