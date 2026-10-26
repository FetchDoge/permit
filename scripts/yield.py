#!/usr/bin/env python3
"""Yield check: rerun the mock-rail targets N times and print a pass rate.

Mock rail only. This script never runs launch_sandbox.py or
scripts/sandbox_smoke.py, and it strips PayPal credentials from the child
environment so the sandbox_live test tier stays skipped.

    python scripts/yield.py            # 5 runs each
    python scripts/yield.py -n 10
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TARGETS = {
    "demo.py": [sys.executable, "demo.py"],
    "pytest": [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
}

_FORBIDDEN = ("launch_sandbox", "sandbox_smoke")


def mock_env() -> dict:
    env = dict(os.environ)
    for k in list(env):
        if k.startswith(("PERMIT_PAYPAL_", "PAYPAL_SANDBOX_")):
            del env[k]
    return env


def run_target(cmd: list[str], runner=subprocess.run) -> bool:
    if any(f in part for part in cmd for f in _FORBIDDEN):
        raise ValueError(f"refusing sandbox command: {cmd}")
    proc = runner(cmd, cwd=ROOT, env=mock_env(),
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return proc.returncode == 0


def main(argv=None, runner=subprocess.run) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-n", "--runs", type=int, default=5)
    args = ap.parse_args(argv)
    if args.runs < 1:
        ap.error("--runs must be >= 1")
    all_ok = True
    for name, cmd in TARGETS.items():
        passed = sum(run_target(cmd, runner) for _ in range(args.runs))
        all_ok &= passed == args.runs
        print(f"{name}: {passed}/{args.runs} passed "
              f"({100 * passed / args.runs:.0f}%)", flush=True)
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
