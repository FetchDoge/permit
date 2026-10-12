#!/usr/bin/env python3
"""Launch the permit service in sandbox mode, mapping .env.sandbox names
(PAYPAL_SANDBOX_*) to the PERMIT_PAYPAL_* names server.py expects."""
import os
import sys

ROOT = os.path.expanduser("~/workspace/permit-main")

env = dict(os.environ)
with open(os.path.join(ROOT, ".env.sandbox")) as fh:
    for line in fh:
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()

env["PERMIT_PAYPAL_CLIENT_ID"] = env.get("PAYPAL_SANDBOX_CLIENT_ID", "")
env["PERMIT_PAYPAL_CLIENT_SECRET"] = env.get("PAYPAL_SANDBOX_SECRET", "")
env["PERMIT_PAYPAL_MERCHANT_ID"] = "GVBH7M3B2KVPW"

if not env["PERMIT_PAYPAL_CLIENT_ID"] or not env["PERMIT_PAYPAL_CLIENT_SECRET"]:
    print("missing credentials", flush=True)
    sys.exit(1)

os.chdir(ROOT)
print("permit: sandbox rail armed", flush=True)
os.execvpe("python3", ["python3", "server.py", "--port", "8741", "--sandbox"], env)
