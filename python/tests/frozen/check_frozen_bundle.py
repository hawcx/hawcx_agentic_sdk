"""Does the egress shim still work once PyInstaller has frozen it?

WHY THIS IS NOT A PYTEST MODULE, AND WHY IT EXISTS AT ALL
---------------------------------------------------------
#118 shipped a change that passed all 73 egress tests and broke every frozen
agent bundle in the field. It replaced a literal ``import httpx`` with
``importlib.import_module(<runtime value>)``. PyInstaller's module graph
follows the first and cannot see the second, so the transport silently stopped
being packaged and `client()` raised `EgressConfigError: the egress transport
requires httpx2 or httpx` at the agent's first request.

Measured after the fact, same PyInstaller config, only the SDK differing:

    pre-#118    httpx modules collected: 23    frozen result: works
    0.1.11      httpx modules collected:  0    frozen result: EgressConfigError

Nothing in the test suite could see that, because every test imports the shim
from a normal interpreter where `find_spec` finds whatever pip installed. The
only thing that catches it is freezing a program and running it.

The check is deliberately behavioural rather than an inventory of collected
modules. Asserting "httpx2 is in the archive" would fail today by design —
0.1.12 resolves to the stdlib flavor in a frozen bundle and that is correct.
What must hold is narrower and more durable: **a frozen program can get a
working client from the broker.** Whichever flavor satisfies that is fine.

Runs on Linux only: `--onefile` collection is static analysis of the same
module graph on every platform, and the AF_UNIX broker the check needs does
not exist on Windows.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))  # tests/, for the broker + TLS doubles

from egress_broker import (  # noqa: E402
    FakeBroker,
    TLSServer,
    make_localhost_cert,
    relay_handler,
)

BODY = b"frozen-bundle-reached-the-api"


def build(workdir: Path) -> Path:
    """Freeze agent_probe.py exactly as a customer's bundler would."""
    out = workdir / "dist"
    cmd = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile",
        "--name", "agent_probe",
        "--distpath", str(out),
        "--workpath", str(workdir / "build"),
        "--specpath", str(workdir),
        str(HERE / "agent_probe.py"),
    ]
    run = subprocess.run(cmd, capture_output=True, text=True)
    if run.returncode != 0:
        sys.stderr.write(run.stdout[-4000:] + run.stderr[-4000:])
        raise SystemExit("PyInstaller build failed")
    binary = out / "agent_probe"
    if not binary.exists():
        raise SystemExit(f"no frozen binary at {binary}")
    return binary


def collected(workdir: Path, prefix: str) -> int:
    """How many modules of `prefix` PyInstaller pulled in. Reported, never
    asserted on — it is the diagnostic that explains a failure, not the
    contract. See the module docstring."""
    toc = workdir / "build" / "agent_probe" / "Analysis-00.toc"
    if not toc.exists():
        return -1
    return len(set(re.findall(rf"'({re.escape(prefix)}[^']*)'", toc.read_text())))


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="hawcx-frozen-") as tmp:
        workdir = Path(tmp)
        binary = build(workdir)
        for prefix in ("httpx2", "httpx", "http.client"):
            print(f"  collected {prefix}: {collected(workdir, prefix)}")

        certdir = workdir / "ca"
        certdir.mkdir()
        cert, key = make_localhost_cert(str(certdir))
        with TLSServer(cert, key, body=BODY) as tls:
            with FakeBroker(relay_handler(tls.host, tls.port)) as broker:
                env = {
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "HAAP_EGRESS_BROKER_SOCKET": broker.path,
                    "FROZEN_PROBE_URL": f"https://localhost:{tls.port}/v1/models",
                    "FROZEN_PROBE_CA": cert,
                }
                run = subprocess.run(
                    [str(binary)], capture_output=True, text=True, env=env, timeout=120
                )
                print(run.stdout.rstrip())
                if run.returncode != 0:
                    sys.stderr.write(run.stderr[-4000:])
                    print("\nFAIL: the frozen binary could not complete a brokered request.")
                    print("This is the #118 shape: the shim imports fine but no transport")
                    print("was packaged. Check how egress.py names the module it imports.")
                    return 1

                problems = []
                if "status=200" not in run.stdout:
                    problems.append("no HTTP 200 from the frozen binary")
                if BODY.decode() not in run.stdout:
                    problems.append("response body did not survive the tunnel")
                # The broker must have seen the request, and seen it as a NAME.
                # A frozen build that resolved DNS itself would still print 200
                # here while defeating the allowlist the broker enforces.
                if len(broker.requests) != 1:
                    problems.append(f"broker saw {len(broker.requests)} CONNECTs, expected 1")
                else:
                    req = broker.requests[0]
                    if req[3] != 0x03:
                        problems.append(f"CONNECT used ATYP {req[3]:#04x}, expected DOMAINNAME")
                    elif req[5 : 5 + req[4]] != b"localhost":
                        problems.append("CONNECT did not name the host the caller asked for")

                if problems:
                    for p in problems:
                        print(f"FAIL: {p}")
                    return 1

    print("OK: a frozen bundle gets a working brokered client.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
