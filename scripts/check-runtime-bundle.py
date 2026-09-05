#!/usr/bin/env python3
"""Verify a staged runtime; --cross explicitly reports execution as unverified."""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile


def verify(directory, version, cross=False):
    directory = Path(directory).resolve()
    ext = '.exe' if (directory / 'hawcx-manager.exe').exists() else ''
    manager = directory / ('hawcx-manager' + ext)
    orch = directory / ('haap-unseal-orch' + ext)
    manager_bytes = manager.read_bytes()
    if not manager_bytes or orch.read_bytes() != manager_bytes:
        raise ValueError('missing, empty, or nonidentical multicall orchestrator artifact')
    print('runtime sha256:', hashlib.sha256(manager_bytes).hexdigest())
    if cross:
        print('UNVERIFIED native execution: cross-compiled artifact; byte identity only')
        return
    result = subprocess.run([str(manager), '--version'], capture_output=True, text=True,
                            timeout=15, check=True)
    if result.stdout.strip() != f'hawcx-manager {version}':
        raise ValueError(f'wrong runtime version: {result.stdout!r}')
    # Empty working directory supplies no customer config. This is an expected
    # fail-closed startup probe, not a successful custody/agent launch claim.
    env = {key: value for key, value in os.environ.items() if not key.startswith('HAAP_')}
    env['RUST_LOG'] = 'info'
    with tempfile.TemporaryDirectory() as cwd:
        result = subprocess.run([str(orch)], cwd=cwd, env=env, capture_output=True, text=True,
                                timeout=15)
    output = result.stdout + result.stderr
    if result.returncode == 0 or 'USAGE' in output or 'haap.audit.security' not in output:
        raise ValueError(f'orchestrator role did not reach fail-closed startup: {output!r}')
    print('PASS native version and orchestrator startup refusal (no custody configured)')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory')
    parser.add_argument('--version', required=True)
    parser.add_argument('--cross', action='store_true')
    args = parser.parse_args()
    verify(args.directory, args.version, args.cross)
