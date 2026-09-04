#!/usr/bin/env python3
"""Assert a published SDK image can reach the unseal-orchestrator role.

`haap-supervisor` spawns the orchestrator by a name it resolves itself --
`[orchestrator] orch_bin`, then a sibling of the supervisor binary, then
`$PATH` (hx_agent_client_auth_service `crates/haap-supervisor/src/graph.rs`,
`resolve_orchestrator_program`). Every one of those lands in
`/usr/local/bin` for this image, because that is where the ENTRYPOINT
symlink resolves to and it is the only bin dir on the distroless `$PATH`.
So one name decides whether the daemon starts at all:

    /usr/local/bin/haap-unseal-orch

Nothing else in CI runs this image (the `docker/bundle` compose is CAA +
RSV + redis, no `hx-agent-sdk` service), and the packaging step that makes
the role-named symlinks listed seven names and not this one -- so the
published image shipped with the orchestrator unreachable and no check
anywhere said so.

This reads the image straight from the registry rather than starting it:
no docker daemon, so it runs on any CI runner, and it resolves against the
bytes that were actually pushed rather than against what the workflow
meant to push.

    ./scripts/check-image-orch-target.py ghcr.io/hawcx/hx-agent-sdk:v0.1.4

Auth: `GITHUB_TOKEN`/`GHCR_TOKEN` if set, else `gh auth token`.

ponytail: presence, not dispatch. That the name resolves to a binary which
routes `argv[0] == "haap-unseal-orch"` to the role needs the image RUN, and
is pinned upstream by `dispatch::unseal_orch_is_reachable_by_subcommand_and_by_argv0`
-- but that only holds for a `hawcx-manager` new enough to have the arm
(>= 0.10.21, added in CAS #434). A version assert belongs with the pin in
release.yml, not here.
"""

from __future__ import annotations

import base64
import io
import json
import os
import subprocess
import sys
import tarfile
import urllib.request

ORCH_NAME = "haap-unseal-orch"
BIN_DIR = "usr/local/bin"

ACCEPT = ", ".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
)


def registry_token(registry: str, repo: str) -> str:
    """Exchange a GitHub PAT for a registry pull token."""
    pat = os.environ.get("GHCR_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not pat:
        pat = subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True, check=True
        ).stdout.strip()
    basic = base64.b64encode(f"x:{pat}".encode()).decode()
    url = f"https://{registry}/token?scope=repository:{repo}:pull&service={registry}"
    req = urllib.request.Request(url, headers={"Authorization": f"Basic {basic}"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)["token"]


def main(ref: str, arch: str) -> int:
    registry, rest = ref.split("/", 1)
    repo, _, tag = rest.rpartition(":")
    if not tag:
        repo, tag = rest, "latest"

    hdrs = {"Authorization": f"Bearer {registry_token(registry, repo)}"}

    def blob(digest_or_tag: str, kind: str = "blobs", raw: bool = False):
        h = dict(hdrs)
        if kind == "manifests":
            h["Accept"] = ACCEPT
        req = urllib.request.Request(
            f"https://{registry}/v2/{repo}/{kind}/{digest_or_tag}", headers=h
        )
        with urllib.request.urlopen(req, timeout=120) as r:
            data = r.read()
        return data if raw else json.loads(data)

    man = blob(tag, "manifests")
    if "manifests" in man:
        # Multi-arch index. Attestation manifests carry platform
        # unknown/unknown -- match on the real platform, not on position.
        picks = [
            m
            for m in man["manifests"]
            if m.get("platform", {}).get("os") == "linux"
            and m.get("platform", {}).get("architecture") == arch
        ]
        if not picks:
            print(f"FAIL {ref}: no linux/{arch} manifest in the index")
            return 1
        man = blob(picks[0]["digest"], "manifests")

    # Walk every layer; a later layer's entry wins, as the union fs would.
    found: dict[str, str] = {}
    for layer in man["layers"]:
        raw = blob(layer["digest"], raw=True)
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as tf:
            for ti in tf:
                head, _, name = ti.name.rpartition("/")
                if head != BIN_DIR or not name:
                    continue
                found[name] = (
                    f"symlink -> {ti.linkname}"
                    if ti.issym()
                    else f"file, {ti.size} bytes"
                    if ti.isfile()
                    else ti.type.decode()
                    if isinstance(ti.type, bytes)
                    else str(ti.type)
                )

    print(f"{ref} (linux/{arch}) /{BIN_DIR}:")
    for name in sorted(found):
        mark = "  <-- orchestrator" if name == ORCH_NAME else ""
        print(f"    {name:26} {found[name]}{mark}")

    if ORCH_NAME in found:
        print(f"\nPASS: {ORCH_NAME} is present in /{BIN_DIR}")
        return 0

    print(
        f"\nFAIL: no {ORCH_NAME} in /{BIN_DIR}.\n"
        "  haap-supervisor resolves the orchestrator via [orchestrator] orch_bin,\n"
        "  then a sibling of its own binary, then $PATH -- all three land here.\n"
        "  With none of them hitting, a supervisor new enough to pre-flight its\n"
        "  exec targets refuses at config load ('no unseal-orchestrator executable\n"
        "  found'), and an older one spawns the bare name and dies at launch.\n"
        "  Fix: ship the role-named symlink, or set [orchestrator] multicall_bin."
    )
    return 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(f"usage: {sys.argv[0]} <image-ref> [arch]")
    sys.exit(main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "amd64"))
