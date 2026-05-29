#!/usr/bin/env python3
"""
Mock MCP server — pretends to be a Slack/Drive/whatever MCP backend
sitting in front of the stage RSV sidecar.

Plays the middle role of the §45 Pattern Z lifecycle:

    Assembler  →  this server  →  RSV /verify
                                  RSV /encrypt-response
    Assembler  ←  this server  ←  (sidecar replies)

What this DOES:
    * Listens on 127.0.0.1:9999 (configurable via env).
    * Accepts a POST on any path with:
        - `Authorization: HAAP <base64-token>` header
        - Body = base64-encoded AEAD ciphertext + 4-byte framing prefix
        - `X-HAAP-AAD: <base64>` header (the AAD the assembler used)
    * Forwards to RSV `/verify` (bearer auth from --rsv-bearer).
    * On 200: decodes the plaintext, builds `{"result": "echo: <plaintext>"}`,
      and asks RSV to encrypt the response via `/encrypt-response`
      using the returned `verification_handle`.
    * Returns the resulting ciphertext (base64) in body, AAD (the framing
      header — not used for response decrypt by client) in `X-HAAP-Resp-AAD`.

What this does NOT do (deliberately out of scope for a test fixture):
    * No rate limiting, no retries, no structured logging, no metrics.
    * No TLS termination — the wrapper script runs it on localhost only.
    * No streaming / SSE — single request, single response.
    * No tool dispatch — `result` always echoes the plaintext.

Logging style: one human-readable line per stage of the sidecar dance,
prefixed with `[mock-mcp]`. Designed to make the §45 cascade visible
when run interactively.
"""

import argparse
import asyncio
import base64
import json
import logging
import os
import sys

import aiohttp
from aiohttp import web

LOG = logging.getLogger("mock-mcp")

# Stage RSV — overridable via CLI so the same script works against a
# locally-run sidecar during diagnostics.
DEFAULT_RSV_URL = "https://stage-authorizer.haapidemo.com"


async def handle_tool_call(request: web.Request) -> web.Response:
    """The one and only route: any POST is treated as a tool call."""
    cfg = request.app["cfg"]
    path = request.path

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("HAAP "):
        LOG.warning("reject: missing or wrong-scheme Authorization (got %r)", auth[:32])
        return web.json_response({"error": "missing HAAP token"}, status=401)
    token_b64 = auth[len("HAAP "):].strip()

    aad_b64 = request.headers.get("X-HAAP-AAD")
    if not aad_b64:
        LOG.warning("reject: missing X-HAAP-AAD header")
        return web.json_response({"error": "missing X-HAAP-AAD"}, status=400)

    body_bytes = await request.read()
    if not body_bytes:
        LOG.warning("reject: empty body")
        return web.json_response({"error": "empty body"}, status=400)
    encrypted_b64 = body_bytes.decode("ascii").strip()

    LOG.info("← inbound: path=%s token.len=%d body.len=%d aad.len=%d",
             path, len(token_b64), len(encrypted_b64), len(aad_b64))

    # Step 1: RSV /verify
    verify_body = {
        "token_b64": token_b64,
        "encrypted_request_b64": encrypted_b64,
        "request_aad_b64": aad_b64,
    }
    async with aiohttp.ClientSession() as session:
        LOG.info("→ RSV /verify (sidecar step 1)")
        async with session.post(
            f"{cfg.rsv_url}/verify",
            json=verify_body,
            headers={"Authorization": f"Bearer {cfg.rsv_bearer}"},
        ) as resp:
            verify_status = resp.status
            verify_json = await resp.json(content_type=None)
        LOG.info("← RSV /verify: status=%d keys=%s", verify_status, sorted(verify_json.keys()))
        if verify_status != 200:
            return web.json_response({"error": "verify failed", "rsv": verify_json},
                                     status=verify_status)

        plaintext_b64 = verify_json["plaintext_b64"]
        handle = verify_json["verification_handle"]
        session_id = verify_json["session_id"]
        decoded = base64.b64decode(plaintext_b64).decode("utf-8", errors="replace")
        LOG.info("  plaintext=%r session_id=%d handle=%s", decoded, session_id, handle)

        # Step 2: pretend to "do work" and craft a response.
        response_obj = {"result": f"echo: {decoded}"}
        response_plaintext = json.dumps(response_obj, separators=(",", ":"))
        response_b64 = base64.b64encode(response_plaintext.encode()).decode()
        LOG.info("  built response plaintext=%r", response_plaintext)

        # Step 3: RSV /encrypt-response
        enc_body = {
            "verification_handle": handle,
            "plaintext_b64": response_b64,
        }
        LOG.info("→ RSV /encrypt-response (sidecar step 2)")
        async with session.post(
            f"{cfg.rsv_url}/encrypt-response",
            json=enc_body,
            headers={"Authorization": f"Bearer {cfg.rsv_bearer}"},
        ) as resp:
            enc_status = resp.status
            enc_json = await resp.json(content_type=None)
        LOG.info("← RSV /encrypt-response: status=%d keys=%s",
                 enc_status, sorted(enc_json.keys()) if isinstance(enc_json, dict) else type(enc_json))
        if enc_status != 200:
            return web.json_response({"error": "encrypt-response failed", "rsv": enc_json},
                                     status=enc_status)

        ciphertext_b64 = enc_json["ciphertext_b64"]
        LOG.info("→ outbound: ciphertext.len=%d (returning to client)", len(ciphertext_b64))

        return web.Response(
            body=ciphertext_b64,
            status=200,
            content_type="application/octet-stream",
            headers={"X-HAAP-Session-Id": str(session_id)},
        )


async def healthz(_request: web.Request) -> web.Response:
    return web.Response(text="ok\n")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="127.0.0.1:9999")
    ap.add_argument("--rsv-url", default=os.environ.get("STAGE_RSV_URL", DEFAULT_RSV_URL))
    ap.add_argument("--rsv-bearer", default=os.environ.get("HAAP_RSV_AUTH_TOKEN", ""),
                    help="bearer for RSV /verify + /encrypt-response (must match stage k8s secret)")
    cfg = ap.parse_args(argv)
    if not cfg.rsv_bearer:
        print("mock-mcp: --rsv-bearer or HAAP_RSV_AUTH_TOKEN is required", file=sys.stderr)
        return 2

    logging.basicConfig(
        level=logging.INFO,
        format="[%(name)s] %(message)s",
        stream=sys.stderr,
    )

    app = web.Application()
    app["cfg"] = cfg
    app.router.add_get("/healthz", healthz)
    app.router.add_post("/{tail:.*}", handle_tool_call)

    host, port = cfg.listen.split(":")
    LOG.info("listening on %s, forwarding to %s", cfg.listen, cfg.rsv_url)
    web.run_app(app, host=host, port=int(port), access_log=None,
                handle_signals=True, print=lambda *_a, **_kw: None)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
