"""`hawcx submit` — auto-wrap plan U2.

Drives the real HTTP client against a throwaway local server rather than mocking
`urllib`: the interesting behaviour is in what goes ON the wire (the Authorization
header, the absence of an Origin) and how a 400 body is turned back into canonical
`E_*` codes. A mock of urllib would assert my own call shape back at me.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from hawcx_haap.submit import (
    SubmitError,
    resolve_credentials,
    submit_template,
)

VALID = {
    "template": "hawcx/agent-template/v1",
    "name": "o365-group-assistant",
    "version": "0.1.0",
    "framework": {"kind": "langchain"},
    "tools": [{"id": "o365.mail.read", "actions": ["read"], "risk": "read_internal"}],
}


class _Recorder(BaseHTTPRequestHandler):
    """Captures the request and replies with whatever the test queued."""

    received: dict = {}
    reply: tuple[int, dict] = (200, {})

    def do_POST(self):  # noqa: N802 — BaseHTTPRequestHandler's name
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length)
        type(self).received = {
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": json.loads(raw) if raw else None,
        }
        status, payload = type(self).reply
        blob = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(blob)))
        self.end_headers()
        self.wfile.write(blob)

    def log_message(self, *_args):  # keep pytest output clean
        pass


@pytest.fixture
def server():
    srv = HTTPServer(("127.0.0.1", 0), _Recorder)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv, f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


# ── credential resolution ────────────────────────────────────────────────────

def test_per_org_env_beats_the_generic_one(monkeypatch):
    monkeypatch.setenv("HAWCX_CONSOLE_URL", "https://generic.example")
    monkeypatch.setenv("HAWCX_API_KEY", "hx_generic")
    monkeypatch.setenv("HAWCX_CONSOLE_URL_UKG", "https://ukg.example")
    monkeypatch.setenv("HAWCX_API_KEY_UKG", "hx_ukg")
    assert resolve_credentials("ukg") == ("https://ukg.example", "hx_ukg")
    # An org with no specific vars falls back.
    assert resolve_credentials("acme") == ("https://generic.example", "hx_generic")


def test_hyphenated_org_maps_to_underscore(monkeypatch):
    """Org slugs routinely contain `-`; env var names cannot."""
    monkeypatch.setenv("HAWCX_CONSOLE_URL_BIG_CORP", "https://bc.example")
    monkeypatch.setenv("HAWCX_API_KEY_BIG_CORP", "hx_bc")
    assert resolve_credentials("big-corp") == ("https://bc.example", "hx_bc")


def test_missing_credentials_name_what_to_set(monkeypatch):
    for k in list(os.environ):
        if k.startswith("HAWCX_"):
            monkeypatch.delenv(k, raising=False)
    with pytest.raises(SubmitError) as e:
        resolve_credentials("ukg")
    msg = str(e.value)
    assert "HAWCX_API_KEY_UKG" in msg and "HAWCX_CONSOLE_URL_UKG" in msg
    # The permission is the part people get wrong, so it is named.
    assert "org.agent_templates.push" in msg


def test_a_non_hawcx_key_is_refused_before_the_request(monkeypatch):
    """The console 401s a non-`hx_` bearer, which reads as an auth outage rather
    than a wrong value. Catch it locally where the message can be specific."""
    monkeypatch.setenv("HAWCX_CONSOLE_URL", "https://c.example")
    monkeypatch.setenv("HAWCX_API_KEY", "eyJhbGciOi.a.jwt")
    with pytest.raises(SubmitError, match="hx_"):
        resolve_credentials("ukg")


# ── the wire ─────────────────────────────────────────────────────────────────

def test_posts_the_document_with_a_bearer_key_and_no_origin(server):
    srv, url = server
    _Recorder.reply = (200, {"id": "abc", "name": "o365-group-assistant",
                             "version": "0.1.0", "status": "draft", "toolCount": 1})
    out = submit_template(VALID, console_url=url, api_key="hx_k", source="cli/test")
    assert out["id"] == "abc"

    got = _Recorder.received
    assert got["path"] == "/api/agent-templates"
    assert got["headers"]["authorization"] == "Bearer hx_k"
    assert got["body"] == {"document": VALID, "source": "cli/test"}
    # Deliberately absent: sending one would make a CLI look like a browser to
    # any future middleware that checks it.
    assert "origin" not in got["headers"]
    # The org is NOT on the wire — the console derives it from the key. A client
    # able to name the org would be a cross-tenant write primitive.
    assert "org" not in json.dumps(got["body"]).lower().replace("group", "")


def test_a_400_is_turned_back_into_canonical_codes(server):
    srv, url = server
    _Recorder.reply = (400, {
        "error": "validation_failed",
        "message": (
            "agent-template validation failed (1 error(s)): "
            "E_AUTHORITY_CLAIM at $.granted_scopes"
        ),
        "errors": [{"code": "E_AUTHORITY_CLAIM", "path": "$.granted_scopes"}],
    })
    with pytest.raises(SubmitError) as e:
        submit_template(VALID, console_url=url, api_key="hx_k")
    assert e.value.status == 400
    assert e.value.errors == [{"code": "E_AUTHORITY_CLAIM", "path": "$.granted_scopes"}]


def test_a_403_explains_the_permission(server):
    srv, url = server
    _Recorder.reply = (403, {
        "error": "forbidden",
        "message": "this API key lacks `org.agent_templates.push`",
    })
    with pytest.raises(SubmitError, match="org.agent_templates.push"):
        submit_template(VALID, console_url=url, api_key="hx_k")


def test_a_non_json_error_body_does_not_crash(server):
    """A proxy or WAF in front of the console returns HTML, not JSON."""
    srv, url = server

    class Html(_Recorder):
        def do_POST(self):  # noqa: N802
            blob = b"<html>502 Bad Gateway</html>"
            self.send_response(502)
            self.send_header("content-type", "text/html")
            self.send_header("content-length", str(len(blob)))
            self.end_headers()
            self.wfile.write(blob)

    srv.RequestHandlerClass = Html
    with pytest.raises(SubmitError) as e:
        submit_template(VALID, console_url=url, api_key="hx_k")
    assert e.value.status == 502
    assert "502" in str(e.value)


def test_unreachable_console_is_a_clear_error():
    with pytest.raises(SubmitError, match="could not reach the console"):
        # Port 1 is reserved and never listening.
        submit_template(VALID, console_url="http://127.0.0.1:1", api_key="hx_k", timeout=2)


def test_refuses_to_send_a_key_over_cleartext_http():
    """An API key in an Authorization header over plain HTTP is a credential
    disclosure, not a configuration preference."""
    with pytest.raises(SubmitError, match="non-HTTPS"):
        submit_template(VALID, console_url="http://console.example.com", api_key="hx_k")


def test_localhost_is_exempt_from_the_https_rule(server):
    """The dev-console case never leaves the loopback."""
    srv, url = server
    _Recorder.reply = (200, {"id": "x", "name": "n", "version": "0.1.0",
                             "status": "draft", "toolCount": 1})
    assert submit_template(VALID, console_url=url, api_key="hx_k")["id"] == "x"


# ── CLI ──────────────────────────────────────────────────────────────────────

def _cli(*args, env=None):
    e = {**os.environ, **(env or {})}
    return subprocess.run(
        [sys.executable, "-m", "hawcx_haap.cli", *args],
        capture_output=True, text=True, env=e,
    )


def test_cli_submit_validates_locally_before_any_network_call(tmp_path):
    """An invalid template must not produce a network round-trip and a 400 — it
    should fail offline, listing every problem at once."""
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({**VALID, "granted_scopes": ["everything"]}))
    r = _cli("submit", str(bad), "--org", "ukg", env={
        # Deliberately unreachable: if the CLI tried to send, this test would
        # report a connection error instead of a validation error.
        "HAWCX_CONSOLE_URL": "https://127.0.0.1:1",
        "HAWCX_API_KEY": "hx_k",
    })
    assert r.returncode == 1
    assert "E_AUTHORITY_CLAIM" in r.stderr
    assert "not submitted" in r.stderr
    assert "could not reach" not in r.stderr


def test_cli_submit_requires_org():
    r = _cli("submit", "x.json")
    assert r.returncode != 0
    assert "--org" in r.stderr
