"""The stdlib egress flavor — the one a frozen offline bundle can actually use.

`hawcx_haap.source_bundle` vendors the nine SDK files and nothing else
("offline builds never run pip"), so an agent packaged that way has
`egress.py` and neither httpx lineage. Before this flavor existed, every such
agent raised `EgressConfigError` at its first brokered request. These tests
run against the real fake broker and a real TLS server, so they prove the
bytes actually move, not merely that a code path was taken.
"""

from __future__ import annotations

import socket
import tempfile

import pytest
from egress_broker import (
    FakeBroker,
    TLSServer,
    make_localhost_cert,
    relay_handler,
    scripted_handler,
)

from hawcx_haap import egress
from hawcx_haap.errors import (
    EgressConfigError,
    EgressHTTPStatusError,
    EgressPolicyDenied,
)

pytestmark = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="egress broker is UNIX-domain-socket only"
)


# ── Layer 1: Example — a real TLS request with no third-party package ────────


def test_tls_request_completes_with_no_httpx_installed() -> None:
    with tempfile.TemporaryDirectory() as d:
        cert, key = make_localhost_cert(d)
        with TLSServer(cert, key, body=b"stdlib-through-tunnel") as tls:
            with FakeBroker(relay_handler(tls.host, tls.port)) as broker:
                with egress.client(
                    socket_path=broker.path, verify=cert, flavor="stdlib"
                ) as http:
                    r = http.get(f"https://localhost:{tls.port}/")
                assert r.status_code == 200
                assert r.text == "stdlib-through-tunnel"
                assert r.is_success
            # DOMAINNAME, like every other flavor: the broker does the DNS.
            assert len(broker.requests) == 1
            req = broker.requests[0]
            assert req[3] == 0x03
            assert req[5 : 5 + req[4]] == b"localhost"


def test_selected_automatically_when_no_lineage_is_installed(monkeypatch) -> None:
    """The case that matters: an offline bundle. Simulated by making both
    lineages unfindable, which is exactly what `find_spec` reports there."""
    real = egress.importlib.util.find_spec

    def missing(name, *a, **kw):
        return None if name in ("httpx", "httpx2") else real(name, *a, **kw)

    monkeypatch.setattr(egress.importlib.util, "find_spec", missing)
    assert egress.flavor() == "stdlib"


def test_a_real_lineage_still_wins(monkeypatch) -> None:
    """Strictly additive: wherever httpx exists today, nothing changes."""
    pytest.importorskip("httpx")
    real = egress.importlib.util.find_spec
    monkeypatch.setattr(
        egress.importlib.util,
        "find_spec",
        lambda name, *a, **kw: None if name == "httpx2" else real(name, *a, **kw),
    )
    assert egress.flavor() == "httpx"


# ── Layer 2: Adversarial — the guarantees must not weaken with the flavor ────


def test_policy_denial_is_the_same_typed_error() -> None:
    with FakeBroker(scripted_handler()) as broker:
        with egress.client(socket_path=broker.path, flavor="stdlib") as http:
            with pytest.raises(EgressPolicyDenied) as ei:
                http.get("https://denied.example.com/v1/models")
        assert ei.value.host == "denied.example.com"
        assert ei.value.port == 443


def test_tls_verification_is_not_silently_disabled() -> None:
    """The broker relays opaque bytes; verification is this client's job and it
    must fail on an untrusted cert rather than proceed."""
    with tempfile.TemporaryDirectory() as d:
        cert, key = make_localhost_cert(d)
        with TLSServer(cert, key, body=b"nope") as tls:
            with FakeBroker(relay_handler(tls.host, tls.port)) as broker:
                # verify=True -> the in-test self-signed cert is not trusted.
                with egress.client(socket_path=broker.path, flavor="stdlib") as http:
                    with pytest.raises(Exception) as ei:
                        http.get(f"https://localhost:{tls.port}/")
                assert "certificate" in str(ei.value).lower()


def test_no_broker_raises_rather_than_dialling_direct(monkeypatch) -> None:
    monkeypatch.delenv("HAAP_EGRESS_BROKER_SOCKET", raising=False)
    monkeypatch.delenv("HAAP_AGENT_SOCKET_DIR", raising=False)
    monkeypatch.delenv("HAAP_AGENT_INSTANCE_ID", raising=False)
    with pytest.raises(EgressConfigError):
        egress.client(flavor="stdlib")


def test_post_sends_json_and_reads_status() -> None:
    with tempfile.TemporaryDirectory() as d:
        cert, key = make_localhost_cert(d)
        with TLSServer(cert, key, body=b'{"ok":true}') as tls:
            with FakeBroker(relay_handler(tls.host, tls.port)) as broker:
                with egress.client(
                    socket_path=broker.path, verify=cert, flavor="stdlib"
                ) as http:
                    r = http.post(
                        f"https://localhost:{tls.port}/v1/messages",
                        json={"model": "claude-opus-5", "max_tokens": 8},
                        headers={"x-api-key": "redacted"},
                    )
                assert r.status_code == 200
                assert r.json() == {"ok": True}
                assert r.raise_for_status() is r


def test_raise_for_status_names_the_status() -> None:
    resp = egress._StdlibResponse(429, {}, b"slow down", "https://api.example.com/v1")
    with pytest.raises(EgressHTTPStatusError) as ei:
        resp.raise_for_status()
    assert ei.value.status_code == 429
    assert "429" in str(ei.value)


def test_async_client_refuses_clearly_rather_than_importing_nothing() -> None:
    with pytest.raises(EgressConfigError) as ei:
        egress.async_client(flavor="stdlib")
    assert "async" in str(ei.value).lower()


def test_unknown_flavor_still_rejected() -> None:
    with pytest.raises(EgressConfigError):
        egress.flavor("urllib9")
