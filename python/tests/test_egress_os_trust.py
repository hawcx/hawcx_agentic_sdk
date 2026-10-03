"""The agent's own TLS behind a TLS-inspecting proxy (Zscaler/Netskope style).

The egress broker relays opaque bytes, so the agent verifies its provider's
certificate itself. Behind an inspecting proxy the chain is re-signed by a
corporate root that MDM put in the OS trust store — which certifi does not
hold and which a Seatbelt-confined agent cannot consult. The supervisor
exports the OS store to a PEM file and names it in ``HAAP_AGENT_OS_TRUST_ROOTS``.

The fixture plays the proxy: a TLS server presenting a leaf for the REAL
hostname ``api.anthropic.com`` signed by "Hawcx Test Inspecting Proxy Root CA",
reached through the fake broker exactly as a confined agent reaches the world.
Nothing here touches this machine's trust store.
"""

from __future__ import annotations

import socket
import ssl
from pathlib import Path

import pytest
from egress_broker import FakeBroker, TLSServer, relay_handler

from hawcx_haap import egress

pytestmark = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="egress broker is UNIX-domain-socket only"
)

MITM = Path(__file__).parent / "fixtures" / "mitm"
URL = "https://api.anthropic.com/v1/messages"
BODY = b'{"type":"message","content":[{"type":"text","text":"through the proxy"}]}'


@pytest.fixture
def proxy():
    with TLSServer(str(MITM / "mitm-chain.pem"), str(MITM / "mitm-leaf.key"), body=BODY) as tls:
        with FakeBroker(relay_handler(tls.host, tls.port)) as broker:
            yield broker


@pytest.fixture
def staged(monkeypatch):
    """The supervisor staged the OS store, and it holds the proxy's root."""
    monkeypatch.setenv(egress.ENV_OS_TRUST_ROOTS, str(MITM / "mitm-root.pem"))


@pytest.fixture
def not_staged(monkeypatch):
    monkeypatch.delenv(egress.ENV_OS_TRUST_ROOTS, raising=False)


# ── Layer 1: the LLM call through the proxy, every client flavor ──────────────


@pytest.mark.parametrize("flavor", ["httpx2", "httpx", "stdlib"])
def test_llm_call_succeeds_with_the_staged_os_roots(proxy, staged, flavor) -> None:
    pytest.importorskip(flavor) if flavor != "stdlib" else None
    with egress.client(socket_path=proxy.path, flavor=flavor) as http:
        r = http.post(URL, content=b"{}")
    assert r.status_code == 200
    assert r.text == BODY.decode()
    assert proxy.requests[0][5 : 5 + proxy.requests[0][4]] == b"api.anthropic.com"


@pytest.mark.parametrize("flavor", ["httpx2", "httpx", "stdlib"])
def test_llm_call_refuses_without_them(proxy, not_staged, flavor) -> None:
    """Negative control: the same proxy, nothing staged — the chain must fail
    verification (certifi / OpenSSL defaults do not hold the corporate root)."""
    pytest.importorskip(flavor) if flavor != "stdlib" else None
    with pytest.raises(Exception) as caught:
        with egress.client(socket_path=proxy.path, flavor=flavor) as http:
            http.post(URL, content=b"{}")
    assert (
        "CERTIFICATE_VERIFY_FAILED" in repr(caught.value)
        or "certificate" in repr(caught.value).lower()
    ), repr(caught.value)


async def test_async_client_uses_the_staged_roots(proxy, staged) -> None:
    pytest.importorskip("httpx2")
    async with egress.async_client(socket_path=proxy.path, flavor="httpx2") as http:
        r = await http.post(URL, content=b"{}")
    assert r.status_code == 200


def test_requests_session_uses_the_staged_roots(proxy, staged) -> None:
    pytest.importorskip("requests")
    with egress.requests_session(socket_path=proxy.path) as s:
        r = s.post(URL, data=b"{}")
    assert r.status_code == 200


def test_requests_session_refuses_without_them(proxy, not_staged) -> None:
    requests = pytest.importorskip("requests")
    with pytest.raises(requests.exceptions.SSLError):
        with egress.requests_session(socket_path=proxy.path) as s:
            s.post(URL, data=b"{}")


# ── Layer 2: ADDITIVE, never replacing; caller choices untouched ──────────────


def test_tls_context_keeps_the_public_roots(staged) -> None:
    pytest.importorskip("certifi")
    public_only = ssl.create_default_context(cafile=egress._default_cafile())
    combined = egress.tls_context()
    assert len(combined.get_ca_certs()) == len(public_only.get_ca_certs()) + 1


def test_an_explicit_verify_is_never_rewritten(staged) -> None:
    ctx = ssl.create_default_context()
    assert egress._effective_verify(ctx) is ctx
    assert egress._effective_verify(False) is False
    assert egress._effective_verify("/some/ca.pem") == "/some/ca.pem"
    assert isinstance(egress._effective_verify(True), ssl.SSLContext)


def test_nothing_staged_leaves_verify_true_alone(not_staged) -> None:
    assert egress._effective_verify(True) is True
    assert egress.os_trust_roots_path() is None


def test_a_missing_staged_file_is_treated_as_not_staged(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv(egress.ENV_OS_TRUST_ROOTS, str(tmp_path / "absent.pem"))
    assert egress.os_trust_roots_path() is None


def test_a_corrupt_staged_bundle_fails_loudly(monkeypatch, tmp_path) -> None:
    bad = tmp_path / "bad.pem"
    bad.write_text("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n")
    monkeypatch.setenv(egress.ENV_OS_TRUST_ROOTS, str(bad))
    with pytest.raises(ssl.SSLError):
        egress.tls_context()


def test_the_env_name_matches_the_supervisor_contract() -> None:
    # haap-supervisor `tls_trust::ENV_AGENT_OS_TRUST_ROOTS`.
    assert egress.ENV_OS_TRUST_ROOTS == "HAAP_AGENT_OS_TRUST_ROOTS"
