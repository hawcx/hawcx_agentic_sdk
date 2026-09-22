"""Tests for the two httpx lineages behind hawcx_haap.egress (ADR-0048).

The Anthropic SDK 1.x is httpx2-based and rejects an old-``httpx`` client at
construction, so ``anthropic.Anthropic(http_client=egress.client())`` is the
case this file exists for. test_egress.py already covers the SOCKS5 wire
behaviour; what is specific here is that two API-identical lineages can both be
installed, that the right one is chosen, and that the caller can tell which.
"""

from __future__ import annotations

import socket
import tempfile

import pytest

pytest.importorskip("httpx2")
import httpx2  # noqa: E402
from egress_broker import (  # noqa: E402
    FakeBroker,
    TLSServer,
    make_localhost_cert,
    relay_handler,
    scripted_handler,
)

from hawcx_haap import egress  # noqa: E402
from hawcx_haap.errors import EgressConfigError, EgressPolicyDenied  # noqa: E402

pytestmark = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="egress broker is UNIX-domain-socket only"
)

_BROKER_ENV = ("HAAP_EGRESS_BROKER_SOCKET", "HAAP_AGENT_SOCKET_DIR", "HAAP_AGENT_INSTANCE_ID")


# ── Layer 1: Example — httpx2 really routes, it does not merely construct ─────


def test_httpx2_client_routes_through_broker() -> None:
    # "Constructs fine" is exactly what the pre-fix code already did, so this
    # asserts bytes on the wire: TLS completes end to end *through* the broker
    # and the broker saw the CONNECT.
    # Kills: MUT-1 (backend swap removed) and MUT-2 (httpcore/httpcore2 streams
    # crossed), both of which still return a usable-looking client.
    with tempfile.TemporaryDirectory() as d:
        cert, key = make_localhost_cert(d)
        with TLSServer(cert, key, body=b"httpx2-through-tunnel") as tls:
            with FakeBroker(relay_handler(tls.host, tls.port)) as broker:
                with egress.client(
                    socket_path=broker.path, verify=cert, flavor="httpx2"
                ) as http:
                    r = http.get(f"https://localhost:{tls.port}/")
                assert r.status_code == 200
                assert r.text == "httpx2-through-tunnel"
                assert len(broker.requests) == 1
                req = broker.requests[0]
                assert req[3] == 0x03  # ATYP DOMAINNAME, never a resolved literal
                assert req[5 : 5 + req[4]] == b"localhost"


async def test_httpx2_async_client_routes_through_broker() -> None:
    with tempfile.TemporaryDirectory() as d:
        cert, key = make_localhost_cert(d)
        with TLSServer(cert, key, body=b"httpx2-async-ok") as tls:
            with FakeBroker(relay_handler(tls.host, tls.port)) as broker:
                async with egress.async_client(
                    socket_path=broker.path, verify=cert, flavor="httpx2"
                ) as http:
                    r = await http.get(f"https://localhost:{tls.port}/")
                assert r.status_code == 200
                assert r.text == "httpx2-async-ok"
                assert len(broker.requests) == 1


def test_client_is_the_real_type_the_anthropic_sdk_accepts() -> None:
    # The whole point of Task 1. Asserting the real type, not duck-typing:
    # anthropic 1.7.0 raises TypeError on an httpx.Client with
    # "this SDK uses `httpx2`". Kills MUT-3 (precedence reversed).
    with FakeBroker(scripted_handler()) as broker:
        client = egress.client(socket_path=broker.path, verify=False)
        with client:
            assert isinstance(client, httpx2.Client)
            anthropic = pytest.importorskip("anthropic")
            # Must not raise: this is the customer-blocking construction.
            anthropic.Anthropic(api_key="sk-ant-not-a-real-key", http_client=client)


def test_backend_is_built_from_the_matching_httpcore_lineage() -> None:
    """The (httpx2, httpcore2) / (httpx, httpcore) pairing is deliberate.

    Measured 2026-09-21: httpcore 1.0.9 and httpcore2 2.13.0 stream classes are
    duck-compatible, so feeding an httpx2 pool httpcore-1 streams still works
    end to end — a behavioural test cannot see the crossing. Only a structural
    assertion catches it, and it needs to, because the two lineages are free to
    diverge at any release and the failure would then be a silent direct dial.
    Kills MUT-2 (core_name hardcoded to "httpcore").
    """
    import httpcore
    import httpcore2

    for which, want, other in (
        ("httpx2", httpcore2.NetworkBackend, httpcore.NetworkBackend),
        ("httpx", httpcore.NetworkBackend, httpcore2.NetworkBackend),
    ):
        pytest.importorskip(which)
        sync_cls, _ = egress._build_transports(which)
        with FakeBroker(scripted_handler()) as broker:
            transport = sync_cls(broker.path, verify=False)
            backend = transport._pool._network_backend
            assert isinstance(backend, want), f"{which}: backend not from its own httpcore"
            assert not isinstance(backend, other), f"{which}: backend crossed lineages"


# ── Layer 2: Adversarial — flavor selection, and failures stay typed ──────────


def test_httpx2_wins_when_both_lineages_are_installed() -> None:
    # Documented precedence. Skips rather than passing vacuously if the old
    # lineage is absent, so this can never report "both installed" from one.
    pytest.importorskip("httpx")
    assert egress.flavor() == "httpx2"


def test_flavor_override_returns_the_old_lineage() -> None:
    httpx = pytest.importorskip("httpx")
    with FakeBroker(scripted_handler()) as broker:
        with egress.client(socket_path=broker.path, verify=False, flavor="httpx") as c:
            assert isinstance(c, httpx.Client)
            assert not isinstance(c, httpx2.Client)


def test_unknown_flavor_is_rejected() -> None:
    with pytest.raises(EgressConfigError) as ei:
        egress.flavor("httpx3")
    assert "httpx3" in str(ei.value)


def test_neither_lineage_installed_falls_back_to_stdlib(monkeypatch) -> None:
    # CONTRACT CHANGE, deliberate: this used to assert EgressConfigError. An
    # agent packaged by `hawcx_haap.source_bundle` has neither lineage and
    # cannot install one ("offline builds never run pip"), so raising here made
    # the shim unusable in exactly the deployment the SDK ships for. The
    # default path now resolves to the stdlib client; see test_egress_stdlib.py.
    import importlib.util

    real_find_spec = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util,
        "find_spec",
        lambda name, *a, **k: None
        if name in ("httpx", "httpx2")
        else real_find_spec(name, *a, **k),
    )
    assert egress.flavor() == "stdlib"


def test_explicit_missing_lineage_raises_config_error_not_import_error(monkeypatch) -> None:
    # MUT-4 lives here now: asking for a lineage BY NAME that is not installed
    # must still be a clear EgressConfigError, never a ModuleNotFoundError
    # leaking out of find_spec. The stdlib fallback must not swallow this --
    # a caller who named httpx2 wants httpx2 (the Anthropic SDK rejects
    # anything else), and silently handing back another client would be worse
    # than failing.
    import importlib.util

    real_find_spec = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util,
        "find_spec",
        lambda name, *a, **k: None
        if name in ("httpx", "httpx2")
        else real_find_spec(name, *a, **k),
    )
    for named in ("httpx2", "httpx"):
        with pytest.raises(EgressConfigError) as ei:
            egress.flavor(named)
        assert not isinstance(ei.value, ImportError)
        assert named in str(ei.value)


@pytest.mark.parametrize("which", ["httpx2", "httpx"])
def test_policy_denial_stays_typed_on_both_lineages(which: str) -> None:
    pytest.importorskip(which)
    reply = bytes([0x05, 0x02, 0x00, 0x01]) + bytes(6)
    with FakeBroker(scripted_handler(connect_reply=reply)) as broker:
        with egress.client(
            socket_path=broker.path, verify=False, timeout=3, flavor=which
        ) as http:
            with pytest.raises(EgressPolicyDenied) as ei:
                http.get("https://blocked.example.com:8443/")
    assert ei.value.host == "blocked.example.com"
    assert ei.value.port == 8443


@pytest.mark.parametrize("which", ["httpx2", "httpx"])
def test_renamed_httpcore_seam_fails_loud_never_silently_direct(monkeypatch, which: str) -> None:
    """The ``assert hasattr(self._pool, "_network_backend")`` guard is deliberate.

    If httpcore ever renames that internal, the backend swap would silently
    no-op and every request would dial the real network instead of the broker —
    the one failure this whole module exists to prevent. Simulate the rename and
    require a loud failure. Kills MUT-8 (guard replaced by a swallowing
    try/except).

    Ceiling: `python -O` strips asserts, so this guard (and this test) rely on
    assertions being enabled. That is unchanged from before this commit.
    """
    httpx_mod = pytest.importorskip(which)
    egress._build_transports(which)  # build before patching, as production does

    class _PoolWithoutTheSeam:  # stands in for a renamed httpcore internal
        pass

    real_init = httpx_mod.HTTPTransport.__init__

    def fake_init(self, **kwargs):
        real_init(self, **kwargs)
        self._pool = _PoolWithoutTheSeam()

    monkeypatch.setattr(httpx_mod.HTTPTransport, "__init__", fake_init)
    with FakeBroker(scripted_handler()) as broker:
        with pytest.raises(AssertionError):
            egress.client(socket_path=broker.path, verify=False, flavor=which)


# ── The contract test: no broker must never yield a direct client ────────────


@pytest.mark.parametrize("which", ["httpx2", "httpx"])
def test_no_broker_raises_rather_than_returning_a_direct_client(monkeypatch, which: str) -> None:
    pytest.importorskip(which)
    for var in _BROKER_ENV:
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(EgressConfigError):
        egress.client(flavor=which)
    with pytest.raises(EgressConfigError):
        egress.async_client(flavor=which)


@pytest.mark.parametrize("which", ["httpx2", "httpx"])
def test_configured_but_missing_socket_raises(monkeypatch, tmp_path, which: str) -> None:
    pytest.importorskip(which)
    monkeypatch.setenv("HAAP_EGRESS_BROKER_SOCKET", str(tmp_path / "absent.sock"))
    with pytest.raises(EgressConfigError):
        egress.client(flavor=which)
    with pytest.raises(EgressConfigError):
        egress.async_client(flavor=which)


def test_configured_but_not_a_socket_raises(monkeypatch, tmp_path) -> None:
    plain = tmp_path / "regular-file"
    plain.write_text("not a socket")
    monkeypatch.setenv("HAAP_EGRESS_BROKER_SOCKET", str(plain))
    with pytest.raises(EgressConfigError):
        egress.client()
