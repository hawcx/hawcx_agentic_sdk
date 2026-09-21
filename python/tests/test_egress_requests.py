"""Tests for hawcx_haap.egress.requests_session — the urllib3/requests side.

The Google client libraries are requests-based (google-auth's
``AuthorizedSession``), so the httpx transport cannot carry them. Same broker,
same no-silent-fallback contract; a different seam (urllib3's ``_new_conn``).
"""

from __future__ import annotations

import socket
import tempfile

import pytest

pytest.importorskip("requests")

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


# ── Layer 1: Example — a session really routes, TLS intact through the pipe ──


def test_requests_session_routes_through_broker() -> None:
    # Kills MUT-5 (pool_classes_by_scheme swap removed): a session that skipped
    # the swap dials 127.0.0.1 directly and never appears at the broker.
    with tempfile.TemporaryDirectory() as d:
        cert, key = make_localhost_cert(d)
        with TLSServer(cert, key, body=b"requests-through-tunnel") as tls:
            with FakeBroker(relay_handler(tls.host, tls.port)) as broker:
                session = egress.requests_session(socket_path=broker.path)
                r = session.get(f"https://localhost:{tls.port}/", verify=cert, timeout=10)
                assert r.status_code == 200
                assert r.text == "requests-through-tunnel"
                assert len(broker.requests) == 1
                req = broker.requests[0]
                assert req[3] == 0x03  # ATYP DOMAINNAME
                assert req[5 : 5 + req[4]] == b"localhost"


def test_session_works_with_no_explicit_timeout() -> None:
    # The default-timeout path end to end. No mutation claim: urllib3 2.x
    # resolves its sentinel inside HTTPConnection.__init__ (measured on 2.0.7 /
    # 2.2.3 / 2.8.0), so the shim's sentinel branch is unreachable there and
    # removing it is an equivalent mutation. This still pins that a request with
    # no timeout= reaches the broker and completes.
    with tempfile.TemporaryDirectory() as d:
        cert, key = make_localhost_cert(d)
        with TLSServer(cert, key, body=b"ok") as tls:
            with FakeBroker(relay_handler(tls.host, tls.port)) as broker:
                session = egress.requests_session(socket_path=broker.path)
                # No `timeout=` at all — this is the sentinel path.
                r = session.get(f"https://localhost:{tls.port}/", verify=cert)
                assert r.status_code == 200


def test_adapter_can_be_mounted_onto_a_foreign_session() -> None:
    """The documented google-auth path: AuthorizedSession builds its own
    requests.Session, so callers mount our brokered adapter onto theirs rather
    than using our session object. This pins the exact snippet in README.md.
    """
    import requests

    with tempfile.TemporaryDirectory() as d:
        cert, key = make_localhost_cert(d)
        with TLSServer(cert, key, body=b"adapter-mount-works") as tls:
            with FakeBroker(relay_handler(tls.host, tls.port)) as broker:
                foreign = requests.Session()  # stands in for AuthorizedSession(creds)
                adapter = egress.requests_session(socket_path=broker.path).get_adapter(
                    "https://"
                )
                foreign.mount("https://", adapter)
                r = foreign.get(f"https://localhost:{tls.port}/", verify=cert, timeout=10)
                assert r.status_code == 200
                assert r.text == "adapter-mount-works"
                assert len(broker.requests) == 1


# ── Layer 2: Adversarial — the allowlist depends on the name, not an address ─


def test_broker_receives_the_hostname_the_caller_asked_for() -> None:
    # Security, not style: the broker's allowlist is by hostname. A session that
    # resolved DNS locally and dialled the result would present an address the
    # allowlist cannot match. `.invalid` is guaranteed never to resolve
    # (RFC 6761), so reaching the broker at all proves no local resolution
    # happened. Kills MUT-6 (self.host -> socket.gethostbyname(self.host)),
    # which is what an allowlist-bypassing regression actually looks like.
    reply = bytes([0x05, 0x02, 0x00, 0x01]) + bytes(6)  # broker denies; we inspect the request
    with FakeBroker(scripted_handler(connect_reply=reply)) as broker:
        session = egress.requests_session(socket_path=broker.path)
        with pytest.raises(EgressPolicyDenied) as ei:
            session.get("https://never-resolves.invalid:8443/", timeout=5)
    assert ei.value.host == "never-resolves.invalid"
    assert ei.value.port == 8443
    assert len(broker.requests) == 1
    req = broker.requests[0]
    assert req[3] == 0x03
    assert req[5 : 5 + req[4]] == b"never-resolves.invalid"


def test_egress_errors_are_not_swallowed_into_requests_exceptions() -> None:
    # The shim's contract is that a typed EgressError escapes. requests wraps a
    # lot of urllib3 failures into requests.exceptions.ConnectionError; this
    # pins that ours is not one of them.
    import requests as _requests

    reply = bytes([0x05, 0x02, 0x00, 0x01]) + bytes(6)
    with FakeBroker(scripted_handler(connect_reply=reply)) as broker:
        session = egress.requests_session(socket_path=broker.path)
        with pytest.raises(EgressPolicyDenied) as ei:
            session.get("https://blocked.example.com/", timeout=5)
    assert not isinstance(ei.value, _requests.exceptions.RequestException)


# ── The contract test: no broker must never yield a direct session ───────────


def test_no_broker_raises_rather_than_returning_a_direct_session(monkeypatch) -> None:
    for var in _BROKER_ENV:
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(EgressConfigError):
        egress.requests_session()


def test_configured_but_missing_socket_raises(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("HAAP_EGRESS_BROKER_SOCKET", str(tmp_path / "absent.sock"))
    with pytest.raises(EgressConfigError):
        egress.requests_session()


def test_configured_but_not_a_socket_raises(monkeypatch, tmp_path) -> None:
    plain = tmp_path / "regular-file"
    plain.write_text("not a socket")
    monkeypatch.setenv("HAAP_EGRESS_BROKER_SOCKET", str(plain))
    with pytest.raises(EgressConfigError):
        egress.requests_session()


def test_resolves_from_env_like_the_httpx_client(monkeypatch) -> None:
    with FakeBroker(scripted_handler()) as broker:
        monkeypatch.setenv("HAAP_EGRESS_BROKER_SOCKET", broker.path)
        assert egress.requests_session() is not None
