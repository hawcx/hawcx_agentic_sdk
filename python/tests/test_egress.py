"""Tests for hawcx_haap.egress — the SOCKS5-over-UDS egress transport (ADR-0048).

Four layers per docs/engineering/TESTING-STANDARD.md:
  1. Example        — success end-to-end incl. TLS completing through the tunnel
  2. Adversarial    — each reply code → its own exception; no ATYP 0x01/0x04 ever
  3. Stateful       — many sequential + concurrent requests, no cross-request leak
  4. Boundary-fuzz  — truncated/malformed/oversized/random bytes → defined errors
"""

from __future__ import annotations

import random
import socket
import sys
import tempfile
import threading

import pytest

pytest.importorskip("httpx")
import httpx  # noqa: E402

from hawcx_haap import egress  # noqa: E402
from hawcx_haap.egress import _connect_request  # noqa: E402
from hawcx_haap.errors import (  # noqa: E402
    EgressConfigError,
    EgressHostUnreachable,
    EgressPeerCredError,
    EgressPolicyDenied,
    EgressProtocolError,
    HawcxError,
)
from egress_broker import (  # noqa: E402
    FakeBroker,
    TLSServer,
    close_no_reply_handler,
    make_localhost_cert,
    relay_handler,
    reset_no_reply_handler,
    scripted_handler,
)

pytestmark = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="egress broker is UNIX-domain-socket only"
)


# ── Layer 1: Example — success + TLS through the opaque tunnel ────────────────


def test_example_tls_completes_through_tunnel() -> None:
    with tempfile.TemporaryDirectory() as d:
        cert, key = make_localhost_cert(d)
        with TLSServer(cert, key, body=b"hello-through-tunnel") as tls:
            with FakeBroker(relay_handler(tls.host, tls.port)) as broker:
                with egress.client(socket_path=broker.path, verify=cert) as http:
                    r = http.get(f"https://localhost:{tls.port}/")
                assert r.status_code == 200
                assert r.text == "hello-through-tunnel"
            # The broker saw exactly one CONNECT, ATYP=DOMAINNAME "localhost".
            assert len(broker.requests) == 1
            req = broker.requests[0]
            assert req[3] == 0x03  # ATYP DOMAINNAME
            dom_len = req[4]
            assert req[5 : 5 + dom_len] == b"localhost"


async def test_example_async_tls_through_tunnel() -> None:
    with tempfile.TemporaryDirectory() as d:
        cert, key = make_localhost_cert(d)
        with TLSServer(cert, key, body=b"async-ok") as tls:
            with FakeBroker(relay_handler(tls.host, tls.port)) as broker:
                async with egress.async_client(socket_path=broker.path, verify=cert) as http:
                    r = await http.get(f"https://localhost:{tls.port}/")
                assert r.status_code == 200
                assert r.text == "async-ok"


# ── Layer 2: Adversarial ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "rep,exc",
    [
        (0x02, EgressPolicyDenied),
        (0x04, EgressHostUnreachable),
        (0x07, EgressProtocolError),  # command not supported — shim bug
        (0x08, EgressProtocolError),  # address type not supported — shim bug
        (0x01, EgressProtocolError),  # generic SOCKS failure
    ],
)
def test_reply_code_maps_to_distinct_exception(rep: int, exc: type) -> None:
    reply = bytes([0x05, rep, 0x00, 0x01]) + bytes(6)
    with FakeBroker(scripted_handler(connect_reply=reply)) as broker:
        with egress.client(socket_path=broker.path, verify=False, timeout=3) as http:
            with pytest.raises(exc):
                http.get("https://denied.example.com/")


def test_policy_denied_names_host_and_port() -> None:
    reply = bytes([0x05, 0x02, 0x00, 0x01]) + bytes(6)
    with FakeBroker(scripted_handler(connect_reply=reply)) as broker:
        with egress.client(socket_path=broker.path, verify=False, timeout=3) as http:
            with pytest.raises(EgressPolicyDenied) as ei:
                http.get("https://blocked.example.com:8443/")
    assert ei.value.host == "blocked.example.com"
    assert ei.value.port == 8443


def test_greeting_rejection_05FF_reported_clearly() -> None:
    with FakeBroker(scripted_handler(method_reply=b"\x05\xff")) as broker:
        with egress.client(socket_path=broker.path, verify=False, timeout=3) as http:
            with pytest.raises(EgressProtocolError) as ei:
                http.get("https://x.example.com/")
    assert "05 FF" in str(ei.value) or "NO-AUTH" in str(ei.value)


def test_closed_with_no_reply_is_peercred_error() -> None:
    with FakeBroker(close_no_reply_handler) as broker:
        with egress.client(socket_path=broker.path, verify=False, timeout=3) as http:
            with pytest.raises(EgressPeerCredError):
                http.get("https://x.example.com/")


def test_reset_instead_of_clean_close_is_still_peercred_error() -> None:
    # Same broker behaviour as the test above, asking for an RST rather than a FIN.
    # The property under test is the contract — only EgressError subclasses cross this
    # boundary — not which wire event delivers it. On Linux the broker's close really
    # does arrive as ECONNRESET and this failed before the fix; on macOS SO_LINGER is a
    # no-op for AF_UNIX, so there it degrades to the clean-close case above.
    with FakeBroker(reset_no_reply_handler) as broker:
        with egress.client(socket_path=broker.path, verify=False, timeout=3) as http:
            with pytest.raises(EgressPeerCredError):
                http.get("https://x.example.com/")


def test_ip_literal_url_is_sent_as_domainname_never_atyp_1_or_4() -> None:
    # Even handed a bare IP, the shim sends ATYP=0x03 with the literal as a NAME
    # and never resolves it (ADR-0048 Amendment 2: literal IPs are denied).
    reply = bytes([0x05, 0x02, 0x00, 0x01]) + bytes(6)  # broker denies; we only inspect the request
    with FakeBroker(scripted_handler(connect_reply=reply)) as broker:
        with egress.client(socket_path=broker.path, verify=False, timeout=3) as http:
            with pytest.raises(EgressPolicyDenied):
                http.get("https://127.0.0.1:9/")
    assert len(broker.requests) == 1
    req = broker.requests[0]
    assert req[3] == 0x03, "ATYP must be DOMAINNAME (0x03), never 0x01/0x04"
    assert req[5 : 5 + req[4]] == b"127.0.0.1"


def test_missing_socket_raises_no_direct_fallback() -> None:
    with pytest.raises(EgressConfigError):
        egress.client(socket_path="/nonexistent/egress-broker.sock")


def test_non_socket_path_raises(tmp_path) -> None:
    regular = tmp_path / "not-a-socket"
    regular.write_text("x")
    with pytest.raises(EgressConfigError):
        egress.client(socket_path=str(regular))


def test_resolve_from_env(monkeypatch) -> None:
    with FakeBroker(scripted_handler()) as broker:
        import os

        monkeypatch.setenv("HAAP_AGENT_SOCKET_DIR", os.path.dirname(os.path.dirname(broker.path)))
        # HAAP_EGRESS_BROKER_SOCKET explicit override wins:
        monkeypatch.setenv("HAAP_EGRESS_BROKER_SOCKET", broker.path)
        assert egress.resolve_socket_path() == broker.path
    monkeypatch.delenv("HAAP_EGRESS_BROKER_SOCKET")
    monkeypatch.delenv("HAAP_AGENT_SOCKET_DIR", raising=False)
    with pytest.raises(EgressConfigError):
        egress.resolve_socket_path()


@pytest.mark.parametrize("host", ["", "\x00bad", "no\x00ul.com", "ünïcödé\x00.com"])
def test_bad_hostnames_raise_before_wire(host: str) -> None:
    with pytest.raises(EgressProtocolError):
        _connect_request(host, 443)


def test_domainname_255_ok_256_rejected() -> None:
    _connect_request("a" * 255, 443)  # exactly at the single-byte length cap
    with pytest.raises(EgressProtocolError):
        _connect_request("a" * 256, 443)


@pytest.mark.parametrize("port", [-1, 65536, 999999])
def test_out_of_range_port_rejected(port: int) -> None:
    with pytest.raises(EgressProtocolError):
        _connect_request("host.example", port)


# ── Layer 3: Stateful / concurrency ───────────────────────────────────────────


def test_sequential_distinct_hosts_each_get_fresh_connect() -> None:
    hosts = [f"h{i}.example.com" for i in range(12)]
    with tempfile.TemporaryDirectory() as d:
        cert, key = make_localhost_cert(d)
        with TLSServer(cert, key) as tls:
            with FakeBroker(relay_handler(tls.host, tls.port)) as broker:
                with egress.client(socket_path=broker.path, verify=False, timeout=5) as http:
                    for h in hosts:
                        r = http.get(f"https://{h}:{tls.port}/")
                        assert r.status_code == 200
                seen = _captured_hosts(broker)
    assert seen == set(hosts), "each distinct destination must open its own CONNECT, no cross-talk"


def test_concurrent_requests_no_host_leak() -> None:
    hosts = [f"c{i}.example.org" for i in range(16)]
    with tempfile.TemporaryDirectory() as d:
        cert, key = make_localhost_cert(d)
        with TLSServer(cert, key) as tls:
            with FakeBroker(relay_handler(tls.host, tls.port)) as broker:
                errors: list[BaseException] = []
                with egress.client(socket_path=broker.path, verify=False, timeout=5) as http:

                    def go(h: str) -> None:
                        try:
                            assert http.get(f"https://{h}:{tls.port}/").status_code == 200
                        except BaseException as e:  # noqa: BLE001
                            errors.append(e)

                    threads = [threading.Thread(target=go, args=(h,)) for h in hosts]
                    for t in threads:
                        t.start()
                    for t in threads:
                        t.join()
                assert not errors, errors
                seen = _captured_hosts(broker)
    assert seen == set(hosts)


def _captured_hosts(broker: FakeBroker) -> set[str]:
    out = set()
    for req in broker.requests:
        assert req[3] == 0x03
        out.add(req[5 : 5 + req[4]].decode())
    return out


# ── Layer 4: Boundary-fuzz (mandatory) ─────────────────────────────────────────

_DEFINED = (HawcxError, httpx.HTTPError)


def _fuzz_case_ok(
    broker_handler, url: str = "https://fuzz.example.com/", timeout: float = 2.0
) -> None:
    with FakeBroker(broker_handler) as broker:
        with egress.client(socket_path=broker.path, verify=False, timeout=timeout) as http:
            try:
                resp = http.get(url)
            except _DEFINED:
                return  # defined failure — acceptable
            except BaseException as e:  # noqa: BLE001
                raise AssertionError(
                    f"undefined exception type escaped: {type(e).__name__}: {e}"
                ) from e
            raise AssertionError(
                f"fuzz input unexpectedly produced a success response: {resp.status_code}"
            )


def test_boundary_fuzz_defined_exceptions_only() -> None:
    iterations = 0

    # 1. Truncated / disconnect at each handshake stage.
    def hold_after_greeting(conn: socket.socket, b: FakeBroker) -> None:
        from egress_broker import recv_exact

        recv_exact(conn, 3)
        conn.sendall(b"\x05\x00")
        # read request then hold the socket open, sending no reply → client times out
        try:
            conn.recv(4096)
        except OSError:
            pass
        threading.Event().wait(10)  # held; the client's own timeout must fire first

    staged = [
        close_no_reply_handler,  # closed before any reply
        reset_no_reply_handler,  # RST before any reply (Linux's real peer-cred rejection)
        scripted_handler(connect_reply=b""),  # greeting ok, then closed with no CONNECT reply
        scripted_handler(connect_reply=b"\x05"),  # 1-byte truncated reply
        scripted_handler(connect_reply=b"\x05\x00\x00"),  # header truncated (3 of 4)
        scripted_handler(
            connect_reply=b"\x05\x00\x00\x03"
        ),  # DOMAINNAME reply, missing length byte
        scripted_handler(
            connect_reply=b"\x05\x00\x00\x03\x0a" + b"partial"
        ),  # len says 10, sends 7
        scripted_handler(connect_reply=b"\x05\x00\x00\x09" + bytes(4)),  # bogus ATYP 0x09
        scripted_handler(connect_reply=b"\x99\x00\x00\x01" + bytes(6)),  # bad SOCKS version
        scripted_handler(method_reply=b"\x99\x00"),  # bad version in method reply
        scripted_handler(method_reply=b"\x05\x02"),  # unsupported method selected
        scripted_handler(
            connect_reply=b"\x05\x00\x00\x01" + bytes(6) + b"x" * 4096
        ),  # oversized trailer
        hold_after_greeting,  # no reply at all → must hit client timeout, not hang
    ]
    for h in staged:
        _fuzz_case_ok(h, timeout=1.5)
        iterations += 1

    # 2. Randomized reply bytes (deterministic seed).
    rng = random.Random(0x0048)
    for _ in range(240):
        n = rng.randint(0, 48)
        blob = bytes(rng.randrange(256) for _ in range(n))
        _fuzz_case_ok(scripted_handler(connect_reply=blob), timeout=1.5)
        iterations += 1

    print(f"\n[boundary-fuzz] egress SOCKS5 reply parser: {iterations} iterations, all defined")
    assert iterations == 13 + 240


if __name__ == "__main__":  # pragma: no cover - quick self-check
    sys.exit(pytest.main([__file__, "-v", "-s"]))
