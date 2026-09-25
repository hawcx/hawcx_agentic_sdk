"""The Windows egress arm: the supervisor's placed control channel (#508 gap 1).

Spec, quoted from hx_agent_client_auth_service
``crates/haap-supervisor/src/egress_broker.rs`` (``pub mod mux``)::

    request  [REQ_CONNECT][port hi][port lo][host len][host bytes…]
    reply    [status][socks5 rep][handle b0][b1][b2][b3]          (REPLY_LEN)

``REQ_CONNECT=0x01``; status ``OK=0x00`` / ``DENIED=0x01`` / ``BUSY=0x02`` /
``VEND_FAILED=0x03``; ``REPLY_LEN=6``; big-endian. The control handle arrives
as a decimal value in ``$HAAP_EGRESS_BROKER_HANDLE`` (graph.rs
``ENV_EGRESS_BROKER_HANDLE``); on OK the handle field names a fresh pipe
already connected to the endpoint, carrying raw bytes (no SOCKS5).

Most rows run on every OS: only the OS handle layer (``_win_adopt`` /
``_win_is_readable``) is replaced, by a table of socketpair ends, and a fake
supervisor thread speaks the wire format above. Everything else -- the
control client, framing validation, the vended stream, TLS over it, and the
stdlib / httpx / httpx2 clients -- is the production code. The last rows run
only on Windows and use real overlapped named pipes and ``DuplicateHandle``.
"""

from __future__ import annotations

import itertools
import select
import socket
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from typing import Any

import pytest
from egress_broker import TLSServer, make_localhost_cert

from hawcx_haap import egress
from hawcx_haap.errors import (
    EgressBrokerBusy,
    EgressConfigError,
    EgressHostUnreachable,
    EgressPolicyDenied,
    EgressProtocolError,
)

ENV = "HAAP_EGRESS_BROKER_HANDLE"


# ── fake supervisor (speaks egress_broker.rs `serve_mux_control`) ────────────


def _recv_exact(ch: Any, n: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = ch.recv(n - len(buf))
        except Exception:  # noqa: BLE001 - OSError (socket) or IpcError (pipe)
            return None
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def _close(ch: Any) -> None:
    try:
        if isinstance(ch, socket.socket):
            ch.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        ch.close()
    except OSError:
        pass


def _pump(a: Any, b: Any) -> None:
    def copy(src: Any, dst: Any) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except Exception:  # noqa: BLE001 - test double: any failure ends the relay
            pass
        finally:
            _close(src)
            _close(dst)

    threading.Thread(target=copy, args=(a, b), daemon=True).start()
    threading.Thread(target=copy, args=(b, a), daemon=True).start()


def reply(status: int, rep: int = 0, handle: int = 0) -> bytes:
    return bytes([status, rep]) + handle.to_bytes(4, "big")


Script = Callable[[int, str, int], "bytes | None"]


class FakeSupervisor:
    """One control channel, served sequentially, like ``serve_mux_control``.

    ``vend()`` returns ``(supervisor_end, handle_value_in_agent)``. ``script``
    (index, host, port) may return raw reply bytes to send instead of the
    real behaviour, or ``None`` to close the channel without replying."""

    def __init__(
        self,
        control: Any,
        vend: Callable[[], tuple[Any, int]],
        upstream: tuple[str, int] | None = None,
        allow: Callable[[str, int], bool] = lambda h, p: True,
        script: Script | None = None,
    ) -> None:
        self._control = control
        self._vend = vend
        self._upstream = upstream
        self._allow = allow
        self._script = script
        self.requests: list[bytes] = []
        self.dials = 0
        self._t = threading.Thread(target=self._loop, daemon=True)

    def __enter__(self) -> FakeSupervisor:
        self._t.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        _close(self._control)

    def _loop(self) -> None:
        try:
            self._serve()
        except Exception:  # noqa: BLE001 - the agent side hung up; the double just ends
            pass

    def _serve(self) -> None:
        while True:
            op = _recv_exact(self._control, 1)
            if op is None:
                return
            if op[0] != 0x01:  # unknown opcode: close, never answer
                _close(self._control)
                return
            rest = _recv_exact(self._control, 3)
            if rest is None:
                return
            host_b = _recv_exact(self._control, rest[2]) if rest[2] else b""
            if host_b is None:
                return
            self.requests.append(op + rest + host_b)
            host, port = host_b.decode("utf-8"), int.from_bytes(rest[:2], "big")
            if self._script is not None:
                out = self._script(len(self.requests) - 1, host, port)
                if out is not None:  # b"" = the script already answered
                    if out:
                        self._control.sendall(out)
                    continue
                if not self._falls_through:
                    _close(self._control)
                    return
            if not self._allow(host, port):
                self._control.sendall(reply(0x01, 0x02))
                continue
            assert self._upstream is not None
            up = socket.create_connection(self._upstream)
            self.dials += 1
            server_end, handle = self._vend()
            self._control.sendall(reply(0x00, 0x00, handle))
            _pump(server_end, up)

    _falls_through = False


class FallThrough(FakeSupervisor):
    """A scripted supervisor whose script returning ``None`` means "behave
    normally" rather than "close"."""

    _falls_through = True


# ── the fake OS handle layer: handle values → socketpair ends ────────────────


class HandleTable:
    def __init__(self) -> None:
        self._next = itertools.count(0x1F4, 4)  # handle-shaped values
        self.handles: dict[int, socket.socket] = {}
        self.adopted: list[int] = []

    def put(self, s: socket.socket) -> int:
        h = next(self._next)
        self.handles[h] = s
        return h

    def adopt(self, h: int) -> socket.socket:
        if h not in self.handles:
            raise EgressConfigError(f"egress broker handle {h} is not a pipe (GetFileType=0)")
        self.adopted.append(h)
        return self.handles[h]

    def vend(self) -> tuple[socket.socket, int]:
        a, b = socket.socketpair()
        return a, self.put(b)


@pytest.fixture
def placed(monkeypatch: pytest.MonkeyPatch):
    """Drive the Windows code path with a socketpair control channel."""
    table = HandleTable()
    sup_end, agent_end = socket.socketpair()
    control_handle = table.put(agent_end)
    monkeypatch.setattr(egress, "_placed_channel_platform", lambda: True)
    monkeypatch.setattr(egress, "_win_adopt", table.adopt)

    def readable(raw: socket.socket) -> bool:
        r, _, _ = select.select([raw], [], [], 0)
        return bool(r)

    monkeypatch.setattr(egress, "_win_is_readable", readable)
    monkeypatch.setattr(egress, "_CONTROLS", {})
    monkeypatch.setenv(ENV, str(control_handle))
    # Proof of "never dials directly": the SOCKS/AF_UNIX path must not run.
    monkeypatch.setattr(
        egress,
        "_socks5_connect_sync",
        lambda *a, **k: pytest.fail("Windows path fell through to the AF_UNIX driver"),
    )
    yield table, sup_end, control_handle
    _close(sup_end)
    _close(agent_end)


@pytest.fixture
def tls():
    with tempfile.TemporaryDirectory() as d:
        cert, key = make_localhost_cert(d)
        with TLSServer(cert, key, body=b"through-the-placed-channel") as srv:
            yield srv, cert


# ── Layer 1: wire encode / decode (pure) ─────────────────────────────────────


def test_request_bytes_match_the_supervisor_reader_exactly() -> None:
    assert egress._mux_request("api.anthropic.com", 443) == (
        b"\x01\x01\xbb\x11api.anthropic.com"
    )
    assert egress._mux_request("h", 0) == b"\x01\x00\x00\x01h"
    assert egress._mux_request("h", 65535) == b"\x01\xff\xff\x01h"
    # Non-ASCII goes as IDNA (ASCII), never resolved locally.
    assert egress._mux_request("bücher.example", 443)[4:] == b"xn--bcher-kva.example"
    assert egress._mux_request("a" * 255, 1)[3] == 255


@pytest.mark.parametrize(
    "host,port",
    [("", 443), ("a" * 256, 443), ("a\x00b", 443), ("h", -1), ("h", 65536), ("h", True)],
)
def test_unrepresentable_requests_raise_before_any_io(host: str, port: Any) -> None:
    with pytest.raises(EgressProtocolError):
        egress._mux_request(host, port)


def test_ok_reply_yields_the_handle() -> None:
    assert egress._parse_mux_reply(reply(0, 0, 0x1F4), "h", 1) == 0x1F4
    assert egress._parse_mux_reply(reply(0, 0, 0xFFFFFFFF), "h", 1) == 0xFFFFFFFF


@pytest.mark.parametrize(
    "raw,exc",
    [
        (reply(0x01, 0x02), EgressPolicyDenied),
        (reply(0x01, 0x04), EgressHostUnreachable),
        (reply(0x01, 0x07), EgressProtocolError),
        (reply(0x01, 0x00), EgressProtocolError),  # a "denial" claiming success
        (reply(0x02), EgressBrokerBusy),
        (reply(0x03), EgressProtocolError),  # vend_failed
        (reply(0x04), EgressProtocolError),  # unknown status
        (reply(0xFF, 0xFF), EgressProtocolError),
        (reply(0x00, 0x00, 0), EgressProtocolError),  # OK with a null handle
        (reply(0x00, 0x02, 0x1F4), EgressProtocolError),  # OK carrying a rep
        (reply(0x01, 0x02, 0x1F4), EgressProtocolError),  # refusal carrying a handle
        (b"", EgressProtocolError),
        (b"\x00\x00\x00\x00\x01", EgressProtocolError),  # short
        (reply(0, 0, 0x1F4) + b"\x00", EgressProtocolError),  # oversize
    ],
)
def test_every_non_ok_or_malformed_reply_raises(raw: bytes, exc: type) -> None:
    with pytest.raises(exc):
        egress._parse_mux_reply(raw, "h", 443)


def test_denied_reply_names_the_endpoint() -> None:
    with pytest.raises(EgressPolicyDenied) as ei:
        egress._parse_mux_reply(reply(0x01, 0x02), "evil.example", 8443)
    assert (ei.value.host, ei.value.port) == ("evil.example", 8443)


# ── Layer 1: env parsing (same acceptance as parse_inherited_handle) ─────────


@pytest.mark.parametrize("raw,want", [("1234", 1234), (" 1234 ", 1234), ("500\n", 500)])
def test_handle_env_accepts_what_the_supervisor_writes(raw: str, want: int) -> None:
    assert egress._parse_broker_handle(raw) == want


@pytest.mark.parametrize(
    "raw",
    [None, "", "   ", "0", "-1", "0x1f4", "1234abcd", "1e5", "١٢٣٤", "+5", "1_000",
     "99999999999999999999999999"],
)
def test_handle_env_malformed_or_absent_fails_closed(raw: str | None) -> None:
    with pytest.raises(EgressConfigError):
        egress._parse_broker_handle(raw)


def test_resolve_broker_handle_reads_the_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV, "772")
    assert egress.resolve_broker_handle() == 772
    assert egress.resolve_broker_handle(9) == 9
    monkeypatch.delenv(ENV)
    with pytest.raises(EgressConfigError, match="direct network"):
        egress.resolve_broker_handle()
    with pytest.raises(EgressConfigError):
        egress.resolve_broker_handle(True)  # type: ignore[arg-type]


# ── Layer 2: configuration fails closed on the Windows path ──────────────────


def test_no_handle_variable_refuses_to_build_a_client(placed, monkeypatch) -> None:
    monkeypatch.delenv(ENV)
    for flavor in ("stdlib", "httpx"):
        with pytest.raises(EgressConfigError, match="direct network"):
            egress.client(flavor=flavor)


def test_socket_path_is_refused_on_windows(placed) -> None:
    with pytest.raises(EgressConfigError, match="not a transport on Windows"):
        egress.client(socket_path="/tmp/egress-broker.sock", flavor="stdlib")


def test_a_handle_that_is_not_a_pipe_fails_at_client(placed, monkeypatch) -> None:
    monkeypatch.setenv(ENV, "999")  # not in the handle table
    with pytest.raises(EgressConfigError, match="not a pipe"):
        egress.client(flavor="stdlib")


def test_requests_session_refuses_on_windows(placed) -> None:
    pytest.importorskip("requests")
    with pytest.raises(EgressConfigError, match="not available on Windows"):
        egress.requests_session()


def test_the_unix_path_is_untouched_off_windows(monkeypatch) -> None:
    """Off the placed platform the handle variable is ignored and the AF_UNIX
    resolution (and its error) is exactly what it was."""
    monkeypatch.setattr(egress, "_placed_channel_platform", lambda: False)
    monkeypatch.setenv(ENV, "1234")
    for var in ("HAAP_EGRESS_BROKER_SOCKET", "HAAP_AGENT_SOCKET_DIR", "HAAP_AGENT_INSTANCE_ID"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(EgressConfigError, match="HAAP_EGRESS_BROKER_SOCKET"):
        egress.client(flavor="stdlib")


# ── Layer 3: full requests over the Windows code path (loopback fake) ────────


def test_stdlib_tls_request_over_a_vended_channel(placed, tls) -> None:
    table, sup_end, control = placed
    srv, cert = tls
    with FakeSupervisor(sup_end, table.vend, (srv.host, srv.port)) as sup:
        with egress.client(verify=cert, flavor="stdlib") as http:
            r = http.get(f"https://localhost:{srv.port}/v1/models")
    assert r.status_code == 200
    assert r.text == "through-the-placed-channel"
    assert sup.requests == [b"\x01" + srv.port.to_bytes(2, "big") + b"\x09localhost"]
    assert sup.dials == 1
    assert table.adopted[0] == control and len(table.adopted) == 2


def test_tls_verification_is_the_callers(placed, tls) -> None:
    """The broker relays ciphertext only; an unverifiable cert still fails."""
    table, sup_end, _ = placed
    srv, _cert = tls
    with FakeSupervisor(sup_end, table.vend, (srv.host, srv.port)):
        with egress.client(flavor="stdlib") as http:  # system trust store
            with pytest.raises(EgressProtocolError, match="CERTIFICATE_VERIFY_FAILED"):
                http.get(f"https://localhost:{srv.port}/")


@pytest.mark.parametrize("which", ["httpx", "httpx2"])
def test_httpx_flavors_over_a_vended_channel(placed, tls, which: str) -> None:
    pytest.importorskip(which)
    import ssl

    table, sup_end, _ = placed
    srv, cert = tls
    with FakeSupervisor(sup_end, table.vend, (srv.host, srv.port)) as sup:
        with egress.client(verify=ssl.create_default_context(cafile=cert), flavor=which) as c:
            r1 = c.post(f"https://localhost:{srv.port}/a", content=b"x" * 70000)
            r2 = c.get(f"https://localhost:{srv.port}/b")
    assert (r1.status_code, r1.text) == (200, "through-the-placed-channel")
    assert (r2.status_code, r2.text) == (200, "through-the-placed-channel")
    # Two connections (the server closes each), two requests on ONE control
    # channel -- the old one-session-per-agent ceiling is gone.
    assert len(sup.requests) == 2 and sup.dials == 2


async def test_async_client_over_a_vended_channel(placed, tls) -> None:
    pytest.importorskip("httpx")
    import ssl

    table, sup_end, _ = placed
    srv, cert = tls
    with FakeSupervisor(sup_end, table.vend, (srv.host, srv.port)) as sup:
        async with egress.async_client(
            verify=ssl.create_default_context(cafile=cert), flavor="httpx"
        ) as c:
            r = await c.get(f"https://localhost:{srv.port}/")
    assert (r.status_code, r.text) == (200, "through-the-placed-channel")
    assert sup.dials == 1


def test_denial_is_typed_nothing_is_dialed_and_the_channel_stays_usable(placed, tls) -> None:
    table, sup_end, _ = placed
    srv, cert = tls
    allow = lambda host, port: host == "localhost"  # noqa: E731
    with FakeSupervisor(sup_end, table.vend, (srv.host, srv.port), allow=allow) as sup:
        with egress.client(verify=cert, flavor="stdlib") as http:
            with pytest.raises(EgressPolicyDenied):
                http.get("https://evil.example/")
            r = http.get(f"https://localhost:{srv.port}/")
    assert r.status_code == 200
    assert sup.dials == 1
    assert len(table.adopted) == 2  # control + the one allowed channel; nothing vended on deny


@pytest.mark.parametrize(
    "first,exc",
    [
        (reply(0x02), EgressBrokerBusy),
        (reply(0x01, 0x04), EgressHostUnreachable),
        (reply(0x03), EgressProtocolError),
    ],
)
def test_well_formed_refusals_keep_the_channel_in_step(placed, tls, first, exc) -> None:
    table, sup_end, _ = placed
    srv, cert = tls
    script = lambda i, h, p: first if i == 0 else None  # noqa: E731
    with FallThrough(sup_end, table.vend, (srv.host, srv.port), script=script):
        with egress.client(verify=cert, flavor="stdlib") as http:
            with pytest.raises(exc):
                http.get(f"https://localhost:{srv.port}/")
            assert http.get(f"https://localhost:{srv.port}/").status_code == 200


@pytest.mark.parametrize(
    "bad",
    [
        reply(0x00, 0x00, 0),  # OK + null handle
        reply(0x01, 0x02, 0x1F4),  # refusal carrying a handle
        reply(0x09),  # unknown status
        reply(0x01, 0x00),  # denial claiming success
    ],
)
def test_malformed_reply_retires_the_control_channel(placed, bad) -> None:
    table, sup_end, _ = placed
    with FallThrough(sup_end, table.vend, ("127.0.0.1", 9), script=lambda i, h, p: bad) as sup:
        with egress.client(flavor="stdlib") as http:
            with pytest.raises(EgressProtocolError):
                http.get("https://localhost/")
            with pytest.raises(EgressProtocolError, match="retired"):
                http.get("https://localhost/")
    assert len(sup.requests) == 1  # the retired channel was never written again


def test_short_reply_then_eof_is_a_transport_error_and_retires(placed) -> None:
    table, sup_end, _ = placed

    def script(i: int, h: str, p: int) -> bytes | None:
        sup_end.sendall(b"\x00\x00\x00")
        sup_end.shutdown(socket.SHUT_WR)
        return b""

    with FallThrough(sup_end, table.vend, None, script=script):
        with egress.client(flavor="stdlib") as http:
            with pytest.raises(EgressProtocolError, match="broker is gone"):
                http.get("https://localhost/")
            with pytest.raises(EgressProtocolError, match="retired"):
                http.get("https://localhost/")


def test_eof_before_any_reply_is_a_transport_error(placed) -> None:
    table, sup_end, _ = placed
    with FakeSupervisor(sup_end, table.vend, None, script=lambda i, h, p: None):
        with egress.client(flavor="stdlib") as http:
            with pytest.raises(EgressProtocolError, match=r"broker is gone|failed"):
                http.get("https://localhost/")


def test_a_stalled_broker_times_out_and_retires(placed) -> None:
    table, sup_end, _ = placed
    gate = threading.Event()

    def stall(i: int, h: str, p: int) -> bytes | None:
        gate.wait(5)
        return reply(0x00, 0x00, 0x1F4)  # late: must never be read as the NEXT reply

    with FallThrough(sup_end, table.vend, None, script=stall):
        with egress.client(flavor="stdlib", timeout=0.3) as http:
            t0 = time.monotonic()
            with pytest.raises(EgressProtocolError, match="timed out"):
                http.get("https://localhost/")
            assert time.monotonic() - t0 < 3
            gate.set()
            with pytest.raises(EgressProtocolError, match="retired"):
                http.get("https://localhost/")


def test_reply_delivered_one_byte_at_a_time_is_reassembled(placed, tls) -> None:
    table, sup_end, _ = placed
    srv, cert = tls

    def dribble(i: int, h: str, p: int) -> bytes | None:
        up = socket.create_connection((srv.host, srv.port))
        server_end, handle = table.vend()
        for byte in reply(0x00, 0x00, handle):
            sup_end.sendall(bytes([byte]))
            time.sleep(0.01)
        _pump(server_end, up)
        return b""

    with FallThrough(sup_end, table.vend, None, script=dribble):
        with egress.client(verify=cert, flavor="stdlib") as http:
            assert http.get(f"https://localhost:{srv.port}/").status_code == 200


def test_a_vended_value_that_is_not_a_pipe_is_refused_not_closed(placed) -> None:
    table, sup_end, _ = placed
    with FallThrough(sup_end, table.vend, None, script=lambda i, h, p: reply(0, 0, 0xABCD)):
        with egress.client(flavor="stdlib") as http:
            with pytest.raises(EgressProtocolError, match="not a pipe"):
                http.get("https://localhost/")
            with pytest.raises(EgressProtocolError, match="retired"):
                http.get("https://localhost/")


def test_concurrent_requests_are_serialised_on_the_control_channel(placed, tls) -> None:
    table, sup_end, _ = placed
    srv, cert = tls
    results: list[int] = []
    errors: list[BaseException] = []
    with FakeSupervisor(sup_end, table.vend, (srv.host, srv.port)) as sup:
        with egress.client(verify=cert, flavor="stdlib") as http:

            def one() -> None:
                try:
                    results.append(http.get(f"https://localhost:{srv.port}/").status_code)
                except BaseException as e:  # noqa: BLE001
                    errors.append(e)

            ts = [threading.Thread(target=one) for _ in range(8)]
            for t in ts:
                t.start()
            for t in ts:
                t.join(20)
    assert not errors and results == [200] * 8
    assert len(sup.requests) == 8 and all(r[0] == 0x01 for r in sup.requests)


def test_is_readable_reports_a_closed_relay(placed) -> None:
    """httpcore drops an idle keep-alive whose far end went away."""
    table, _, _ = placed
    a, b = socket.socketpair()
    h = table.put(b)
    stream = egress._PipeStream(table.adopt(h))
    assert stream.is_readable() is False
    a.close()
    assert stream.is_readable() is True
    stream.close()


# ── Windows only: real overlapped pipes and DuplicateHandle ──────────────────

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="real Windows pipe handles")


def _real_pipe_pair() -> tuple[Any, int]:
    """(supervisor end as WindowsPipeSocket, agent end handle) -- both
    FILE_FLAG_OVERLAPPED, like `connected_pipe_pair`, then the agent end is
    re-placed with DuplicateHandle exactly as `vend_channel` does."""
    import ctypes
    import ctypes.wintypes as wt
    import os

    from hawcx_haap.pipe_win import WindowsPipeSocket

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateNamedPipeW.restype = wt.HANDLE
    k32.CreateNamedPipeW.argtypes = [wt.LPCWSTR] + [wt.DWORD] * 6 + [ctypes.c_void_p]
    k32.CreateFileW.restype = wt.HANDLE
    k32.CreateFileW.argtypes = [
        wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.HANDLE,
    ]
    k32.GetCurrentProcess.restype = wt.HANDLE
    k32.DuplicateHandle.argtypes = [
        wt.HANDLE, wt.HANDLE, wt.HANDLE, ctypes.POINTER(wt.HANDLE), wt.DWORD, wt.BOOL, wt.DWORD,
    ]
    k32.CloseHandle.argtypes = [wt.HANDLE]
    name = rf"\\.\pipe\hawcx-egress-test-{os.getpid()}-{next(_PIPE_SEQ)}"
    server = k32.CreateNamedPipeW(
        name, 0x3 | 0x40000000 | 0x00080000, 0, 1, 65536, 65536, 0, None
    )
    assert server not in (None, ctypes.c_void_p(-1).value), ctypes.get_last_error()
    client = k32.CreateFileW(name, 0xC0000000, 0, None, 3, 0x40000000, None)
    assert client not in (None, ctypes.c_void_p(-1).value), ctypes.get_last_error()
    me = k32.GetCurrentProcess()
    placed = wt.HANDLE()
    assert k32.DuplicateHandle(me, client, me, ctypes.byref(placed), 0, False, 0x2)
    k32.CloseHandle(client)
    return WindowsPipeSocket(server), int(placed.value)


_PIPE_SEQ = itertools.count()


@windows_only
def test_real_pipes_full_tls_request(monkeypatch, tls) -> None:
    srv, cert = tls
    sup_end, control = _real_pipe_pair()
    monkeypatch.setattr(egress, "_CONTROLS", {})
    monkeypatch.setenv(ENV, str(control))
    with FakeSupervisor(sup_end, _real_pipe_pair, (srv.host, srv.port)) as sup:
        with egress.client(verify=cert, flavor="stdlib") as http:
            r1 = http.get(f"https://localhost:{srv.port}/")
            r2 = http.post(f"https://localhost:{srv.port}/", content=b"y" * 100000)
    assert (r1.status_code, r1.text) == (200, "through-the-placed-channel")
    assert r2.status_code == 200
    assert sup.dials == 2


@windows_only
def test_real_pipes_denial_and_closed_broker(monkeypatch) -> None:
    sup_end, control = _real_pipe_pair()
    monkeypatch.setattr(egress, "_CONTROLS", {})
    monkeypatch.setenv(ENV, str(control))
    with FakeSupervisor(sup_end, _real_pipe_pair, None, allow=lambda h, p: False):
        with egress.client(flavor="stdlib", timeout=5) as http:
            with pytest.raises(EgressPolicyDenied):
                http.get("https://evil.example/")
    # The supervisor end is closed now: the next request is a transport error.
    with egress.client(flavor="stdlib", timeout=5) as http:
        with pytest.raises(EgressProtocolError):
            http.get("https://evil.example/")


@windows_only
def test_real_handle_that_is_not_a_pipe_is_refused(monkeypatch) -> None:
    import msvcrt

    with tempfile.TemporaryFile() as f:
        monkeypatch.setattr(egress, "_CONTROLS", {})
        monkeypatch.setenv(ENV, str(msvcrt.get_osfhandle(f.fileno())))
        with pytest.raises(EgressConfigError, match="not a pipe"):
            egress.client(flavor="stdlib")
