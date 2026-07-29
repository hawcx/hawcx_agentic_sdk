"""Optional egress transport — route an agent's outbound HTTP through the
per-agent SOCKS5-over-UDS egress broker (ADR-0048).

An OS sandbox pins a sandboxed agent's entire outbound network to a single
UNIX-domain socket (``egress-broker.sock``); that socket is a SOCKS5 proxy.
No SOCKS proxy *URL* can name a filesystem path
(``socks5h:///tmp/…/egress-broker.sock`` parses to ``host=''``), so every
stock SOCKS transport — which dials ``(host, port)`` — cannot reach a UDS.
Hence this shim: it opens the UDS, performs the SOCKS5 ``CONNECT`` handshake,
and hands the connected stream to httpx for **end-to-end** TLS + HTTP. The
broker never terminates TLS and neither does this shim — certificate
verification stays exactly as the caller configured it.

Opt in with one line::

    import hawcx_haap.egress as egress

    with egress.client() as http:          # a configured httpx.Client
        r = http.get("https://api.example.com/v1/models")

httpx is an **optional** extra (the SDK core is zero-dependency)::

    pip install 'hawcx-haap[httpx]'

Per ADR-0048 the shim always sends ``ATYP=0x03`` (DOMAINNAME) and never
resolves DNS locally: the broker resolves the name the agent actually asked
for, which is what makes its hostname allowlist meaningful (``socks5h``
semantics). IP-literal hosts are passed through *as a name* — the broker,
not the shim, decides on them.
"""

from __future__ import annotations

import os
import socket
import stat
from typing import TYPE_CHECKING, Any

from hawcx_haap.errors import (
    EgressConfigError,
    EgressHostUnreachable,
    EgressPeerCredError,
    EgressPolicyDenied,
    EgressProtocolError,
)

if TYPE_CHECKING:  # pragma: no cover - typing only, never imported at runtime
    import httpx

# EgressHTTPTransport / EgressAsyncHTTPTransport are provided lazily via
# module __getattr__ (they need the optional httpx extra), so they are not
# listed here — `egress.EgressHTTPTransport` still resolves.
__all__ = [
    "client",
    "async_client",
    "resolve_socket_path",
]

# SOCKS5, one method offered: NO-AUTH (0x00). The transport authenticates via
# SO_PEERCRED on the UDS (ADR-0048 D48-3), so there is no in-band credential.
_GREETING = b"\x05\x01\x00"
_DEFAULT_TIMEOUT = 30.0


# ── socket resolution ───────────────────────────────────────────────────────


def resolve_socket_path(socket_path: str | None = None) -> str:
    """Resolve the broker socket path, or raise. Never returns a path that is
    not an existing socket — a silent fallback to the direct network would
    defeat the entire control (ADR-0048 D48-5).

    Order: explicit arg → ``$HAAP_EGRESS_BROKER_SOCKET`` →
    ``$HAAP_AGENT_SOCKET_DIR/$HAAP_AGENT_INSTANCE_ID/egress-broker.sock``.
    """
    path = socket_path or os.environ.get("HAAP_EGRESS_BROKER_SOCKET")
    if not path:
        base = os.environ.get("HAAP_AGENT_SOCKET_DIR")
        inst = os.environ.get("HAAP_AGENT_INSTANCE_ID")
        if base and inst:
            path = os.path.join(base, inst, "egress-broker.sock")
    if not path:
        raise EgressConfigError(
            "no egress broker socket configured — set HAAP_EGRESS_BROKER_SOCKET, "
            "or HAAP_AGENT_SOCKET_DIR + HAAP_AGENT_INSTANCE_ID, or pass socket_path=. "
            "Refusing to fall back to direct network access."
        )
    try:
        is_sock = stat.S_ISSOCK(os.stat(path).st_mode)
    except OSError as exc:
        raise EgressConfigError(
            f"egress broker socket {path!r} not found ({exc.strerror}) — "
            "refusing to fall back to direct network access."
        ) from exc
    if not is_sock:
        raise EgressConfigError(
            f"egress broker path {path!r} is not a socket — "
            "refusing to fall back to direct network access."
        )
    return path


# ── SOCKS5 wire helpers (pure, no IO) ───────────────────────────────────────


def _encode_host(host: str) -> bytes:
    """Encode a hostname into the DOMAINNAME octets, or raise a defined error.

    Never resolves DNS. ASCII (incl. already-punycoded) passes through; other
    Unicode is IDNA-encoded. NUL, empty, and >255 bytes cannot be represented
    on the wire, so they raise rather than emit a malformed frame."""
    if not isinstance(host, str) or host == "":
        raise EgressProtocolError("empty egress host")
    try:
        raw = host.encode("ascii")
    except UnicodeEncodeError:
        try:
            raw = host.encode("idna")
        except (UnicodeError, ValueError) as exc:
            raise EgressProtocolError(f"egress host not encodable as a DNS name: {host!r}") from exc
    if b"\x00" in raw:
        raise EgressProtocolError("NUL byte in egress host")
    if not 1 <= len(raw) <= 255:
        raise EgressProtocolError(
            f"egress host length {len(raw)} out of SOCKS5 DOMAINNAME range 1..255"
        )
    return raw


def _connect_request(host: str, port: int) -> bytes:
    """Build the SOCKS5 CONNECT request. ATYP is ALWAYS 0x03 (DOMAINNAME) —
    the shim never sends 0x01/0x04 literal-IP requests (ADR-0048)."""
    if not isinstance(port, int) or not 0 <= port <= 0xFFFF:
        raise EgressProtocolError(f"egress port {port!r} out of range 0..65535")
    raw = _encode_host(host)
    return b"\x05\x01\x00\x03" + bytes([len(raw)]) + raw + port.to_bytes(2, "big")


def _check_method_reply(reply: bytes) -> None:
    """Validate the 2-byte method-selection reply."""
    if reply[0] != 0x05:
        raise EgressProtocolError(f"bad SOCKS version {reply[0]:#04x} in method reply")
    method = reply[1]
    if method == 0xFF:
        raise EgressProtocolError(
            "broker refused method negotiation (05 FF): it did not accept NO-AUTH (0x00)"
        )
    if method != 0x00:
        raise EgressProtocolError(f"broker selected unsupported SOCKS5 method {method:#04x}")


def _reply_exception(rep: int, host: str, port: int) -> Exception:
    """Map a non-zero SOCKS5 CONNECT reply code to a distinguishable error."""
    if rep == 0x02:
        return EgressPolicyDenied(host, port)
    if rep == 0x04:
        return EgressHostUnreachable(host, port)
    if rep == 0x07:
        return EgressProtocolError(
            "SOCKS5 reply 0x07 (command not supported) — shim bug: CONNECT must always be accepted"
        )
    if rep == 0x08:
        return EgressProtocolError(
            "SOCKS5 reply 0x08 (address type not supported) — shim bug: DOMAINNAME must be accepted"
        )
    return EgressProtocolError(f"SOCKS5 CONNECT failed with reply code {rep:#04x}")


def _bound_trailer_len(atyp: int) -> int | None:
    """Bytes of BND.ADDR+BND.PORT to drain after a success reply header, given
    ATYP. ``None`` means DOMAINNAME (a length byte must be read first)."""
    if atyp == 0x01:  # IPv4
        return 4 + 2
    if atyp == 0x04:  # IPv6
        return 16 + 2
    if atyp == 0x03:  # DOMAINNAME
        return None
    raise EgressProtocolError(f"unsupported ATYP {atyp:#04x} in broker reply")


# ── sync driver ─────────────────────────────────────────────────────────────


def _closed_mid_handshake(*, peer_cred: bool, got_bytes: bool) -> EgressError:
    """Classify "the broker went away" — a clean EOF and an RST are one event.

    A connection reset is not a distinct failure from an orderly close. Linux
    sends RST when a peer closes a socket that still has unread data queued (the
    greeting we just wrote is exactly that), while macOS reports the same broker
    behaviour as a clean EOF. Routing both here is what keeps the shim's public
    contract — "only EgressError subclasses escape" — true on every platform.
    """
    if peer_cred and not got_bytes:
        return EgressPeerCredError(
            "broker closed the connection without a reply — "
            "peer-credential (SO_PEERCRED) check likely failed"
        )
    return EgressProtocolError("broker closed connection mid-handshake (truncated reply)")


def _sendall_sync(sock: socket.socket, data: bytes, *, peer_cred: bool) -> None:
    try:
        sock.sendall(data)
    # socket.timeout IS an OSError subclass, so it must be caught first.
    except socket.timeout as exc:  # noqa: UP041 - socket.timeout is what sendall raises
        raise EgressProtocolError("timed out writing the broker handshake") from exc
    except OSError as exc:
        raise _closed_mid_handshake(peer_cred=peer_cred, got_bytes=False) from exc


def _recv_exact_sync(sock: socket.socket, n: int, *, peer_cred: bool) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout as exc:  # noqa: UP041 - socket.timeout is what recv raises
            raise EgressProtocolError("timed out awaiting broker handshake reply") from exc
        except ConnectionResetError as exc:
            raise _closed_mid_handshake(peer_cred=peer_cred, got_bytes=bool(buf)) from exc
        if not chunk:
            raise _closed_mid_handshake(peer_cred=peer_cred, got_bytes=bool(buf))
        buf.extend(chunk)
    return bytes(buf)


def _socks5_connect_sync(
    socket_path: str, host: str, port: int, timeout: float | None
) -> socket.socket:
    if not hasattr(socket, "AF_UNIX"):
        raise EgressConfigError("egress broker requires AF_UNIX sockets (Unix only)")
    request = _connect_request(host, port)  # validate before touching the network
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        try:
            sock.connect(socket_path)
        except OSError as exc:
            raise EgressConfigError(
                f"cannot connect to egress broker socket {socket_path!r}: {exc.strerror}"
            ) from exc
        _sendall_sync(sock, _GREETING, peer_cred=True)
        _check_method_reply(_recv_exact_sync(sock, 2, peer_cred=True))
        _sendall_sync(sock, request, peer_cred=False)
        header = _recv_exact_sync(sock, 4, peer_cred=False)
        if header[0] != 0x05:
            raise EgressProtocolError(f"bad SOCKS version {header[0]:#04x} in CONNECT reply")
        if header[1] != 0x00:
            raise _reply_exception(header[1], host, port)
        trailer = _bound_trailer_len(header[3])
        if trailer is None:  # DOMAINNAME: one length byte, then that many + port
            ln = _recv_exact_sync(sock, 1, peer_cred=False)[0]
            _recv_exact_sync(sock, ln + 2, peer_cred=False)
        else:
            _recv_exact_sync(sock, trailer, peer_cred=False)
    except BaseException:
        sock.close()
        raise
    return sock


# ── async driver ────────────────────────────────────────────────────────────


async def _recv_exact_async(stream: Any, n: int, *, peer_cred: bool) -> bytes:
    import anyio

    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = await stream.receive(n - len(buf))
        # anyio surfaces a clean close as EndOfStream and an RST (ECONNRESET) as
        # BrokenResourceError; see _closed_mid_handshake for why they are one event.
        except (anyio.EndOfStream, anyio.BrokenResourceError) as exc:
            raise _closed_mid_handshake(peer_cred=peer_cred, got_bytes=bool(buf)) from exc
        buf.extend(chunk)
    return bytes(buf)


async def _send_all_async(stream: Any, data: bytes, *, peer_cred: bool) -> None:
    import anyio

    try:
        await stream.send(data)
    except anyio.BrokenResourceError as exc:
        raise _closed_mid_handshake(peer_cred=peer_cred, got_bytes=False) from exc


async def _socks5_connect_async(
    socket_path: str, host: str, port: int, timeout: float | None
) -> Any:
    import anyio

    request = _connect_request(host, port)  # validate before touching the network
    stream = None
    try:
        with anyio.fail_after(timeout):
            try:
                stream = await anyio.connect_unix(socket_path)
            except OSError as exc:
                raise EgressConfigError(
                    f"cannot connect to egress broker socket {socket_path!r}: {exc}"
                ) from exc
            await _send_all_async(stream, _GREETING, peer_cred=True)
            _check_method_reply(await _recv_exact_async(stream, 2, peer_cred=True))
            await _send_all_async(stream, request, peer_cred=False)
            header = await _recv_exact_async(stream, 4, peer_cred=False)
            if header[0] != 0x05:
                raise EgressProtocolError(f"bad SOCKS version {header[0]:#04x} in CONNECT reply")
            if header[1] != 0x00:
                raise _reply_exception(header[1], host, port)
            trailer = _bound_trailer_len(header[3])
            if trailer is None:
                ln = (await _recv_exact_async(stream, 1, peer_cred=False))[0]
                await _recv_exact_async(stream, ln + 2, peer_cred=False)
            else:
                await _recv_exact_async(stream, trailer, peer_cred=False)
    except TimeoutError as exc:
        if stream is not None:
            await stream.aclose()
        raise EgressProtocolError("timed out awaiting broker handshake reply") from exc
    except BaseException:
        if stream is not None:
            await stream.aclose()
        raise
    return stream


# ── httpx transport wiring (lazy: needs the optional httpx extra) ────────────

_BUILT: tuple[type, type] | None = None


def _require_httpx() -> Any:
    try:
        import httpx
    except ModuleNotFoundError as exc:
        raise EgressConfigError(
            "the egress transport requires httpx: pip install 'hawcx-haap[httpx]'"
        ) from exc
    return httpx


def _build_transports() -> tuple[type, type]:
    """Define the httpx transport subclasses lazily, so importing this module
    does not require httpx. Cached after first call."""
    global _BUILT
    if _BUILT is not None:
        return _BUILT

    httpx = _require_httpx()
    try:
        import httpcore
        from httpcore._backends.anyio import AnyIOStream
        from httpcore._backends.sync import SyncStream
    except (ModuleNotFoundError, ImportError) as exc:  # fail loud, never silently direct
        raise EgressConfigError(
            f"egress transport could not load the httpcore network-backend seam: {exc}. "
            "Requires httpcore>=1.0 (installed with httpx)."
        ) from exc

    class _SyncBackend(httpcore.NetworkBackend):
        def __init__(self, socket_path: str) -> None:
            self._socket_path = socket_path

        def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            sock = _socks5_connect_sync(self._socket_path, host, port, timeout)
            return SyncStream(sock)

        def connect_unix_socket(self, path, timeout=None, socket_options=None):  # pragma: no cover
            raise EgressProtocolError("egress transport connects only via the broker CONNECT path")

    class _AsyncBackend(httpcore.AsyncNetworkBackend):
        def __init__(self, socket_path: str) -> None:
            self._socket_path = socket_path

        async def connect_tcp(
            self, host, port, timeout=None, local_address=None, socket_options=None
        ):
            stream = await _socks5_connect_async(self._socket_path, host, port, timeout)
            return AnyIOStream(stream)

        async def connect_unix_socket(
            self, path, timeout=None, socket_options=None
        ):  # pragma: no cover
            raise EgressProtocolError("egress transport connects only via the broker CONNECT path")

    class EgressHTTPTransport(httpx.HTTPTransport):  # type: ignore[name-defined]  # base resolved at runtime
        """A sync httpx transport whose TCP connect goes through the egress
        broker's SOCKS5 CONNECT. All other httpx knobs (verify, cert, http2,
        limits, timeouts) behave exactly as the stock transport."""

        def __init__(self, socket_path: str, **httpx_kwargs: Any) -> None:
            super().__init__(**httpx_kwargs)
            # ponytail: swap the pool's network backend in place instead of
            # re-threading ~10 httpcore kwargs. Fails loud (AttributeError) if
            # httpcore ever renames it — never degrades to a direct dial.
            assert hasattr(self._pool, "_network_backend"), "httpcore ConnectionPool layout changed"
            self._pool._network_backend = _SyncBackend(socket_path)

    class EgressAsyncHTTPTransport(httpx.AsyncHTTPTransport):  # type: ignore[name-defined]  # base resolved at runtime
        """Async counterpart of :class:`EgressHTTPTransport`."""

        def __init__(self, socket_path: str, **httpx_kwargs: Any) -> None:
            super().__init__(**httpx_kwargs)
            assert hasattr(self._pool, "_network_backend"), (
                "httpcore AsyncConnectionPool layout changed"
            )
            self._pool._network_backend = _AsyncBackend(socket_path)

    _BUILT = (EgressHTTPTransport, EgressAsyncHTTPTransport)
    return _BUILT


def __getattr__(name: str) -> Any:
    # Expose the transport classes as module attributes without importing httpx
    # at module load. `from hawcx_haap.egress import EgressHTTPTransport` works
    # iff the httpx extra is installed.
    if name in ("EgressHTTPTransport", "EgressAsyncHTTPTransport"):
        sync_cls, async_cls = _build_transports()
        return sync_cls if name == "EgressHTTPTransport" else async_cls
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def client(
    *,
    socket_path: str | None = None,
    verify: Any = True,
    http2: bool = False,
    **client_kwargs: Any,
) -> httpx.Client:
    """Return an ``httpx.Client`` whose outbound traffic tunnels through the
    per-agent egress broker. ``verify`` is forwarded to the transport unchanged
    (TLS is not terminated by the broker or the shim). Extra kwargs go to the
    ``httpx.Client`` (timeout, headers, ...)."""
    httpx = _require_httpx()
    sync_cls, _ = _build_transports()
    path = resolve_socket_path(socket_path)
    transport = sync_cls(path, verify=verify, http2=http2)
    client_kwargs.setdefault("timeout", _DEFAULT_TIMEOUT)
    return httpx.Client(transport=transport, **client_kwargs)


def async_client(
    *,
    socket_path: str | None = None,
    verify: Any = True,
    http2: bool = False,
    **client_kwargs: Any,
) -> httpx.AsyncClient:
    """Async counterpart of :func:`client`."""
    httpx = _require_httpx()
    _, async_cls = _build_transports()
    path = resolve_socket_path(socket_path)
    transport = async_cls(path, verify=verify, http2=http2)
    client_kwargs.setdefault("timeout", _DEFAULT_TIMEOUT)
    return httpx.AsyncClient(transport=transport, **client_kwargs)
