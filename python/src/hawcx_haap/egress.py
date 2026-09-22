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

The HTTP client is an **optional** extra (the SDK core is zero-dependency).
Two API-identical httpx lineages exist; install whichever your client needs::

    pip install 'hawcx-haap[httpx2]'    # Anthropic SDK 1.x and other httpx2 clients
    pip install 'hawcx-haap[httpx]'     # the original httpx lineage
    pip install 'hawcx-haap[requests]'  # requests_session(), for google-auth et al

When **both** httpx lineages are installed, ``httpx2`` wins; see
:func:`flavor` for why, how to tell which you got, and how to override it.

The Google client libraries are ``requests``-based and the httpx transport
cannot carry them, so :func:`requests_session` brokers those under the same
no-fallback contract.

Per ADR-0048 the shim always sends ``ATYP=0x03`` (DOMAINNAME) and never
resolves DNS locally: the broker resolves the name the agent actually asked
for, which is what makes its hostname allowlist meaningful (``socks5h``
semantics). IP-literal hosts are passed through *as a name* — the broker,
not the shim, decides on them.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import socket
import stat
from typing import Any

from hawcx_haap.errors import (
    EgressConfigError,
    EgressError,
    EgressHostUnreachable,
    EgressPeerCredError,
    EgressPolicyDenied,
    EgressProtocolError,
)

# EgressHTTPTransport / EgressAsyncHTTPTransport are provided lazily via
# module __getattr__ (they need the optional httpx extra), so they are not
# listed here — `egress.EgressHTTPTransport` still resolves.
__all__ = [
    "client",
    "async_client",
    "flavor",
    "requests_session",
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


# ── httpx / httpx2 transport wiring (lazy: needs an optional extra) ─────────

# Two httpx lineages ship the same public API and a process may hold both:
#
#   httpx2 + httpcore2 — what the Anthropic SDK 1.x requires. It rejects an
#                        old-httpx client at construction with a TypeError.
#   httpx  + httpcore  — the original lineage, still what most apps carry.
#
# Measured on 2026-09-21 against httpx2 2.13.0 / httpcore2 2.13.0: the transport
# seam (`Transport._pool._network_backend`), the `HTTPTransport.__init__`
# signature and the `_backends.{sync,anyio}.{SyncStream,AnyIOStream}` module
# paths are identical in both lineages. So the only real difference is which
# name gets imported, and one parameterised build covers both.
_FLAVOR_HTTPCORE = {"httpx2": "httpcore2", "httpx": "httpcore"}

# PRECEDENCE when BOTH are installed: httpx2 wins. httpx2 is present only
# because something in the process explicitly asked for it (the Anthropic SDK
# is the whole reason this shim needs it), whereas plain httpx is near
# ubiquitous and its presence says nothing about what the caller wants. Pass
# `flavor="httpx"` to override per call — this package deliberately installs no
# process-wide alias, because that is an application-level switch.
_FLAVOR_ORDER = ("httpx2", "httpx")

_BUILT: dict[str, tuple[type, type]] = {}


def _select_flavor(name: str | None = None) -> str:
    """Resolve a flavor name, or raise. See :func:`flavor` for the contract."""
    if name is not None and name not in _FLAVOR_HTTPCORE:
        raise EgressConfigError(
            f"unknown egress httpx flavor {name!r}; expected one of {sorted(_FLAVOR_HTTPCORE)}"
        )
    for candidate in ((name,) if name else _FLAVOR_ORDER):
        # find_spec, not import: it answers "is this installed" without
        # executing the package, so a *broken* httpx2 install fails loudly in
        # _build_transports rather than silently demoting us to plain httpx.
        if importlib.util.find_spec(candidate) is not None:
            return candidate
    raise EgressConfigError(
        f"the egress transport requires {name or 'httpx2 or httpx'}: "
        "pip install 'hawcx-haap[httpx2]' (for the Anthropic SDK 1.x and other "
        "httpx2-based clients) or 'hawcx-haap[httpx]'"
    )


def flavor(name: str | None = None) -> str:
    """Return the httpx flavor this shim will use: ``"httpx2"`` or ``"httpx"``.

    The object returned by :func:`client` is an instance of *that* module's
    ``Client``, so this is how a caller tells which lineage they got without
    importing both — and why ``anthropic.Anthropic(http_client=...)`` now works:
    it accepts only an ``httpx2.Client``.

    With ``name`` given, checks that one specific flavor is installed. With no
    argument, resolves by precedence (``httpx2`` before ``httpx``). Raises
    :class:`EgressConfigError` — never ``ImportError`` — when nothing usable is
    installed, so the failure reads the same as every other egress
    misconfiguration.
    """
    return _select_flavor(name)


def _build_transports(flavor_name: str) -> tuple[type, type]:
    """Define the transport subclasses for one flavor lazily, so importing this
    module does not require either lineage. Cached per flavor."""
    cached = _BUILT.get(flavor_name)
    if cached is not None:
        return cached

    core_name = _FLAVOR_HTTPCORE[flavor_name]
    try:
        httpx = importlib.import_module(flavor_name)
        httpcore = importlib.import_module(core_name)
        sync_stream = importlib.import_module(f"{core_name}._backends.sync").SyncStream
        anyio_stream = importlib.import_module(f"{core_name}._backends.anyio").AnyIOStream
    # AttributeError is in here on purpose: a renamed stream class must fail
    # loud exactly like a missing module, never silently direct.
    except (ModuleNotFoundError, ImportError, AttributeError) as exc:
        raise EgressConfigError(
            f"egress transport could not load the {core_name} network-backend seam: {exc}. "
            f"Requires {core_name} (installed with {flavor_name})."
        ) from exc

    class _SyncBackend(httpcore.NetworkBackend):  # type: ignore[misc,name-defined]
        def __init__(self, socket_path: str) -> None:
            self._socket_path = socket_path

        def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            sock = _socks5_connect_sync(self._socket_path, host, port, timeout)
            return sync_stream(sock)

        def connect_unix_socket(self, path, timeout=None, socket_options=None):  # pragma: no cover
            raise EgressProtocolError("egress transport connects only via the broker CONNECT path")

    class _AsyncBackend(httpcore.AsyncNetworkBackend):  # type: ignore[misc,name-defined]
        def __init__(self, socket_path: str) -> None:
            self._socket_path = socket_path

        async def connect_tcp(
            self, host, port, timeout=None, local_address=None, socket_options=None
        ):
            stream = await _socks5_connect_async(self._socket_path, host, port, timeout)
            return anyio_stream(stream)

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

    _BUILT[flavor_name] = (EgressHTTPTransport, EgressAsyncHTTPTransport)
    return _BUILT[flavor_name]


def __getattr__(name: str) -> Any:
    # Expose the transport classes as module attributes without importing httpx
    # at module load. `from hawcx_haap.egress import EgressHTTPTransport` works
    # iff one of the httpx extras is installed, and follows the same precedence.
    if name in ("EgressHTTPTransport", "EgressAsyncHTTPTransport"):
        sync_cls, async_cls = _build_transports(_select_flavor())
        return sync_cls if name == "EgressHTTPTransport" else async_cls
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def client(
    *,
    socket_path: str | None = None,
    verify: Any = True,
    http2: bool = False,
    flavor: str | None = None,
    **client_kwargs: Any,
) -> Any:
    """Return an ``httpx2.Client`` (or ``httpx.Client``) whose outbound traffic
    tunnels through the per-agent egress broker.

    ``verify`` is forwarded to the transport unchanged (TLS is not terminated by
    the broker or the shim). ``flavor`` pins the lineage — see
    :func:`flavor` for the default precedence and how to tell which you got.
    Extra kwargs go to the client (timeout, headers, ...).

    The returned object is what ``anthropic.Anthropic(http_client=...)`` expects
    whenever ``httpx2`` is the resolved flavor.
    """
    flavor_name = _select_flavor(flavor)
    httpx = importlib.import_module(flavor_name)
    sync_cls, _ = _build_transports(flavor_name)
    path = resolve_socket_path(socket_path)
    transport = sync_cls(path, verify=verify, http2=http2)
    client_kwargs.setdefault("timeout", _DEFAULT_TIMEOUT)
    return httpx.Client(transport=transport, **client_kwargs)


def async_client(
    *,
    socket_path: str | None = None,
    verify: Any = True,
    http2: bool = False,
    flavor: str | None = None,
    **client_kwargs: Any,
) -> Any:
    """Async counterpart of :func:`client`."""
    flavor_name = _select_flavor(flavor)
    httpx = importlib.import_module(flavor_name)
    _, async_cls = _build_transports(flavor_name)
    path = resolve_socket_path(socket_path)
    transport = async_cls(path, verify=verify, http2=http2)
    client_kwargs.setdefault("timeout", _DEFAULT_TIMEOUT)
    return httpx.AsyncClient(transport=transport, **client_kwargs)


# ── requests transport wiring (lazy: needs the optional requests extra) ──────
#
# The Google client libraries are requests-based (google-auth's
# AuthorizedSession), so the httpx transport above cannot carry them. They
# default to gRPC, which cannot traverse a SOCKS5 proxy reachable only over a
# Unix socket, but every such client also ships a REST transport, and REST means
# requests, which means urllib3 — which has the same seam httpx does: the one
# place a TCP socket is created. So the shape below mirrors the httpx transport
# exactly. Swap the socket creation, change nothing else. TLS is still
# negotiated by urllib3 against the real hostname after the broker connects, so
# certificate verification is untouched and the broker never sees plaintext.


def _brokered_pool_classes(socket_path: str) -> tuple[type, type]:
    """Build urllib3 pool classes whose TCP connect goes via the broker.

    Built per socket path rather than reading the environment at connect time:
    a connection pool can outlive the call that created it, and re-reading the
    environment later would let a changed variable silently repoint live
    connections.
    """
    try:
        import urllib3.connection
        import urllib3.connectionpool
        from urllib3.util.timeout import _DEFAULT_TIMEOUT as _URLLIB3_DEFAULT_TIMEOUT
    except (ModuleNotFoundError, ImportError) as exc:  # fail loud, never silently direct
        raise EgressConfigError(
            f"egress transport could not load the urllib3 connection seam: {exc}. "
            "Requires urllib3>=2 (installed with requests)."
        ) from exc

    def _new_conn(self):  # noqa: ANN001, ANN202 - urllib3 protocol
        # urllib3 represents "no timeout set" with a sentinel object, and
        # socket.settimeout raises TypeError on it rather than treating it as
        # None. Measured 2026-09-21 on urllib3 2.0.7 / 2.2.3 / 2.8.0:
        # HTTPConnection.__init__ already calls Timeout.resolve_default_timeout,
        # so self.timeout is resolved before we ever see it and this branch does
        # not currently fire. Kept because it costs one comparison, it is what
        # the proven downstream implementation does, and the failure it guards
        # against is a TypeError at connect time on every request.
        # ponytail: defensive, measured-unreachable on urllib3 2.x.
        timeout = None if self.timeout is _URLLIB3_DEFAULT_TIMEOUT else self.timeout
        # self.host, never self._dns_host: the broker must receive the name the
        # caller asked for. The allowlist is by hostname, so resolving locally
        # and dialling the result would be a security regression, not a style
        # one (ADR-0048, socks5h semantics).
        return _socks5_connect_sync(socket_path, self.host, self.port, timeout)

    https_conn = type(
        "BrokeredHTTPSConnection", (urllib3.connection.HTTPSConnection,), {"_new_conn": _new_conn}
    )
    http_conn = type(
        "BrokeredHTTPConnection", (urllib3.connection.HTTPConnection,), {"_new_conn": _new_conn}
    )
    https_pool = type(
        "BrokeredHTTPSConnectionPool",
        (urllib3.connectionpool.HTTPSConnectionPool,),
        {"ConnectionCls": https_conn},
    )
    http_pool = type(
        "BrokeredHTTPConnectionPool",
        (urllib3.connectionpool.HTTPConnectionPool,),
        {"ConnectionCls": http_conn},
    )
    return https_pool, http_pool


def requests_session(*, socket_path: str | None = None, **adapter_kwargs: Any) -> Any:
    """Return a ``requests.Session`` whose outbound traffic tunnels through the
    per-agent egress broker.

    Same contract as :func:`client`: the socket is resolved and stat'd up front,
    and a broker that is unconfigured, absent or not a socket raises rather than
    handing back a session that would dial the network directly.

    Exists for the Google client libraries, whose REST transports build a
    ``google.auth.transport.requests.AuthorizedSession`` on top of ``requests``.
    Extra kwargs go to the ``HTTPAdapter`` (``pool_connections``,
    ``pool_maxsize``, ``max_retries``).

    ``requests`` is an optional extra::

        pip install 'hawcx-haap[requests]'
    """
    try:
        import requests
    except ModuleNotFoundError as exc:
        raise EgressConfigError(
            "the egress requests session requires requests: "
            "pip install 'hawcx-haap[requests]'"
        ) from exc

    # Resolves and stats the socket, raising if it is absent or not a socket.
    path = resolve_socket_path(socket_path)
    https_pool, http_pool = _brokered_pool_classes(path)

    class _BrokeredAdapter(requests.adapters.HTTPAdapter):
        def init_poolmanager(self, *args: Any, **kw: Any) -> None:
            super().init_poolmanager(*args, **kw)
            # Swap the pool classes in place rather than re-threading the
            # PoolManager's kwargs. Fails loud if urllib3 renames the mapping,
            # which is the right outcome: never degrade to a direct dial.
            assert hasattr(self.poolmanager, "pool_classes_by_scheme"), (
                "urllib3 PoolManager layout changed"
            )
            self.poolmanager.pool_classes_by_scheme = {"http": http_pool, "https": https_pool}

        def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
            # `requests` reads $HTTPS_PROXY/$HTTP_PROXY from the environment by
            # default (Session.trust_env), and a proxy manager builds STOCK
            # pools -- the brokered classes above are never consulted. Measured
            # 2026-09-22 against 0.1.11: with $HTTPS_PROXY set, the broker
            # observes ZERO CONNECTs and the request dials the proxy directly.
            # Inside the sandbox that is the hang this shim exists to replace;
            # outside it, it is a silent bypass of the egress control. Same
            # contract as resolve_socket_path: raise, never degrade.
            raise EgressConfigError(
                f"egress session refuses to route through an HTTP proxy ({proxy!r}): "
                "requests took it from $HTTPS_PROXY/$HTTP_PROXY or an explicit "
                "proxies= argument, and a proxied request would leave the broker. "
                "Unset those variables, or set session.trust_env = False."
            )

    session = requests.Session()
    adapter = _BrokeredAdapter(**adapter_kwargs)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session
