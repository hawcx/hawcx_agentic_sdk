"""Test doubles for the egress-broker transport: a fake SOCKS5 broker over a
UDS, and a local TLS server to prove the tunnel is opaque (TLS not terminated).

The fake broker is handler-driven: each accepted connection is passed to a
callback, so a test can speak the real handshake and relay, or emit arbitrary
(truncated / malformed / oversized) bytes for the boundary-fuzz layer.
"""

from __future__ import annotations

import datetime
import socket
import ssl
import struct
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any


def recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed during recv")
        buf.extend(chunk)
    return bytes(buf)


def read_socks_request(conn: socket.socket) -> bytes:
    """Read one full SOCKS5 CONNECT request (assuming ATYP=0x03) and return the
    raw bytes exactly as received, for assertion."""
    head = recv_exact(conn, 4)  # VER CMD RSV ATYP
    atyp = head[3]
    if atyp == 0x03:
        ln = recv_exact(conn, 1)
        rest = recv_exact(conn, ln[0] + 2)
        return head + ln + rest
    if atyp == 0x01:
        return head + recv_exact(conn, 4 + 2)
    if atyp == 0x04:
        return head + recv_exact(conn, 16 + 2)
    raise ConnectionError(f"unexpected ATYP {atyp:#x}")


class FakeBroker:
    """Threaded UDS server. ``handler(conn, broker)`` runs per connection.
    ``broker.requests`` collects each connection's captured CONNECT bytes when
    the handler chooses to capture them."""

    def __init__(self, handler: Callable[[socket.socket, FakeBroker], None]) -> None:
        self._handler = handler
        self._dir = tempfile.TemporaryDirectory()
        self.path = str(Path(self._dir.name) / "egress-broker.sock")
        self._srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._srv.bind(self.path)
        self._srv.listen(64)
        self.requests: list[bytes] = []
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []
        self._stop = False
        self._accept = threading.Thread(target=self._accept_loop, daemon=True)

    def record(self, req: bytes) -> None:
        with self._lock:
            self.requests.append(req)

    def _accept_loop(self) -> None:
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            t = threading.Thread(target=self._serve, args=(conn,), daemon=True)
            t.start()
            self._threads.append(t)

    def _serve(self, conn: socket.socket) -> None:
        try:
            self._handler(conn, self)
        except (OSError, ConnectionError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def __enter__(self) -> FakeBroker:
        self._accept.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._stop = True
        try:
            self._srv.close()
        except OSError:
            pass
        self._dir.cleanup()


# ── handlers ────────────────────────────────────────────────────────────────

_SUCCESS_REPLY = b"\x05\x00\x00\x01" + bytes(4) + bytes(2)  # REP=0 ATYP=IPv4 0.0.0.0:0


def relay_handler(upstream_host: str, upstream_port: int):
    """Full success: accept, capture the request, reply success, then pipe
    bytes both ways to the upstream. TLS runs end-to-end through this pipe."""

    def handler(conn: socket.socket, broker: FakeBroker) -> None:
        recv_exact(conn, 3)  # greeting
        conn.sendall(b"\x05\x00")  # NO-AUTH selected
        broker.record(read_socks_request(conn))
        up = socket.create_connection((upstream_host, upstream_port))
        conn.sendall(_SUCCESS_REPLY)
        _pump(conn, up)

    return handler


def scripted_handler(
    *,
    method_reply: bytes = b"\x05\x00",
    connect_reply: bytes = b"\x05\x02\x00\x01" + bytes(6),  # REP=0x02 policy-deny
    capture: bool = True,
):
    """Speak the greeting, optionally capture the request, then emit a scripted
    (possibly malformed/truncated) connect reply and close."""

    def handler(conn: socket.socket, broker: FakeBroker) -> None:
        recv_exact(conn, 3)
        conn.sendall(method_reply)
        if method_reply[:2] != b"\x05\x00":
            return  # broker would close after refusing method negotiation
        if capture:
            broker.record(read_socks_request(conn))
        else:
            try:
                conn.recv(4096)
            except OSError:
                pass
        if connect_reply:
            conn.sendall(connect_reply)

    return handler


def close_no_reply_handler(conn: socket.socket, broker: FakeBroker) -> None:
    """Peer-cred rejection: accept then close without any reply."""
    conn.close()


def reset_no_reply_handler(conn: socket.socket, broker: FakeBroker) -> None:
    """Peer-cred rejection that lands as an RST rather than a clean EOF.

    ``SO_LINGER`` with a zero timeout asks for RST instead of a graceful FIN. On
    Linux that is what an agent actually observes when the broker rejects it at
    the ``SO_PEERCRED`` gate and closes with our greeting still queued — the case
    that leaked a raw ``ConnectionResetError`` before this was handled.

    Honest ceiling: ``SO_LINGER`` is a no-op for ``AF_UNIX`` on macOS, so this
    handler degrades to a clean close there and only exercises the reset path on
    Linux. Linux is the light-mode platform, so that is where it counts — but it
    does mean a macOS-only run cannot prove this path.
    """
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    conn.close()


def _pump(a: socket.socket, b: socket.socket) -> None:
    def copy(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    t1 = threading.Thread(target=copy, args=(a, b), daemon=True)
    t2 = threading.Thread(target=copy, args=(b, a), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


# ── local TLS server + self-signed cert ──────────────────────────────────────


def make_localhost_cert(dirpath: str) -> tuple[str, str]:
    """Mint an in-test self-signed localhost cert. Returns (cert_pem, key_pem)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    d = Path(dirpath)
    cert_pem = d / "cert.pem"
    key_pem = d / "key.pem"
    cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return str(cert_pem), str(key_pem)


class TLSServer:
    """Minimal HTTPS server: one fixed 200 response per connection."""

    def __init__(self, cert_pem: str, key_pem: str, body: bytes = b"ok") -> None:
        self._body = body
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_pem, key_pem)
        self._ctx = ctx
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(16)
        self.host, self.port = self._srv.getsockname()
        self._stop = False
        self._t = threading.Thread(target=self._loop, daemon=True)

    def _loop(self) -> None:
        while not self._stop:
            try:
                raw, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(raw,), daemon=True).start()

    def _serve(self, raw: socket.socket) -> None:
        try:
            tls = self._ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            raw.close()
            return
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                data += chunk
            resp = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (
                len(self._body),
                self._body,
            )
            tls.sendall(resp)
        except OSError:
            pass
        finally:
            try:
                tls.close()
            except OSError:
                pass

    def __enter__(self) -> TLSServer:
        self._t.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._stop = True
        try:
            self._srv.close()
        except OSError:
            pass
