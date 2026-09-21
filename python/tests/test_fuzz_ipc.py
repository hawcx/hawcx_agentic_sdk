"""Generative fuzz (Layer 4) for hawcx_haap.ipc — the untrusted-byte frame and
handshake decoders (``read_frame`` / ``_decode_handshake``).

Four-layer discipline per docs/engineering/TESTING-STANDARD.md; see
``test_prop_ipc.py`` for layers 1-3. This file is Layer 4: throw arbitrary,
truncated, and deliberately-lying length-prefixed bytes at the parser and prove
the ONLY thing that ever escapes is a specific ``IpcError`` — never a hang,
never an allocation past ``MAX_MESSAGE_SIZE``, never another exception type.

The Rust ``haap-ipc`` fuzz corpus does not cover this Python re-implementation,
so the "arbitrary u32 length-prefix cannot cause an oversized read" invariant —
the classic length-prefix DoS — is asserted here on the Python code itself via
``_ByteSock.max_request``.
"""

from __future__ import annotations

import os
import socket
import struct
import sys
import tempfile
import threading
import uuid

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from test_prop_ipc import _ByteSock

from hawcx_haap.errors import IpcError
from hawcx_haap.ipc import MAX_MESSAGE_SIZE, AssemblerClient, _decode_handshake, read_frame

# Ceiling on any single recv the parser is allowed to request. The 4-byte
# length prefix plus at most MAX_MESSAGE_SIZE of body. A larger request means a
# lying length-prefix was trusted into an unbounded allocation.
_RECV_CEILING = MAX_MESSAGE_SIZE + 4


# ── read_frame: arbitrary whole streams ──────────────────────────────────────


@settings(max_examples=500)
@given(
    data=st.binary(max_size=512),
    chunk=st.one_of(st.none(), st.integers(min_value=1, max_value=7)),
)
def test_fuzz_read_frame_arbitrary_stream(data: bytes, chunk: int | None) -> None:
    """Arbitrary bytes → ``read_frame`` returns a well-formed ``(type, payload)``
    consistent with the header it read, or raises ``IpcError``. Nothing else,
    and never a recv past the ceiling."""
    sock = _ByteSock(data, chunk=chunk)
    try:
        msg_type, payload = read_frame(sock)
    except IpcError:
        assert sock.max_request <= _RECV_CEILING
        return
    # Success: the parse must be self-consistent with the declared length.
    assert 0 <= msg_type <= 0xFF
    assert sock.max_request <= MAX_MESSAGE_SIZE
    declared = struct.unpack(">I", data[:4])[0]
    assert 1 <= declared <= MAX_MESSAGE_SIZE
    assert len(payload) == declared - 1
    assert bytes([msg_type]) + payload == data[4 : 4 + declared]


# ── read_frame: a fully attacker-controlled u32 length-prefix ────────────────


@settings(max_examples=500)
@given(
    declared=st.integers(min_value=0, max_value=2**32 - 1),
    type_byte=st.integers(min_value=0, max_value=0xFF),
    body=st.binary(max_size=80),
)
def test_fuzz_read_frame_lying_length_prefix(
    declared: int, type_byte: int, body: bytes
) -> None:
    """The length-prefix DoS: a frame claims ``declared`` bytes (up to 4 GiB)
    but supplies only ``body``. The parser must reject an over-cap or truncated
    claim with ``IpcError`` and, crucially, must NEVER attempt to read the
    claimed size when it exceeds ``MAX_MESSAGE_SIZE``."""
    stream = struct.pack(">I", declared) + bytes([type_byte]) + body
    sock = _ByteSock(stream)
    try:
        msg_type, payload = read_frame(sock)
    except IpcError:
        # Even handed a 4 GiB claim, the guard fires before any body recv.
        assert sock.max_request <= MAX_MESSAGE_SIZE
        return
    # Success only when the claim was in-range AND fully satisfied.
    assert 1 <= declared <= MAX_MESSAGE_SIZE
    assert msg_type == type_byte
    assert len(payload) == declared - 1
    assert sock.max_request <= MAX_MESSAGE_SIZE


# ── _decode_handshake: arbitrary payloads ────────────────────────────────────


@settings(max_examples=300)
@given(payload=st.binary(max_size=64))
def test_fuzz_decode_handshake_defined(payload: bytes) -> None:
    """Arbitrary handshake payload → a 5-tuple of in-range ints parsed from the
    first 9 bytes, or ``IpcError`` when too short. No other outcome."""
    try:
        proto, major, minor, patch, role = _decode_handshake(payload)
    except IpcError:
        assert len(payload) < 9
        return
    assert len(payload) >= 9
    for field in (proto, major, minor, patch):
        assert 0 <= field <= 0xFFFF
    assert 0 <= role <= 0xFF
    # Only the first 9 bytes are consumed; trailing bytes are ignored.
    assert (proto, major, minor, patch, role) == struct.unpack(">HHHHB", payload[:9])


# ── AssemblerClient.connect over a real socket: the handshake-READ path ──────
#
# The tests above fuzz the byte-level decoders directly. This one fuzzes the
# live path the 2026-09-21 diagnosability fix touched:
# `AssemblerClient.connect` reading a handshake reply off a REAL AF_UNIX
# socket from a peer that sends garbage, truncated, empty, or oversized-claim
# bytes back. The only acceptable outcomes are (a) a well-formed connect (for
# the astronomically rare garbage that happens to decode as a valid Assembler
# handshake) or (b) `IpcError` -- specifically the wrapped
# `_diagnosable_ipc_error` -- and NEVER a hang or a raw/other exception type
# escaping to the caller.


def _short_socket_dir() -> str:
    """A short, 0o700 AF_UNIX-safe temp dir, independent of `conftest.py`'s
    private helper so this file doesn't reach into it -- see that helper's
    docstring for why a bare mkdtemp() is used over pytest's tmp_path."""
    d = tempfile.mkdtemp(prefix="hx-fuzz-hs-")
    os.chmod(d, 0o700)
    return d


def _serve_garbage_reply(server: socket.socket, garbage: bytes) -> None:
    try:
        conn, _ = server.accept()
    except OSError:
        return
    try:
        conn.settimeout(2)
        # Drain the client's own handshake write (best-effort) so this is
        # testing the REPLY, not just a refused write.
        try:
            length_bytes = conn.recv(4)
            if len(length_bytes) == 4:
                msg_len = struct.unpack(">I", length_bytes)[0]
                if 0 < msg_len <= MAX_MESSAGE_SIZE:
                    conn.recv(msg_len)
        except OSError:
            pass
        if garbage:
            conn.sendall(garbage)
    except OSError:
        pass
    finally:
        conn.close()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Python on the Windows GHA runner image does not expose socket.AF_UNIX "
    "(same reason conftest's short_sock_path fixture skips; this file rolls its own "
    "temp dir and so does not inherit that guard)",
)
@settings(max_examples=25, deadline=None)
@given(garbage=st.binary(max_size=256))
def test_fuzz_assembler_connect_handshake_reply_never_hangs(garbage: bytes) -> None:
    """A crashed or malicious Assembler can send ANYTHING back after the
    client's handshake write -- empty, truncated, a lying oversized length
    prefix, pure noise. `connect()` must always terminate promptly and the
    only exception type that escapes is `IpcError`."""
    socket_dir = _short_socket_dir()
    socket_path = os.path.join(socket_dir, f"{uuid.uuid4().hex[:8]}.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(socket_path)
    server.listen(1)
    t = threading.Thread(target=_serve_garbage_reply, args=(server, garbage), daemon=True)
    t.start()
    try:
        try:
            client = AssemblerClient.connect(socket_path, timeout_secs=2.0)
        except IpcError:
            pass
        else:
            client.close()
    except Exception as exc:  # pragma: no cover — the assertion IS the failure
        pytest.fail(f"connect raised {type(exc).__name__} instead of IpcError: {exc}")
    finally:
        t.join(timeout=3)
        assert not t.is_alive(), "server thread never finished — client hung"
        server.close()
        try:
            os.unlink(socket_path)
        except FileNotFoundError:
            pass


if __name__ == "__main__":  # pragma: no cover
    import sys

    sys.exit(pytest.main([__file__, "-v", "-s"]))
