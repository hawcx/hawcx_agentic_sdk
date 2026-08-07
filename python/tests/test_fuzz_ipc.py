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

import struct

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from test_prop_ipc import _ByteSock

from hawcx_haap.errors import IpcError
from hawcx_haap.ipc import MAX_MESSAGE_SIZE, _decode_handshake, read_frame

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


if __name__ == "__main__":  # pragma: no cover
    import sys

    sys.exit(pytest.main([__file__, "-v", "-s"]))
