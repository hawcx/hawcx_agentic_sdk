"""Property tests for hawcx_haap.ipc framing — the SDK-owned parser of untrusted
bytes off the Assembler UDS (``[len:u32 BE][type:u8][payload]``).

Generative (``hypothesis``) counterpart to the example / boundary cases in
``test_ipc.py``. The two properties retained here each carry a real boundary
dimension that no example test exercises:

  * a valid frame round-trips through ``read_frame`` at ANY recv-chunking
    granularity — the only generative exercise of the ``_recv_exact``
    reassembly loop on the success path (the fuzz file's random streams almost
    never form a valid frame, so they never reach it);
  * the largest legal payload (``msg_len == MAX_MESSAGE_SIZE``) is read in full
    — the accept side of the length-prefix DoS boundary whose reject side lives
    in ``test_fuzz_ipc.py``.

The Rust ``haap-ipc`` fuzzing does NOT protect this re-implemented Python
parser, so these invariants are asserted here directly. ``_ByteSock`` below is
also imported by ``test_fuzz_ipc.py``.
"""

from __future__ import annotations

import struct

from hypothesis import given, settings
from hypothesis import strategies as st

from hawcx_haap.ipc import (
    MAX_MESSAGE_SIZE,
    encode_frame,
    read_frame,
)


class _ByteSock:
    """A minimal ``socket``-shaped reader that serves a fixed buffer to
    ``read_frame``. ``recv(n)`` returns up to ``chunk`` bytes (to exercise the
    ``_recv_exact`` reassembly loop) and ``b""`` at EOF. ``max_request`` records
    the largest single ``recv`` size requested, so a test can prove the parser
    never asks the kernel for an unbounded read on a lying length-prefix."""

    def __init__(self, data: bytes, chunk: int | None = None) -> None:
        self._data = bytes(data)
        self._pos = 0
        self._chunk = chunk
        self.max_request = 0

    def recv(self, n: int) -> bytes:
        self.max_request = max(self.max_request, n)
        take = n if self._chunk is None else min(n, self._chunk)
        out = self._data[self._pos : self._pos + take]
        self._pos += len(out)
        return out


# ── Property: a valid frame round-trips at any recv-chunking granularity ──────


@settings(max_examples=300)
@given(
    msg_type=st.integers(min_value=0, max_value=0xFF),
    # Cap payload well under MAX so encode never rejects; the exact-boundary
    # case is covered separately. 4 KiB keeps 300 examples fast.
    payload=st.binary(max_size=4096),
    chunk=st.one_of(st.none(), st.integers(min_value=1, max_value=7)),
)
def test_prop_encode_read_frame_round_trip(
    msg_type: int, payload: bytes, chunk: int | None
) -> None:
    """``read_frame(encode_frame(t, p)) == (t, p)`` for every type byte and
    payload, at any recv-chunking granularity — the reassembly-loop regression
    guard for ``_recv_exact`` under fragmented reads."""
    frame = encode_frame(msg_type, payload)
    # Structural invariant of the encoder itself.
    assert struct.unpack(">I", frame[:4])[0] == 1 + len(payload)
    sock = _ByteSock(frame, chunk=chunk)
    got_type, got_payload = read_frame(sock)
    assert got_type == msg_type
    assert got_payload == payload


def test_encode_read_frame_round_trip_at_max_boundary() -> None:
    """The largest legal payload (msg_len == MAX) still round-trips exactly —
    the accept side of the length-prefix DoS boundary."""
    payload = b"\xa5" * (MAX_MESSAGE_SIZE - 1)
    got_type, got_payload = read_frame(_ByteSock(encode_frame(0x52, payload)))
    assert got_type == 0x52
    assert got_payload == payload
