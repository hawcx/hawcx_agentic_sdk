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

from hawcx_haap.errors import IpcError
from hawcx_haap.ipc import (
    MAX_MESSAGE_SIZE,
    _diagnosable_ipc_error,
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


# ── Property: a diagnosable IPC error always names endpoint + op + type ──────
#
# The 2026-09-21 UKG demo bug (see ipc.py's _diagnosable_ipc_error docstring)
# was a bare `str(TimeoutError())` == "timed out" propagating with no
# endpoint, no operation, no type. This is the invariant that fix has to
# hold for ANY endpoint string and ANY underlying exception, not just the
# specific TimeoutError/FileNotFoundError cases test_ipc.py exercises with
# real sockets -- a stateful/generative counterpart to those examples.

# Endpoint alphabet restricted to characters `repr()` never escapes, so
# `endpoint in str(wrapped)` is a valid substring check against the `!r`
# formatting `_diagnosable_ipc_error` uses -- not an artifact of what
# `repr()` does to quotes or backslashes.
_PATH_SAFE_TEXT = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="/-_.~"
    ),
    min_size=1,
    max_size=80,
)


@settings(max_examples=200)
@given(
    endpoint=_PATH_SAFE_TEXT,
    op=st.sampled_from(["connect", "handshake-read"]),
    timeout_secs=st.one_of(
        st.none(), st.floats(min_value=0, max_value=120, allow_nan=False, allow_infinity=False)
    ),
    exc=st.sampled_from(
        [
            TimeoutError("timed out"),
            FileNotFoundError(2, "No such file or directory"),
            ConnectionRefusedError(61, "Connection refused"),
            IpcError("IPC peer closed connection mid-message"),
        ]
    ),
)
def test_prop_diagnosable_ipc_error_always_names_endpoint_op_and_type(
    endpoint: str, op: str, timeout_secs: float | None, exc: Exception
) -> None:
    wrapped = _diagnosable_ipc_error(endpoint, op, timeout_secs, exc)
    assert isinstance(wrapped, IpcError)
    msg = str(wrapped)
    assert endpoint in msg, "endpoint must survive into the message"
    assert op in msg, "operation must survive into the message"
    assert type(exc).__name__ in msg, "underlying exception TYPE must survive into the message"
    # And never just the underlying str() alone -- the exact shape of the bug.
    assert msg != str(exc)
