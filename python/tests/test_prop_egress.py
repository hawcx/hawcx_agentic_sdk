"""Property tests for the pure SOCKS5 wire helpers in hawcx_haap.egress — the
SDK-owned parser of an untrusted broker reply (ADR-0048).

Generative (``hypothesis``) counterpart to the example/parametrised cases in
``test_egress.py``. Retained here are the invariants that hold over a whole
untrusted byte domain and are not already pinned by an example:

  * ``_encode_host`` wire-safety: for ANY string the output is 1..255 bytes with
    no NUL, or a defined ``EgressProtocolError`` (256+ rejected, NUL anywhere
    rejected — via the ASCII check or the IDNA failure).
  * ``_bound_trailer_len`` / ``_reply_exception`` / ``_check_method_reply``:
    total over the whole attacker-controlled byte domain, only the specific
    ``EgressError`` subclass ever surfaces — never a crash or a bogus success.

These helpers are pure (no IO), so the properties run without a broker and
without the httpx extra. Every rejection asserts the SPECIFIC exception type.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from hawcx_haap.egress import (
    _bound_trailer_len,
    _check_method_reply,
    _encode_host,
    _reply_exception,
)
from hawcx_haap.errors import (
    EgressError,
    EgressHostUnreachable,
    EgressPolicyDenied,
    EgressProtocolError,
)

_PORTS = st.integers(min_value=0, max_value=0xFFFF)


# ── _encode_host wire-safety ─────────────────────────────────────────────────


@given(host=st.text(max_size=300))
def test_prop_encode_host_output_is_always_wire_safe(host: str) -> None:
    """The safety net: for ANY string (incl. the IDNA path), ``_encode_host``
    either returns 1..255 bytes with no NUL, or raises ``EgressProtocolError``.
    A malformed frame must never be emitted, and no other exception may escape."""
    try:
        raw = _encode_host(host)
    except EgressProtocolError:
        return
    assert isinstance(raw, bytes)
    assert 1 <= len(raw) <= 255
    assert b"\x00" not in raw


@given(n=st.integers(min_value=256, max_value=1024))
def test_prop_encode_host_over_255_rejected(n: int) -> None:
    """256+ rejected — the reject side of the DOMAINNAME 1..255 length bound."""
    with pytest.raises(EgressProtocolError):
        _encode_host("a" * n)


@given(host=st.text(max_size=64), pos=st.integers(min_value=0, max_value=64))
def test_prop_encode_host_nul_always_rejected(host: str, pos: int) -> None:
    """A NUL anywhere → ``EgressProtocolError`` (via the ASCII NUL check or,
    for non-ASCII hosts, the IDNA failure). Never a malformed frame."""
    pos = min(pos, len(host))
    with pytest.raises(EgressProtocolError):
        _encode_host(host[:pos] + "\x00" + host[pos:])


# ── _bound_trailer_len (total over all 256 ATYP values) ──────────────────────


@given(atyp=st.integers(min_value=0, max_value=0xFF))
def test_prop_bound_trailer_len_total(atyp: int) -> None:
    """Untrusted ATYP byte from the broker reply → a defined trailer length for
    the three real address types, ``EgressProtocolError`` for every other."""
    if atyp == 0x01:  # IPv4
        assert _bound_trailer_len(atyp) == 6
    elif atyp == 0x04:  # IPv6
        assert _bound_trailer_len(atyp) == 18
    elif atyp == 0x03:  # DOMAINNAME — length byte read separately
        assert _bound_trailer_len(atyp) is None
    else:
        with pytest.raises(EgressProtocolError):
            _bound_trailer_len(atyp)


# ── _reply_exception (always an EgressError, for every reply byte) ───────────


@given(rep=st.integers(min_value=0, max_value=0xFF), host=st.text(max_size=32), port=_PORTS)
def test_prop_reply_exception_always_egress_error(rep: int, host: str, port: int) -> None:
    exc = _reply_exception(rep, host, port)
    assert isinstance(exc, EgressError)
    if rep == 0x02:
        assert isinstance(exc, EgressPolicyDenied)
        assert exc.host == host and exc.port == port
    elif rep == 0x04:
        assert isinstance(exc, EgressHostUnreachable)
        assert exc.host == host and exc.port == port
    else:
        assert isinstance(exc, EgressProtocolError)


# ── _check_method_reply (total over the 2-byte method reply the driver reads) ─


@settings(max_examples=300)
@given(reply=st.binary(min_size=2, max_size=2))
def test_prop_check_method_reply_defined(reply: bytes) -> None:
    """The driver always hands ``_check_method_reply`` exactly 2 bytes. Over that
    whole domain it returns ``None`` for the one accepting reply (05 00) and
    raises the specific ``EgressProtocolError`` for every other."""
    try:
        result = _check_method_reply(reply)
    except EgressProtocolError:
        assert reply != b"\x05\x00"
        return
    assert result is None
    assert reply == b"\x05\x00"
