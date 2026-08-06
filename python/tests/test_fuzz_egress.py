"""Generative fuzz (Layer 4) for the hawcx_haap.egress SOCKS5 reply parser —
end-to-end through a fake broker, driven by ``hypothesis``.

Four-layer discipline per docs/engineering/TESTING-STANDARD.md; layers 1-3 live
in ``test_egress.py`` / ``test_prop_egress.py``. This file generalises the
seeded ``test_boundary_fuzz_defined_exceptions_only`` case in ``test_egress.py``
into a ``@given`` search: an arbitrary broker method-reply and CONNECT-reply are
fed through the real ``egress.client`` handshake, and the ONLY exceptions
allowed to escape are ``HawcxError`` (the SDK's ``EgressError`` family) or
``httpx.HTTPError`` (a downstream transport failure once the socket is handed
off). Any other exception type — or a silent success on garbage — is a defect.

The Rust ``haap-ipc`` fuzz corpus does not cover this Python SOCKS5 client.
"""

from __future__ import annotations

import socket

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

pytest.importorskip("httpx")
import httpx  # noqa: E402
from egress_broker import FakeBroker, scripted_handler  # noqa: E402

from hawcx_haap import egress  # noqa: E402
from hawcx_haap.errors import HawcxError  # noqa: E402

pytestmark = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="egress broker is UNIX-domain-socket only"
)

# The only exception families permitted to cross the shim boundary.
_DEFINED = (HawcxError, httpx.HTTPError)

_GOOD_METHOD = b"\x05\x00"


def _run_case(*, method_reply: bytes, connect_reply: bytes) -> None:
    """Drive one full handshake against a broker emitting the given bytes.
    Only ``_DEFINED`` exceptions may escape; a success on fuzz input is a bug."""
    handler = scripted_handler(
        method_reply=method_reply, connect_reply=connect_reply, capture=True
    )
    with FakeBroker(handler) as broker:
        with egress.client(socket_path=broker.path, verify=False, timeout=1.0) as http:
            try:
                resp = http.get("https://fuzz.example.com/")
            except _DEFINED:
                return  # defined failure — acceptable
            except BaseException as exc:  # noqa: BLE001
                raise AssertionError(
                    f"undefined exception escaped the shim: {type(exc).__name__}: {exc}"
                ) from exc
            raise AssertionError(
                f"fuzz input unexpectedly produced a success response: {resp.status_code}"
            )


# ── Fuzz the CONNECT-reply parser (method negotiation held valid) ────────────
#
# Holding the method reply valid (05 00) is what makes every generated
# connect_reply actually reach the deep parser — `_reply_exception`,
# `_bound_trailer_len`, and the DOMAINNAME length-byte drain. Fuzzing the tiny
# 2-byte method reply is left to the exhaustive unit property
# `test_prop_check_method_reply_defined` plus the seeded staged cases in
# test_egress.py.


@settings(max_examples=120, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(connect_reply=st.binary(max_size=40))
def test_fuzz_connect_reply_defined_exceptions_only(connect_reply: bytes) -> None:
    _run_case(method_reply=_GOOD_METHOD, connect_reply=connect_reply)


if __name__ == "__main__":  # pragma: no cover
    import sys

    sys.exit(pytest.main([__file__, "-v", "-s"]))
