"""``hawcx submit`` — push a validated agent template to the Admin Console.

Auto-wrap plan U2.

TRANSPORT: ``POST /api/agent-templates`` WITH AN API KEY
-------------------------------------------------------
Not the console's tRPC endpoint, and not for want of trying — two independent
walls make it unreachable from a CLI:

* ``/api/trpc/*`` mutations are refused by the console's same-origin guard,
  which requires an ``Origin``/``Referer`` matching the console. A CLI has
  neither, and forging one would mean attacking the console's own CSRF
  protection.
* The console's ``requireRole`` refuses API-key sessions outright, so a
  role-gated procedure is unreachable by any machine client by construction.

So the console grew a REST route that accepts API-key auth only (and refuses
cookie sessions deliberately — it sits outside the CSRF guard).

``--org`` IS A CLIENT-SIDE CREDENTIAL SELECTOR, NOT A DESTINATION
-----------------------------------------------------------------
Worth being blunt about, because the flag name invites the opposite reading: the
org written to is derived SERVER-SIDE from the API key's own row. ``--org`` picks
which key to send. It is never transmitted, so it cannot be used to write into
another tenant — and if the wrong key is configured for a name, the submission
lands in that key's org, not the one you typed. The CLI prints the org it
believes it used so that mistake is visible rather than silent.

Stdlib only: ``hawcx-haap`` ships ``dependencies = []`` and this must not be the
thing that adds ``requests``.
"""

from __future__ import annotations

import ipaddress
import json
import math
import os
import socket
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

__all__ = ["SubmitError", "resolve_credentials", "submit_template", "DEFAULT_TIMEOUT_SECS"]

DEFAULT_TIMEOUT_SECS = 30
_PATH = "/api/agent-templates"
_LOOPBACK_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1"})
_CLOUD_METADATA_HOSTS: frozenset[str] = frozenset(
    {"metadata.google.internal", "metadata.goog", "instance-data"}
)
_IDNA_ALT_DOTS: tuple[str, ...] = ("\u3002", "\uff0e", "\uff61")
_REDIRECT_CODES: frozenset[int] = frozenset({301, 302, 303, 307, 308})
_STDLIB_URLOPEN = urllib.request.urlopen
urlopen = _STDLIB_URLOPEN


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Fail-closed redirect handler: never follow 30x or forward Bearer credentials."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            f"refusing HTTP {code} redirect from console endpoint",
            headers,
            fp,
        )

    def http_error_302(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
    ) -> Any:
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            f"refusing HTTP {code} redirect from console endpoint",
            headers,
            fp,
        )

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler())


def _normalize_submit_errors(raw_errors: Any) -> list[dict[str, str]]:
    if not isinstance(raw_errors, list):
        return []
    out: list[dict[str, str]] = []
    for item in raw_errors:
        if isinstance(item, dict):
            out.append(
                {
                    k: v if isinstance(v, str) else str(v)
                    for k, v in item.items()
                    if isinstance(k, str) and v is not None
                }
            )
    return out


class SubmitError(Exception):
    """A submission could not be made or was refused.

    ``errors`` carries the canonical ``E_*`` codes when the console rejected the
    document, so the CLI can print the same codes ``hawcx validate`` would.
    """

    def __init__(self, message: str, *, errors: list[dict[str, str]] | None = None,
                 status: int | None = None):
        super().__init__(message)
        self.errors = _normalize_submit_errors(errors)
        self.status = status


class _SubmitTypeError(SubmitError, TypeError):
    """Invalid submit argument type (subclasses both SubmitError and TypeError)."""


def _env_for_org(base: str, org: str) -> str | None:
    """``HAWCX_API_KEY_UKG`` in preference to ``HAWCX_API_KEY``.

    Per-org variables make `--org` meaningful without inventing a config-file
    format the fleet does not have yet. `-` is mapped to `_` because an env var
    cannot contain a hyphen and org slugs routinely do.
    """
    specific = f"{base}_{org.upper().replace('-', '_')}"
    return os.environ.get(specific) or os.environ.get(base)


def resolve_credentials(org: str) -> tuple[str, str]:
    """Return ``(console_url, api_key)`` for *org*, or raise with what to set."""
    url = _env_for_org("HAWCX_CONSOLE_URL", org)
    key = _env_for_org("HAWCX_API_KEY", org)
    missing = []
    if not url:
        missing.append(f"HAWCX_CONSOLE_URL_{org.upper().replace('-', '_')} (or HAWCX_CONSOLE_URL)")
    if not key:
        missing.append(f"HAWCX_API_KEY_{org.upper().replace('-', '_')} (or HAWCX_API_KEY)")
    if missing:
        raise SubmitError(
            "missing credentials for org "
            f"{org!r}: set {', '.join(missing)}. The API key needs the "
            "`org.agent_templates.push` permission — an API key is authorized by its "
            "explicit permission list, never by the creating user's role."
        )
    assert url is not None and key is not None
    if not key.startswith("hx_"):
        # Fail before the request: the console rejects a non-`hx_` bearer with a
        # 401 that looks like an auth outage rather than a misconfigured value.
        raise SubmitError(
            "the API key does not look like a Hawcx key (expected an `hx_` prefix). "
            "A session JWT or an OAuth token will be refused by the console."
        )
    return url.rstrip("/"), key


def _validate_console_url(console_url: Any) -> str:
    if not isinstance(console_url, str):
        raise _SubmitTypeError(f"console_url must be str; got {type(console_url).__name__}")
    # Check ASCII/Unicode control chars and surrounding/embedded whitespace BEFORE .strip() (I1).
    if (
        not console_url
        or console_url != console_url.strip()
        or any(
            ch.isspace()
            or ord(ch) < 0x20
            or ord(ch) == 0x7F
            or unicodedata.category(ch).startswith("C")
            for ch in console_url
        )
    ):
        raise SubmitError(
            "invalid console_url: must not be empty or contain whitespace or control characters"
        )
    if any(ch in console_url for ch in ("@", "\\", "?", "#")):
        raise SubmitError(
            "invalid console_url: credentials, backslashes, query strings, and fragments "
            "are forbidden"
        )
    try:
        parts = urllib.parse.urlsplit(console_url)
    except ValueError as e:
        raise SubmitError(f"invalid console_url ({console_url}): {e}") from e
    if parts.scheme not in ("https", "http") or not console_url.startswith(
        ("https://", "http://")
    ):
        raise SubmitError(
            f"refusing to send an API key over a non-HTTPS URL ({console_url}). "
            "Use https://, or http://localhost for a dev console."
        )
    host = parts.hostname
    if (
        not host
        or host.startswith(".")
        or host.endswith(".")
        or ".." in host
        or any(dot in host for dot in _IDNA_ALT_DOTS)
    ):
        raise SubmitError(f"invalid hostname in console_url ({console_url})")
    host_lower = host.lower()
    if host_lower in _CLOUD_METADATA_HOSTS:
        raise SubmitError(f"forbidden cloud metadata hostname in console_url ({console_url})")
    is_bracketed = "[" in parts.netloc or "]" in parts.netloc
    try:
        parsed_ip = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        parsed_ip = None
    if is_bracketed or ":" in host:
        if not isinstance(parsed_ip, ipaddress.IPv6Address):
            raise SubmitError(f"invalid IPv6 literal in console_url ({console_url})")
    if parsed_ip is not None:
        if "%" in host and not isinstance(parsed_ip, ipaddress.IPv6Address):
            raise SubmitError(f"invalid hostname in console_url ({console_url})")
        if parsed_ip.is_unspecified or parsed_ip.is_link_local:
            raise SubmitError(
                f"forbidden unspecified or link-local IP in console_url ({console_url})"
            )
        if isinstance(parsed_ip, ipaddress.IPv6Address):
            if (
                parsed_ip == ipaddress.IPv6Address("fd00:ec2::254")
                or parsed_ip.ipv4_mapped is not None
                or (
                    (int(parsed_ip) >> 32) == 0
                    and parsed_ip != ipaddress.IPv6Address("::1")
                )
            ):
                raise SubmitError(
                    f"forbidden metadata or IPv4-mapped/compatible IPv6 in console_url "
                    f"({console_url})"
                )
    else:
        if "%" in host:
            raise SubmitError(f"invalid hostname in console_url ({console_url})")
        # Per RFC 3696 §2, no valid DNS TLD is all-digits or 0x-prefixed; also guard
        # socket.inet_aton(host) to block decimal/hex/octal/shortened IPv4 IMDS literals.
        last_label = host_lower.rsplit(".", 1)[-1]
        if last_label.isdigit() or last_label.startswith("0x"):
            raise SubmitError(
                f"non-canonical or numeric IPv4 literal forbidden in console_url ({console_url})"
            )
        try:
            socket.inet_aton(host)
        except OSError:
            pass
        else:
            raise SubmitError(
                f"non-canonical or numeric IPv4 literal forbidden in console_url ({console_url})"
            )
    try:
        port = parts.port
    except ValueError as e:
        raise SubmitError(f"invalid port in console_url ({console_url}): {e}") from e
    if port == 0:
        raise SubmitError(f"invalid port 0 in console_url ({console_url})")
    if parts.path not in ("", "/"):
        raise SubmitError(
            f"invalid console_url ({console_url}): expected an origin without a non-root path"
        )
    if parts.scheme == "http" and host_lower not in _LOOPBACK_HOSTS:
        raise SubmitError(
            f"refusing to send an API key over a non-HTTPS URL ({console_url}). "
            "Use https://, or localhost for a dev console."
        )
    return console_url.rstrip("/")


def _validate_api_key(api_key: Any) -> str:
    if not isinstance(api_key, str):
        raise _SubmitTypeError(f"api_key must be str; got {type(api_key).__name__}")
    if (
        not api_key
        or api_key != api_key.strip()
        or any(
            ch.isspace()
            or ord(ch) < 0x20
            or ord(ch) == 0x7F
            or unicodedata.category(ch).startswith("C")
            for ch in api_key
        )
    ):
        raise SubmitError(
            "invalid api_key: must be a non-empty string without whitespace or control characters"
        )
    return api_key


def submit_template(
    document: dict[str, Any],
    *,
    console_url: str,
    api_key: str,
    source: str = "cli",
    timeout: int | float = DEFAULT_TIMEOUT_SECS,
) -> dict[str, Any]:
    """POST *document* and return the console's result dict."""
    if isinstance(timeout, bool) or not (type(timeout) is int or type(timeout) is float):
        raise TypeError(f"timeout must be int or float; got {type(timeout).__name__}")
    if math.isnan(timeout) or math.isinf(timeout) or timeout <= 0:
        raise ValueError(f"timeout must be a finite positive number; got {timeout!r}")

    clean_url = _validate_console_url(console_url)
    clean_key = _validate_api_key(api_key)

    body = json.dumps({"document": document, "source": source}).encode("utf-8")
    req = urllib.request.Request(
        clean_url + _PATH,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {clean_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            # Deliberately NOT sending an Origin header. The console's CSRF
            # guard does not apply to this route, and sending one would make a
            # CLI look like a browser to any future middleware that checks.
            "User-Agent": "hawcx-haap-cli",
        },
    )
    try:
        if urlopen is not _STDLIB_URLOPEN:
            resp_ctx = urlopen(req, timeout=timeout)
        elif urllib.request.urlopen is not _STDLIB_URLOPEN:
            resp_ctx = urllib.request.urlopen(req, timeout=timeout)
        else:
            resp_ctx = _NO_REDIRECT_OPENER.open(req, timeout=timeout)
        with resp_ctx as resp:
            status_code = getattr(resp, "status", 200)
            raw_bytes = resp.read()
        if not (
            type(status_code) is int
            and not isinstance(status_code, bool)
            and 200 <= status_code <= 299
        ):
            raise SubmitError(
                f"console returned unexpected HTTP {status_code}",
                status=status_code if type(status_code) is int else None,
            )
        try:
            payload = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise SubmitError(
                f"console returned malformed JSON on HTTP {status_code}",
                status=status_code,
            ) from e
        if not isinstance(payload, dict):
            raise SubmitError(
                f"console returned non-object JSON ({type(payload).__name__}) "
                f"on HTTP {status_code}",
                status=status_code,
            )
        if payload.get("error") is not None:
            raise SubmitError(
                str(payload.get("message") or payload["error"]),
                errors=_normalize_submit_errors(payload.get("errors")),
                status=status_code,
            )
        if ("decision" in payload and payload.get("decision") != "allow") or (
            payload.get("reject_code") is not None
        ):
            raise SubmitError(
                "console returned non-allow decision or non-null reject_code",
                errors=_normalize_submit_errors(payload.get("errors")),
                status=status_code,
            )
        return payload
    except urllib.error.HTTPError as e:
        if e.code in _REDIRECT_CODES:
            try:
                e.close()
            except Exception:
                pass
            raise SubmitError(
                f"refusing HTTP {e.code} redirect from console endpoint",
                status=e.code,
            ) from e
        raw = e.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            raise SubmitError(f"console returned HTTP {e.code}: {raw[:400]}", status=e.code) from e
        if not isinstance(payload, dict):
            raise SubmitError(f"console returned HTTP {e.code}: {raw[:400]}", status=e.code) from e
        msg = str(payload.get("message") or payload.get("error") or f"HTTP {e.code}")
        raise SubmitError(
            msg,
            errors=_normalize_submit_errors(payload.get("errors")),
            status=e.code,
        ) from e
    except urllib.error.URLError as e:
        raise SubmitError(f"could not reach the console at {clean_url}: {e.reason}") from e
