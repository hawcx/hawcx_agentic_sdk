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

import json
import os
import urllib.error
import urllib.request
from typing import Any

__all__ = ["SubmitError", "resolve_credentials", "submit_template", "DEFAULT_TIMEOUT_SECS"]

DEFAULT_TIMEOUT_SECS = 30
_PATH = "/api/agent-templates"


class SubmitError(Exception):
    """A submission could not be made or was refused.

    ``errors`` carries the canonical ``E_*`` codes when the console rejected the
    document, so the CLI can print the same codes ``hawcx validate`` would.
    """

    def __init__(self, message: str, *, errors: list[dict[str, str]] | None = None,
                 status: int | None = None):
        super().__init__(message)
        self.errors = errors or []
        self.status = status


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
    if not key.startswith("hx_"):
        # Fail before the request: the console rejects a non-`hx_` bearer with a
        # 401 that looks like an auth outage rather than a misconfigured value.
        raise SubmitError(
            "the API key does not look like a Hawcx key (expected an `hx_` prefix). "
            "A session JWT or an OAuth token will be refused by the console."
        )
    return url.rstrip("/"), key


def submit_template(
    document: dict[str, Any],
    *,
    console_url: str,
    api_key: str,
    source: str = "cli",
    timeout: int = DEFAULT_TIMEOUT_SECS,
) -> dict[str, Any]:
    """POST *document* and return the console's result dict."""
    if not console_url.startswith("https://"):
        # An API key in an Authorization header over cleartext HTTP is a
        # credential disclosure, not a config preference. localhost is exempt
        # because that is the dev-console case and never leaves the loopback.
        host = console_url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        if host not in ("localhost", "127.0.0.1", "::1"):
            raise SubmitError(
                f"refusing to send an API key over a non-HTTPS URL ({console_url}). "
                "Use https://, or localhost for a dev console."
            )

    body = json.dumps({"document": document, "source": source}).encode("utf-8")
    req = urllib.request.Request(
        console_url + _PATH,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            # Deliberately NOT sending an Origin header. The console's CSRF
            # guard does not apply to this route, and sending one would make a
            # CLI look like a browser to any future middleware that checks.
            "User-Agent": "hawcx-haap-cli",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            raise SubmitError(f"console returned HTTP {e.code}: {raw[:400]}", status=e.code) from e
        msg = payload.get("message") or payload.get("error") or f"HTTP {e.code}"
        raise SubmitError(msg, errors=payload.get("errors") or [], status=e.code) from e
    except urllib.error.URLError as e:
        raise SubmitError(f"could not reach the console at {console_url}: {e.reason}") from e
