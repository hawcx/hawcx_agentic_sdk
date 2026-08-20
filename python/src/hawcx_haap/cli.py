"""``hawcx`` CLI. Auto-wrap plan U1 (``wrap``) and U2 (``validate``).

``submit`` is deliberately absent rather than stubbed — see :func:`main`.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

from .submit import SubmitError, resolve_credentials, submit_template
from .template import TemplateError, load_template
from .wrap import GenerationError, generate_module

_PROG = "hawcx"


def _read(path: str) -> tuple[str, str]:
    if path == "-":
        return sys.stdin.read(), "<stdin>"
    p = pathlib.Path(path)
    if not p.is_file():
        raise TemplateError(f"{path}: no such file")
    return p.read_text(encoding="utf-8"), str(p)


def _cmd_validate(args: argparse.Namespace) -> int:
    text, hint = _read(args.template)
    try:
        load_template(text, path_hint=hint)
    except TemplateError as e:
        if e.errors:
            # Every error, not just the first — a developer fixing one code per
            # round-trip is the slowest possible way to land a valid template.
            print(f"{hint}: INVALID — {len(e.errors)} error(s)", file=sys.stderr)
            for code, path in e.errors:
                print(f"  {code:28} {path}", file=sys.stderr)
            if any(c == "E_AUTHORITY_CLAIM" for c, _ in e.errors):
                print(
                    "\n  A template is a DESCRIPTION. Authority attaches at publish/assign\n"
                    "  and is enforced by HAAP. Remove the authority-claiming key — it is\n"
                    "  rejected rather than stripped, so that a claim can never be quietly\n"
                    "  turned into a valid submission.",
                    file=sys.stderr,
                )
        else:
            print(f"{e}", file=sys.stderr)
        return 1
    print(f"{hint}: OK")
    return 0


def _cmd_wrap(args: argparse.Namespace) -> int:
    text, hint = _read(args.template)
    try:
        doc = load_template(text, path_hint=hint)
        source = generate_module(doc, source_path=hint, stamp_time=args.stamp_time)
    except (TemplateError, GenerationError) as e:
        print(f"{e}", file=sys.stderr)
        return 1

    if args.output in (None, "-"):
        sys.stdout.write(source)
        return 0

    out = pathlib.Path(args.output)
    if out.exists() and not args.force:
        # Generated output is a file the developer may have (wrongly) edited.
        # Refuse rather than silently discarding their work; --force is the
        # explicit "yes, regenerate" signal.
        print(f"{out}: exists — pass --force to overwrite", file=sys.stderr)
        return 1
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(source, encoding="utf-8")
    n = len(doc["tools"])
    print(f"{out}: wrote {n} tool wrapper(s) from {hint}")
    return 0


def _cmd_submit(args: argparse.Namespace) -> int:
    text, hint = _read(args.template)
    try:
        # Validate LOCALLY first. The console revalidates — it must, since it is
        # reachable without this CLI — but failing here turns a network
        # round-trip and a 400 into an immediate, offline error listing every
        # problem at once.
        doc = load_template(text, path_hint=hint)
    except TemplateError as e:
        print(f"{hint}: INVALID — not submitted", file=sys.stderr)
        for code, path in e.errors:
            print(f"  {code:28} {path}", file=sys.stderr)
        if not e.errors:
            print(f"  {e}", file=sys.stderr)
        return 1

    try:
        console_url, api_key = resolve_credentials(args.org)
        result = submit_template(
            doc,
            console_url=console_url,
            api_key=api_key,
            source=args.source,
            timeout=args.timeout,
        )
    except SubmitError as e:
        print(f"submit failed: {e}", file=sys.stderr)
        for err in e.errors:
            print(f"  {err.get('code', '?'):28} {err.get('path', '?')}", file=sys.stderr)
        return 1

    print(
        f"submitted {result.get('name')} v{result.get('version')} "
        f"({result.get('toolCount')} tool(s)) — status {result.get('status')}, "
        f"id {result.get('id')}"
    )
    # `--org` selected the CREDENTIAL; the console derives the destination org
    # from the key itself. Saying so on success makes a wrong-key submission
    # visible instead of silent.
    print(
        f"  via {console_url} using the API key configured for {args.org!r}; "
        "the destination org is the one bound to that key.",
        file=sys.stderr,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=_PROG,
        description="Hawcx HAAP agent tooling: validate a hawcx/agent-template/v1 "
                    "and generate tool wrappers from it.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    v = sub.add_parser("validate", help="validate a hawcx/agent-template/v1 document")
    v.add_argument("template", help="path to the template YAML/JSON, or - for stdin")
    v.set_defaults(func=_cmd_validate)

    w = sub.add_parser("wrap", help="generate HAAP tool wrappers from a template")
    w.add_argument("template", help="path to the template YAML/JSON, or - for stdin")
    w.add_argument("-o", "--output", help="write to this path (default: stdout)")
    w.add_argument("--force", action="store_true", help="overwrite an existing output file")
    w.add_argument(
        "--stamp-time", action="store_true",
        help="embed a generation timestamp (off by default so regeneration is "
             "byte-identical and CI shows no spurious diff)",
    )
    w.set_defaults(func=_cmd_wrap)

    s_ = sub.add_parser(
        "submit",
        help="submit a template to the Admin Console as a draft",
        description=(
            "Validate a template locally, then POST it to the console's "
            "/api/agent-templates endpoint. --org selects WHICH API KEY to use; the "
            "destination org is derived server-side from that key and cannot be set "
            "by this client."
        ),
    )
    s_.add_argument("template", help="path to the template YAML/JSON, or - for stdin")
    s_.add_argument(
        "--org", required=True,
        help="org name, used to pick HAWCX_API_KEY_<ORG> / HAWCX_CONSOLE_URL_<ORG> "
             "(falling back to the unsuffixed variables)",
    )
    s_.add_argument("--source", default="cli", help="provenance string recorded on the draft")
    s_.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds")
    s_.set_defaults(func=_cmd_submit)
    return p


def main(argv: list[str] | None = None) -> int:
    """Entry point for `hawcx validate` / `hawcx wrap` / `hawcx submit`."""
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except TemplateError as e:
        print(f"{e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
