"""``hawcx`` CLI. Auto-wrap plan U1 (``wrap``) and U2 (``validate``).

``submit`` is deliberately absent rather than stubbed — see :func:`main`.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

from .template import TemplateError, load_template, validate_v1
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
    return p


def main(argv: list[str] | None = None) -> int:
    """Entry point.

    NOTE on `submit`: plan U2 pairs `validate` with `submit --org <org>`, which
    pushes a draft to the Admin Console (`templates.push`). That console endpoint
    does not exist yet (plan U3), so `submit` is NOT registered here. A subcommand
    that accepted the flags and failed at the network would look like an outage
    instead of an unbuilt feature; an unknown-subcommand error is honest.
    """
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except TemplateError as e:
        print(f"{e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
