"""``hawcx`` CLI. Auto-wrap plan U1 (``wrap``) and U2 (``validate``).

``submit`` is deliberately absent rather than stubbed — see :func:`main`.

``bundle`` (agent-delivery WP-F) is Python-only. Node bundling is not built:
``node/package.json`` has no ``bin`` and there is no Node CLI to hang it off,
so a half-built subcommand would advertise a capability that does not exist.
The asymmetry is stated in ``--help`` rather than papered over.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from .bundle import BundleError, build_bundle
from .extract import (
    ExtractError,
    build_template,
    extract_from_mcp_tools_list,
    extract_from_names,
)
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
        print(f"{hint}: INVALID -- not submitted", file=sys.stderr)
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
        f"({result.get('toolCount')} tool(s)) -- status {result.get('status')}, "
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


def _cmd_extract(args: argparse.Namespace) -> int:
    try:
        if args.names:
            report = extract_from_names(args.names, namespace=args.namespace)
        else:
            text, hint = _read(args.tools)
            try:
                payload = json.loads(text)
            except json.JSONDecodeError as e:
                print(f"{hint}: not valid JSON: {e}", file=sys.stderr)
                return 1
            report = extract_from_mcp_tools_list(payload, namespace=args.namespace)
        doc = build_template(
            report, name=args.name, version=args.version, framework=args.framework
        )
    except ExtractError as e:
        print(f"extract failed: {e}", file=sys.stderr)
        return 1

    print(json.dumps(doc, indent=2))

    # The report goes to STDERR so `hawcx extract ... > template.json` yields a
    # clean file while the human still sees what needs checking. Silencing it
    # would be the difference between a draft and something that looks finished.
    if report.refused:
        print("\nREFUSED -- add these by hand:", file=sys.stderr)
        for src_name, why in report.refused:
            print(f"  {src_name}: {why}", file=sys.stderr)
    if report.unknown_verbs:
        print(
            "\nNo recognised verb -- actions DEFAULTED to ['read'], check each: "
            + ", ".join(report.unknown_verbs),
            file=sys.stderr,
        )
    if report.normalized:
        print("\nRenamed to satisfy the id grammar:", file=sys.stderr)
        for src_name, new_id in report.normalized:
            print(f"  {src_name} -> {new_id}", file=sys.stderr)
    print(
        "\nThis is a DRAFT. `risk` is derived from the inferred action and is "
        "deliberately mild; endpoints are absent by design (they come from the org "
        "tool registry at runtime). Review, then `hawcx validate`.",
        file=sys.stderr,
    )
    return 0


def _cmd_bundle(args: argparse.Namespace) -> int:
    src = pathlib.Path(args.source)
    out = pathlib.Path(args.output) if args.output else pathlib.Path(f"{src.resolve().name}.pyz")

    if out.exists() and not args.force:
        # Same posture as `wrap`: the output is a file someone may have already
        # placed in a class manifest. Silently replacing it would change what
        # the digest on record refers to.
        print(f"{out}: exists -- pass --force to overwrite", file=sys.stderr)
        return 1

    req = pathlib.Path(args.requirement) if args.requirement else src / "requirements.txt"
    if not req.is_file():
        if args.requirement:
            print(f"{req}: no such requirements file", file=sys.stderr)
            return 1
        req = None  # type: ignore[assignment]

    try:
        digest = build_bundle(src, out, main=args.main, requirement=req)
    except BundleError as e:
        print(f"{e}", file=sys.stderr)
        return 1

    print(digest)
    print(
        f"  {out} ({out.stat().st_size} bytes)\n"
        "  Put that digest in the class manifest's `allowed_workload_selectors` and "
        "point\n  the supervisor's agent_bin at this file. The exec target IS the "
        "workload: the\n  code-identity gate measures these exact bytes, so a rebuild "
        "that changes them\n  needs a manifest update.",
        file=sys.stderr,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=_PROG,
        description="Hawcx HAAP agent tooling: validate a hawcx/agent-template/v1, "
                    "generate tool wrappers from it, and bundle a Python agent into "
                    "one measurable executable file.",
        epilog="Python only. Node bundling is not yet available (there is no Node CLI "
               "in this SDK); `hawcx bundle` covers Python agents.",
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

    e = sub.add_parser(
        "extract",
        help="draft a template from an existing agent's tool list",
        description=(
            "Infer tools[].{id, actions, risk} from an MCP tools/list response or a "
            "list of tool names. Endpoints, providers and constraints are NEVER "
            "inferred. Output is a DRAFT for review, printed to stdout; the "
            "what-to-check report goes to stderr."
        ),
    )
    src = e.add_mutually_exclusive_group(required=True)
    src.add_argument("--tools", help="path to an MCP tools/list JSON response, or - for stdin")
    src.add_argument("--names", nargs="+", help="bare tool names, space separated")
    e.add_argument(
        "--namespace", required=True,
        help="id prefix, e.g. `o365`. Required: the v1 id grammar is dotted and a "
             "bare name cannot satisfy it. Synthesising one would mint a HAAP tool "
             "identity out of nothing.",
    )
    e.add_argument("--name", required=True, help="template name (the agent's name)")
    e.add_argument("--version", default="0.1.0", help="template version")
    e.add_argument("--framework", default="langchain",
                   help="framework kind accepted by the v1 schema")
    e.set_defaults(func=_cmd_extract)

    b = sub.add_parser(
        "bundle",
        help="pack a Python agent project into one executable .pyz and print its sha256",
        description=(
            "Build a stdlib zipapp with a `#!/usr/bin/env python3` shebang: one file, "
            "one digest, directly executable. HAAP's code-identity gate measures the "
            "bytes of the file the supervisor execs and there is no way to pass it a "
            "script argument, so the exec target must BE the agent program. The printed "
            "sha256 is what an admin puts in the class manifest's "
            "`allowed_workload_selectors`.\n\n"
            "Dependencies are staged with `pip install --target` for the interpreter "
            "running this command, so build on the platform you deploy to. Native "
            "extension modules (.so/.pyd/.dylib) are REFUSED -- a zipapp cannot carry "
            "them without unpacking to a temp dir, which breaks the measurement; use "
            "PyInstaller for those agents.\n\n"
            "Python only. Node bundling is not yet available -- there is no Node CLI "
            "in this SDK (`node/package.json` has no `bin`), and a single-file .mjs "
            "entry is a later increment."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    b.add_argument("source", help="path to the agent project directory")
    b.add_argument("-o", "--output", help="output path (default: <dirname>.pyz in the cwd)")
    b.add_argument(
        "-m", "--main",
        help="entry point as 'package.module:function'. Omit when the project already "
             "has a __main__.py.",
    )
    b.add_argument(
        "-r", "--requirement",
        help="requirements file to vendor (default: <source>/requirements.txt when it "
             "exists; no dependency staging at all when it does not)",
    )
    b.add_argument("--force", action="store_true", help="overwrite an existing output file")
    b.set_defaults(func=_cmd_bundle)
    return p


def main(argv: list[str] | None = None) -> int:
    """Entry point for `hawcx validate` / `wrap` / `submit` / `extract` / `bundle`."""
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except TemplateError as e:
        print(f"{e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
