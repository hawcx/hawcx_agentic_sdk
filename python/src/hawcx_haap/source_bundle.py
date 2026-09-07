"""Bounded offline ZIP-to-zipapp packaging for CAA-owned build jobs.

Uploaded files are data: never import them, resolve dependencies, or run hooks.
The caller supplies private regular input/output paths and a trusted interpreter.
This is separate from the trusted-local ``bundle`` command, which may run pip.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import keyword
import os
import re
import stat
import struct
import sys
import zipapp
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path

from .bundle import _MAIN_TEMPLATE, NATIVE_SUFFIXES, BundleError

MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 1024
SDK_VERSION = "0.1.9"  # checked against pyproject.toml in test_source_bundle
PYTHON_VERSION = "3.10"  # minimum syntax/runtime version, not builder-host version
SDK_FILES = (
    "__init__.py",
    "_binary.py",
    "agent.py",
    "auth_ipc.py",
    "egress.py",
    "errors.py",
    "ipc.py",
    "mcp_caller.py",
    "pipe_win.py",
)
_BUILD_RECORD = "_hawcx_build.json"
_STDLIB_NAMES = {n.casefold() for n in sys.stdlib_module_names}
_TEXT_SUFFIXES = {
    "",
    ".py",
    ".txt",
    ".md",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
    ".csv",
    ".ini",
    ".cfg",
}


@dataclass(frozen=True)
class SourceBundleResult:
    """Measured executable identity and trusted build provenance, not a signature."""

    workload_digest: str
    size_bytes: int
    sdk_version: str
    sdk_digest: str
    python_version: str = PYTHON_VERSION
    entrypoint: str = "__main__.py"


def _member_name(info: zipfile.ZipInfo) -> str:
    name = info.filename.rstrip("/") if info.is_dir() else info.filename
    parts = name.split("/")
    if (
        info.orig_filename != info.filename
        or not name
        or len(name.encode("utf-8")) > 240
        or any(p in ("", ".", "..") or not re.fullmatch(r"[A-Za-z0-9_.-]+", p) for p in parts)
    ):
        raise BundleError("source ZIP requires bounded relative paths without dot segments")
    mode = info.external_attr >> 16
    if stat.S_IFMT(mode) not in (0, stat.S_IFDIR if info.is_dir() else stat.S_IFREG):
        raise BundleError(
            "source ZIP accepts regular files/directories only; symlinks are forbidden"
        )
    if info.flag_bits & 1 or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        raise BundleError("encrypted or unsupported-compression source ZIP entry")
    top = parts[0].split(".")[0].casefold()
    if (
        top == "hawcx_haap"
        or top in _STDLIB_NAMES
        or any(p.casefold().endswith((".dist-info", ".egg-info")) for p in parts)
        or parts[0].casefold() == _BUILD_RECORD
    ):
        raise BundleError(
            "source ZIP cannot overwrite the trusted SDK or standard-library namespace"
        )
    return name


def _read_sources(source_zip: Path) -> dict[str, bytes]:
    if source_zip.suffix.lower() in (".pyc", ".pyo"):
        raise BundleError("bare .pyc is not a standalone executable; upload a Python source ZIP")
    # O_NOFOLLOW is defense in depth; CAA must own the parent directories.
    if source_zip.is_symlink():
        raise BundleError("source ZIP must not be a symlink")
    fd = os.open(
        source_zip, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise BundleError("source ZIP must be a regular file")
        raw = stream.read(MAX_SOURCE_BYTES + 1)
    if len(raw) > MAX_SOURCE_BYTES:
        raise BundleError("source ZIP exceeds 32 MiB")
    # Bound central-directory allocation BEFORE ZipFile creates one Python
    # object per member. This small source format does not need ZIP64/multidisk.
    end = raw.rfind(b"PK\x05\x06", max(0, len(raw) - 65557))
    if end < 0 or len(raw) - end < 22:
        raise BundleError("invalid source ZIP end record")
    disk, cd_disk, count, total, cd_size, cd_offset, comment = struct.unpack_from(
        "<4H2IH", raw, end + 4
    )
    if (
        disk
        or cd_disk
        or count != total
        or total > MAX_ENTRIES
        or cd_size > 1024 * 1024
        or cd_offset + cd_size != end
        or end + 22 + comment != len(raw)
    ):
        raise BundleError("source ZIP has oversized metadata or unsupported ZIP64/multidisk layout")
    sources: dict[str, bytes] = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_ENTRIES:
            raise BundleError("source ZIP exceeds 1024 entries")
        seen: dict[str, bool] = {}
        expanded = 0
        for info in entries:
            name = _member_name(info)
            key = name.casefold()
            if key in seen:
                raise BundleError("duplicate or case-colliding source ZIP entry")
            seen[key] = info.is_dir()
            if info.is_dir():
                if info.file_size:
                    raise BundleError("source ZIP directory contains data")
                continue
            suffix = Path(name).suffix.lower()
            if suffix in NATIVE_SUFFIXES or suffix in (".pyc", ".pyo"):
                raise BundleError(
                    "native extensions and bytecode are unsupported; upload pure Python source"
                )
            if suffix not in _TEXT_SUFFIXES:
                raise BundleError(
                    "unsupported source resource; only Python and UTF-8 text data are accepted"
                )
            expanded += info.file_size
            if info.file_size > MAX_MEMBER_BYTES or expanded > MAX_SOURCE_BYTES:
                raise BundleError(
                    "expanded source ZIP exceeds member (8 MiB) or total (32 MiB) limit"
                )
            with archive.open(info) as member:
                data = member.read(MAX_MEMBER_BYTES + 1)
            if len(data) != info.file_size or len(data) > MAX_MEMBER_BYTES:
                raise BundleError("expanded source ZIP member size mismatch")
            try:
                text = data.decode("utf-8")
                if "\x00" in text:
                    raise BundleError("source ZIP text must not contain NUL bytes")
            except UnicodeError as exc:
                raise BundleError("source ZIP requires UTF-8 Python/text files") from exc
            sources[name] = data
        for name in seen:
            parts = name.split("/")
            if any(seen.get("/".join(parts[:i])) is False for i in range(1, len(parts))):
                raise BundleError("source ZIP path is both file and directory")
    return sources


def _entrypoint(sources: dict[str, bytes], main: str | None) -> None:
    if main is None:
        if "__main__.py" not in sources:
            raise BundleError("source ZIP needs __main__.py or --main package.module:function")
        return
    module, sep, function = main.partition(":")
    if (
        len(main) > 240
        or not sep
        or not module
        or not function
        or "." in function
        or any(
            not p.isidentifier() or keyword.iskeyword(p)
            for p in (*module.split("."), *function.split("."))
        )
    ):
        raise BundleError("--main requires package.module:function with valid Python identifiers")
    if "__main__.py" in sources:
        raise BundleError("choose one entry point: __main__.py or --main")
    path = module.replace(".", "/")
    if path + ".py" not in sources and path + "/__init__.py" not in sources:
        raise BundleError("--main module must be included in the uploaded source ZIP")
    source_name = path + ".py" if path + ".py" in sources else path + "/__init__.py"
    try:
        tree = ast.parse(sources[source_name], feature_version=(3, 10))
    except (SyntaxError, ValueError, RecursionError) as exc:
        raise BundleError("--main module must use supported Python 3.10 syntax") from exc
    candidate = next(
        (n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == function), None
    )
    if (
        candidate is None
        or candidate.decorator_list
        or len(candidate.args.posonlyargs + candidate.args.args) > len(candidate.args.defaults)
        or any(default is None for default in candidate.args.kw_defaults)
    ):
        raise BundleError(
            "--main must name an undecorated top-level function callable with no arguments"
        )
    sources["__main__.py"] = _MAIN_TEMPLATE.format(module=module, fn=function).encode("utf-8")


def _check_sources(sources: dict[str, bytes]) -> None:
    local_modules = {name.split("/")[0].removesuffix(".py") for name in sources}
    allowed = sys.stdlib_module_names | local_modules | {"hawcx_haap"}
    for name, data in sources.items():
        if not name.endswith(".py"):
            continue
        try:
            tree = ast.parse(data, filename=name, feature_version=(3, 10))
        except (SyntaxError, ValueError, RecursionError) as exc:
            raise BundleError(f"{name}: source must use supported Python 3.10 syntax") from exc
        for node in ast.walk(tree):
            imports = (
                [alias.name for alias in node.names]
                if isinstance(node, ast.Import)
                else [node.module]
                if isinstance(node, ast.ImportFrom) and not node.level
                else []
            )
            for module in imports:
                if (
                    module
                    and module.startswith("hawcx_haap.")
                    and module.removeprefix("hawcx_haap.") + ".py" not in SDK_FILES
                ):
                    raise BundleError(
                        f"{name}: SDK module {module!r} is outside the offline runtime closure"
                    )
                if module and module.split(".")[0] not in allowed:
                    raise BundleError(
                        f"{name}: dependency {module!r} is not vendored. "
                        "Offline builds never run pip. "
                        "Upload its supported pure-Python sources "
                        "or use a prebuilt compatible executable."
                    )


def _runtime_sources() -> tuple[dict[str, bytes], str]:
    root = Path(__file__).parent
    files = {f"hawcx_haap/{name}": (root / name).read_bytes() for name in SDK_FILES}
    files[f"hawcx_haap-{SDK_VERSION}.dist-info/METADATA"] = (
        f"Metadata-Version: 2.1\nName: hawcx-haap\nVersion: {SDK_VERSION}\n"
    ).encode("ascii")
    digest = hashlib.sha256()
    # Unambiguous source-closure hash: sorted UTF-8 names, u32-BE name length,
    # name, u64-BE content length, content. Only build provenance uses this.
    for name, data in sorted(files.items()):
        encoded = name.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big") + encoded)
        digest.update(len(data).to_bytes(8, "big") + data)
    return files, digest.hexdigest()


def build_source_bundle(
    source_zip: Path, output: Path, *, main: str | None = None
) -> SourceBundleResult:
    """Package a source ZIP without execution or network; refuse output overwrite.

    CAA owns quotas, worker isolation and authoritative metadata finalization.
    This function does not establish arbitrary application/HAAP compatibility.
    Static import checks reject known missing dependencies; dynamic imports and
    application behavior still require the runtime acceptance gate.
    """
    try:
        sources = _read_sources(Path(source_zip))
        _entrypoint(sources, main)
        _check_sources(sources)
        runtime, sdk_digest = _runtime_sources()
        sources.update(runtime)
        sources[_BUILD_RECORD] = json.dumps(
            {
                "sdk_version": SDK_VERSION,
                "sdk_digest": sdk_digest,
                "python_version": PYTHON_VERSION,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        zipped = io.BytesIO()
        with zipfile.ZipFile(zipped, "w", compression=zipfile.ZIP_STORED) as archive:
            for name, data in sorted(sources.items()):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, data)
        zipped.seek(0)
        executable = io.BytesIO()
        zipapp.create_archive(zipped, target=executable, interpreter="/usr/bin/env python3")
        raw = executable.getvalue()
        # Exclusive creation. On any failed write no completed output survives.
        target = Path(output).open("xb")
        try:
            with target:
                target.write(raw)
                target.flush()
                os.fsync(target.fileno())
                os.chmod(output, 0o755)
        except BaseException:
            Path(output).unlink(missing_ok=True)
            raise
        return SourceBundleResult(
            f"sha256:{hashlib.sha256(raw).hexdigest()}", len(raw), SDK_VERSION, sdk_digest
        )
    except BundleError:
        raise
    except (OSError, ValueError, zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError) as exc:
        raise BundleError(f"source-only build refused: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_zip", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--main")
    args = parser.parse_args(argv)
    try:
        result = build_source_bundle(args.source_zip, args.output, main=args.main)
    except BundleError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(asdict(result), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
