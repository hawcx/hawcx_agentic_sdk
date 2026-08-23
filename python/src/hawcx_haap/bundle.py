"""``hawcx bundle`` -- pack an agent program into ONE measurable executable file.

WHY A SINGLE FILE, AND NOT A TARBALL
------------------------------------
HAAP's code-identity gate (ADR-0043) measures the bytes of the exact file the
supervisor ``exec``s and requires that digest to appear in the org-signed class
manifest's ``allowed_workload_selectors``. The supervisor's ``AgentConfig`` has
no args field -- it cannot pass a script path to an interpreter -- so the exec
target must BE the whole agent program. Configuring
``agent_bin = "/usr/local/bin/python"`` measures CPython and proves nothing
about the agent; this command produces the file that makes the measurement
mean something.

The stdlib ``zipapp`` module is the whole mechanism. A ``.pyz`` is a zip with a
``#!/usr/bin/env python3`` shebang and the executable bit -- one file, one
digest, directly executable.

NAMED RESIDUAL (do not claim otherwise): the interpreter named by the shebang
is NOT measured. It is the same trust class as the system libraries the agent
links. What IS measured is the entire agent program plus its vendored
dependencies, which is the property ADR-0043's honest-scope note asked for.

NATIVE EXTENSIONS ARE REFUSED, NOT WORKED AROUND
------------------------------------------------
A zipapp cannot portably carry a compiled extension module: CPython cannot
``dlopen`` a ``.so`` out of a zip, so any runtime that "supports" it does so by
silently unpacking to a temp directory -- which means the measured bytes are no
longer the bytes that execute. Refusing is the fail-closed answer; PyInstaller
is the documented escape hatch for agents that genuinely need native deps.

DETERMINISM SCOPE
-----------------
Two builds of the same input on one machine produce the same digest: staged
file mtimes are normalised to the zip epoch, byte-compilation is disabled, and
``zipapp`` walks the tree in sorted order. Full cross-machine reproducibility
is NOT claimed -- ``pip`` resolves wheels for the running interpreter and
platform, and zip timestamps are written in local time. That is roadmap.

Stdlib only: ``hawcx-haap`` ships ``dependencies = []`` and this must not be
the thing that adds a build tool.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import zipapp

__all__ = ["BundleError", "build_bundle", "NATIVE_SUFFIXES"]

# A file with one of these suffixes anywhere in the staged tree is a compiled
# extension module. `.so` also matches the versioned form
# (`_rust.cpython-312-x86_64-linux-gnu.so`) because `Path.suffix` is the last
# component only.
NATIVE_SUFFIXES = frozenset({".so", ".pyd", ".dylib"})

# 1980-01-03 00:00:00 UTC. The zip format cannot represent anything before
# 1980-01-01, and zipfile converts each mtime to LOCAL time before storing it --
# so the zip epoch itself raises `ValueError: ZIP does not support timestamps
# before 1980` anywhere west of UTC. Two days of slack clears the whole
# UTC-12..UTC+14 range. (That same local-time conversion is why the digest is
# stable per machine and not across machines in different timezones -- the
# documented v0 scope.)
_ZIP_EPOCH = 315532800 + 2 * 86400

_STAGE_IGNORE = shutil.ignore_patterns(
    "__pycache__", "*.pyc", "*.pyo", "*.pyz", ".git", ".hg", ".svn",
    ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "*.egg-info", "dist", "build",
)


class BundleError(Exception):
    """A bundle could not be built, or was refused."""


_MAIN_TEMPLATE = "# -*- coding: utf-8 -*-\nimport {module}\n{module}.{fn}()\n"


def _is_pycache(arcname: pathlib.PurePath) -> bool:
    return "__pycache__" in arcname.parts or arcname.suffix in (".pyc", ".pyo")


def _write_entry_point(staging: pathlib.Path, main: str) -> None:
    """Materialise ``__main__.py`` in the staging tree from a ``mod:fn`` spec.

    ``zipapp.create_archive(main=...)`` would synthesise this same file via
    ``writestr``, which stamps it with ``time.localtime()`` -- one member whose
    timestamp moves on every build, and with it the digest. Writing it as a
    real staged file puts it through the mtime normalisation with everything
    else.
    """
    module, sep, fn = main.partition(":")
    if not sep or not module or not fn:
        raise BundleError(
            f"--main {main!r}: expected 'package.module:function' "
            "(a callable taking no arguments)"
        )
    for part in (*module.split("."), *fn.split(".")):
        if not part.isidentifier():
            raise BundleError(f"--main {main!r}: {part!r} is not a valid Python identifier")
    target = staging / "__main__.py"
    if target.exists():
        raise BundleError(
            f"--main was given but {main.split(':')[0]}'s project already has a "
            "__main__.py. Pick one entry point: drop --main, or remove the file."
        )
    target.write_text(_MAIN_TEMPLATE.format(module=module, fn=fn), encoding="utf-8")


def _stage_dependencies(requirement: pathlib.Path, staging: pathlib.Path) -> None:
    """``pip install --target`` the requirements into the staging tree."""
    cmd = [
        sys.executable, "-m", "pip", "install",
        "--target", str(staging),
        "--requirement", str(requirement),
        # Bytecode embeds the source mtime, so a .pyc is a second, hidden
        # source of digest drift. The bundle ships source; CPython compiles at
        # first run into its own cache, outside the measured file.
        "--no-compile",
        "--upgrade",
        "--disable-pip-version-check",
        "--no-input",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except OSError as e:  # pragma: no cover - pip missing is an install fault
        raise BundleError(f"could not run pip to stage dependencies: {e}") from e
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-15:]
        raise BundleError(
            f"pip failed staging {requirement} (exit {proc.returncode}):\n  "
            + "\n  ".join(tail)
        )


def _refuse_native_extensions(staging: pathlib.Path) -> None:
    """Refuse the bundle if any staged file is a compiled extension module."""
    offenders: list[tuple[str, str]] = []
    for path in sorted(staging.rglob("*")):
        if path.is_file() and path.suffix.lower() in NATIVE_SUFFIXES:
            rel = path.relative_to(staging)
            # The top-level staged directory IS the distribution name for a
            # pip --target install, which is the name the developer has to act
            # on. For a loose file at the root, name the file.
            offenders.append((rel.parts[0], rel.as_posix()))
    if not offenders:
        return

    packages = sorted({pkg for pkg, _ in offenders})
    lines = [
        "refusing to bundle: native extension module(s) found in "
        f"{len(packages)} package(s) -- " + ", ".join(packages),
    ]
    for _pkg, rel in offenders[:10]:
        lines.append(f"  {rel}")
    if len(offenders) > 10:
        lines.append(f"  ... and {len(offenders) - 10} more")
    lines.append(
        "\nA zipapp cannot portably carry a compiled extension: CPython cannot "
        "import a\n"
        ".so/.pyd/.dylib from inside a zip, and any runtime that appears to "
        "manage it does\n"
        "so by unpacking to a temp directory -- at which point the bytes HAAP "
        "measured are\n"
        "no longer the bytes that execute, and the code-identity gate is "
        "measuring a lie.\n"
        "\n"
        "Options: (a) drop the dependency or replace it with a pure-Python "
        "one; or\n"
        "(b) build that agent with PyInstaller instead -- a one-file "
        "PyInstaller binary is\n"
        "also a single measurable exec target. `hawcx bundle` does not build "
        "the PyInstaller\n"
        "path; run PyInstaller yourself and hash the result."
    )
    raise BundleError("\n".join(lines))


def _normalize_mtimes(staging: pathlib.Path) -> None:
    """Flatten every staged mtime to the zip epoch.

    zipfile records each member's mtime, so freshly pip-installed files (whose
    mtime is `now`) would move the digest on every rebuild. This is the single
    reason two consecutive builds hash the same.
    """
    for path in staging.rglob("*"):
        os.utime(path, (_ZIP_EPOCH, _ZIP_EPOCH))
    os.utime(staging, (_ZIP_EPOCH, _ZIP_EPOCH))


def sha256_file(path: pathlib.Path) -> str:
    """``sha256:<hex>`` of *path* as it sits on disk."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


def build_bundle(
    source: pathlib.Path,
    output: pathlib.Path,
    *,
    main: str | None = None,
    requirement: pathlib.Path | None = None,
    interpreter: str = "/usr/bin/env python3",
) -> str:
    """Build *output* from the agent project at *source*; return its digest.

    Overwrites *output* unconditionally -- the clobber refusal lives in the CLI
    so that a caller who has already decided is not fought a second time.
    """
    source = source.resolve()
    if not source.is_dir():
        raise BundleError(f"{source}: not a directory (bundle takes an agent project directory)")
    if main is None and not (source / "__main__.py").is_file():
        raise BundleError(
            f"{source}: no __main__.py, and no --main given. A bundle must have one "
            "entry point: add a __main__.py, or pass --main 'package.module:function'."
        )

    with tempfile.TemporaryDirectory(prefix="hawcx-bundle-") as tmp:
        staging = pathlib.Path(tmp) / "app"
        shutil.copytree(source, staging, ignore=_STAGE_IGNORE)

        if main is not None:
            _write_entry_point(staging, main)

        if requirement is not None:
            if not requirement.is_file():
                raise BundleError(f"{requirement}: no such requirements file")
            _stage_dependencies(requirement, staging)

        # Before the archive exists: a refusal must cost the developer nothing
        # and leave no half-built artifact behind.
        _refuse_native_extensions(staging)
        _normalize_mtimes(staging)

        output.parent.mkdir(parents=True, exist_ok=True)
        try:
            # main=None deliberately: the entry point is already a staged file
            # (see _write_entry_point) so that it carries a normalised mtime.
            zipapp.create_archive(
                staging,
                target=output,
                interpreter=interpreter,
                main=None,
                filter=lambda arcname: not _is_pycache(arcname),
            )
        except zipapp.ZipAppError as e:
            raise BundleError(f"zipapp refused this project: {e}") from e

    return sha256_file(output)
