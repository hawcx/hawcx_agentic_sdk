"""`hawcx bundle` — one measurable executable file per agent. WP-F.

The property under test is narrower than "it builds": HAAP's code-identity gate
compares the digest of the exec target against the signed class manifest, so a
bundle whose digest moves between builds of unchanged input would force a
manifest re-sign for nothing, and a bundle that is not self-contained would
measure bytes that are not the whole program.
"""

from __future__ import annotations

import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from hawcx_haap.bundle import BundleError, build_bundle, sha256_file

FIXTURES = Path(__file__).parent / "fixtures"
GOLDEN_SRC = FIXTURES / "golden_agent"


def _cli(*args, cwd=None):
    return subprocess.run(
        [sys.executable, "-m", "hawcx_haap.cli", *args],
        capture_output=True, text=True, cwd=cwd,
    )


def _tiny_project(root: Path, body: str = "print('hi')\n") -> Path:
    proj = root / "tiny"
    proj.mkdir()
    (proj / "__main__.py").write_text(body, encoding="utf-8")
    return proj


# ── shape of the artifact ────────────────────────────────────────────────────

def test_bundle_is_a_zip_with_a_shebang_and_runs(tmp_path):
    proj = _tiny_project(tmp_path)
    out = tmp_path / "tiny.pyz"
    digest = build_bundle(proj, out)

    assert digest.startswith("sha256:") and len(digest) == 7 + 64
    assert digest == sha256_file(out), "the printed digest must be of the file on disk"

    head = out.read_bytes()[:32]
    assert head.startswith(b"#!/usr/bin/env python3\n"), head
    assert zipfile.is_zipfile(out)

    r = subprocess.run([sys.executable, str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "hi"


def test_bundle_is_executable_on_unix(tmp_path):
    if sys.platform == "win32":
        pytest.skip("no POSIX mode bits")
    proj = _tiny_project(tmp_path)
    out = tmp_path / "tiny.pyz"
    build_bundle(proj, out)
    # The supervisor execs this path directly. Without +x that exec fails with
    # EACCES, which reads as a permissions outage rather than a build bug.
    assert os.stat(out).st_mode & 0o111, oct(os.stat(out).st_mode)


# ── the digest is the whole point ────────────────────────────────────────────

def test_digest_is_stable_across_rebuilds(tmp_path):
    """Two consecutive builds of unchanged input, same machine, same digest.

    Not a nicety: the digest is pasted into a signed class manifest. If it
    drifted on rebuild, every no-op rebuild would need an org-admin re-sign,
    and "is this the deployed version?" would stop being answerable.

    Full cross-machine reproducibility is NOT claimed and NOT tested — pip
    resolves per-platform wheels and zip stores local-time stamps. Roadmap.
    """
    proj = _tiny_project(tmp_path)
    first = build_bundle(proj, tmp_path / "a.pyz")
    second = build_bundle(proj, tmp_path / "b.pyz")
    assert first == second
    assert (tmp_path / "a.pyz").read_bytes() == (tmp_path / "b.pyz").read_bytes()


def test_digest_is_stable_with_a_generated_entry_point(tmp_path):
    """The --main path used to be the one that drifted.

    `zipapp.create_archive(main=...)` synthesises __main__.py with `writestr`,
    which stamps it with time.localtime(). One member's timestamp moving is
    enough to move the digest, and it only shows up if you rebuild in a
    different second — so this test exists rather than a manual check.
    """
    proj = tmp_path / "pkgproj"
    (proj / "myagent").mkdir(parents=True)
    (proj / "myagent" / "__init__.py").write_text("def run():\n    print('ran')\n")
    first = build_bundle(proj, tmp_path / "a.pyz", main="myagent:run")
    second = build_bundle(proj, tmp_path / "b.pyz", main="myagent:run")
    assert first == second

    r = subprocess.run([sys.executable, str(tmp_path / "a.pyz")], capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.strip() == "ran", r.stderr


def test_changed_source_changes_the_digest(tmp_path):
    """The converse: normalising mtimes must not have flattened away content."""
    proj = _tiny_project(tmp_path)
    before = build_bundle(proj, tmp_path / "a.pyz")
    (proj / "__main__.py").write_text("print('ho')\n", encoding="utf-8")
    after = build_bundle(proj, tmp_path / "b.pyz")
    assert before != after


# ── refusals ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("ext", [".so", ".pyd", ".dylib"])
def test_native_extension_is_refused_by_name(tmp_path, ext):
    proj = _tiny_project(tmp_path)
    (proj / "fastthing").mkdir()
    (proj / "fastthing" / "__init__.py").write_text("")
    (proj / "fastthing" / f"_core.cpython-312-x86_64-linux-gnu{ext}").write_bytes(b"\x7fELF")

    with pytest.raises(BundleError) as ei:
        build_bundle(proj, tmp_path / "out.pyz")

    msg = str(ei.value)
    # Actionable means: which package, and what to do instead.
    assert "fastthing" in msg
    assert "PyInstaller" in msg
    assert not (tmp_path / "out.pyz").exists(), "a refused build must leave no artifact"


def test_refusal_names_every_offending_package(tmp_path):
    proj = _tiny_project(tmp_path)
    for pkg in ("alpha", "bravo"):
        (proj / pkg).mkdir()
        (proj / pkg / "_ext.so").write_bytes(b"\x7fELF")
    with pytest.raises(BundleError) as ei:
        build_bundle(proj, tmp_path / "out.pyz")
    # Fixing one and rediscovering the next is the slowest possible loop.
    assert "alpha" in str(ei.value) and "bravo" in str(ei.value)


def test_missing_entry_point_is_refused(tmp_path):
    proj = tmp_path / "noentry"
    (proj / "mod").mkdir(parents=True)
    (proj / "mod" / "__init__.py").write_text("")
    with pytest.raises(BundleError, match="__main__.py"):
        build_bundle(proj, tmp_path / "out.pyz")


def test_bad_main_spec_is_refused(tmp_path):
    proj = tmp_path / "p"
    (proj / "m").mkdir(parents=True)
    (proj / "m" / "__init__.py").write_text("")
    with pytest.raises(BundleError, match="package.module:function"):
        build_bundle(proj, tmp_path / "out.pyz", main="just_a_module")


def test_source_must_be_a_directory(tmp_path):
    f = tmp_path / "agent.py"
    f.write_text("print(1)")
    with pytest.raises(BundleError, match="not a directory"):
        build_bundle(f, tmp_path / "out.pyz")


# ── CLI ──────────────────────────────────────────────────────────────────────

def test_cli_prints_the_digest_on_stdout(tmp_path):
    proj = _tiny_project(tmp_path)
    out = tmp_path / "t.pyz"
    r = _cli("bundle", str(proj), "-o", str(out))
    assert r.returncode == 0, r.stderr
    # stdout is exactly the digest so `hawcx bundle ... | ...` is usable; the
    # advisory about allowed_workload_selectors goes to stderr.
    assert r.stdout.strip() == sha256_file(out)
    assert "allowed_workload_selectors" in r.stderr


def test_cli_refuses_to_clobber(tmp_path):
    proj = _tiny_project(tmp_path)
    out = tmp_path / "t.pyz"
    assert _cli("bundle", str(proj), "-o", str(out)).returncode == 0
    out.write_bytes(b"a digest someone already put in a manifest")
    r = _cli("bundle", str(proj), "-o", str(out))
    assert r.returncode == 1 and "--force" in r.stderr
    assert out.read_bytes() == b"a digest someone already put in a manifest"
    assert _cli("bundle", str(proj), "-o", str(out), "--force").returncode == 0
    assert zipfile.is_zipfile(out)


def test_cli_default_output_name(tmp_path):
    proj = _tiny_project(tmp_path)
    r = _cli("bundle", str(proj), cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "tiny.pyz").is_file()


def test_cli_help_states_that_node_is_not_available():
    """The Python/Node asymmetry is real (node/package.json has no `bin`).
    Saying so in --help is the difference between a deferral and a surprise."""
    r = _cli("bundle", "--help")
    assert r.returncode == 0
    assert "Node bundling is not yet available" in r.stdout

    top = _cli("--help")
    assert "Node bundling is not yet available" in top.stdout


# ── the golden ───────────────────────────────────────────────────────────────

def test_golden_bundle_reaches_a_mock_assembler(tmp_path, mock_assembler, mock_assembler_endpoint):
    """Bundle a real agent, run the ONE file, and watch it complete a tool call.

    The SDK is vendored into the project tree (what `pip install --target`
    would produce for a `hawcx-haap` requirement, minus the network), and the
    bundle runs under `-S` so site-packages is off sys.path. If the archive
    were not self-contained, the import fails and this test cannot reach the
    socket at all.
    """
    import shutil

    import hawcx_haap

    proj = tmp_path / "golden_agent"
    shutil.copytree(GOLDEN_SRC, proj)
    shutil.copytree(
        Path(hawcx_haap.__file__).parent,
        proj / "hawcx_haap",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )

    out = tmp_path / "acme-doc-gen.pyz"
    digest = build_bundle(proj, out)
    assert digest == build_bundle(proj, tmp_path / "again.pyz"), "golden digest must be stable"

    env = {**os.environ, "HAWCX_ASSEMBLER_ENDPOINT": mock_assembler_endpoint}
    env.pop("PYTHONPATH", None)
    r = subprocess.run(
        [sys.executable, "-S", str(out)],
        capture_output=True, text=True, env=env, timeout=60,
    )
    assert r.returncode == 0, f"stdout={r.stdout!r} stderr={r.stderr!r}"
    assert "GOLDEN-OK status=200 body=GOLDEN-OK" in r.stdout
    assert str(out) in r.stdout, f"SDK was imported from outside the bundle: {r.stdout!r}"

    # The Assembler saw a real Profile E call, not just a process that started.
    assert mock_assembler.received_request is not None
    assert mock_assembler.received_request["tool"] == "acme.doc.generate"


# -- the entry point's exit code -------------------------------------------

def _main_project(root: Path, ret: str) -> Path:
    """A project whose `--main` entry function returns `ret`."""
    proj = root / "app"
    (proj / "pkg").mkdir(parents=True)
    (proj / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (proj / "pkg" / "run.py").write_text(
        "def main():\n    return " + ret + "\n", encoding="utf-8"
    )
    return proj


def test_main_entry_propagates_a_failing_exit_code(tmp_path):
    """A bundled agent that fails MUST NOT exit 0.

    The generated `__main__.py` used to call the entry point and throw its
    return value away, so a function returning 2 produced exit 0. Everything
    that reads exit status -- a supervisor deciding whether the workload it
    just spawned is healthy, CI, a shell `&&` -- was told a failed run
    succeeded. This is the regression test for that.
    """
    proj = _main_project(tmp_path, "2")
    out = tmp_path / "app.pyz"
    build_bundle(proj, out, main="pkg.run:main")

    r = subprocess.run([sys.executable, str(out)], capture_output=True, text=True)
    assert r.returncode == 2, (
        "a --main entry returning 2 must exit 2, not "
        f"{r.returncode} -- exit status is how a supervisor learns the agent failed"
    )


def test_main_entry_returning_none_is_still_a_clean_zero(tmp_path):
    """Positive control: the fix must not turn every success into a failure."""
    proj = _main_project(tmp_path, "None")
    out = tmp_path / "app.pyz"
    build_bundle(proj, out, main="pkg.run:main")

    r = subprocess.run([sys.executable, str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
