"""The remote source boundary must not inherit the local builder's pip/hooks."""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch

from hawcx_haap.bundle import BundleError
from hawcx_haap.source_bundle import (
    MAX_ENTRIES,
    MAX_MEMBER_BYTES,
    MAX_SOURCE_BYTES,
    SDK_VERSION,
    _runtime_sources,
    build_source_bundle,
    main,
)


class SourceBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def source(self, files=None):
        source = self.root / "source.zip"
        with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, value in (files or {"__main__.py": b"print('hello')\n"}).items():
                archive.writestr(name, value)
        return source

    def test_deterministic_executable_and_sdk_identity(self):
        source = self.source(
            {
                "__main__.py": b"import hawcx_haap; print(hawcx_haap.__version__)\n",
                "data.json": b'{"message":"hello"}',
            }
        )
        first, second = self.root / "first.pyz", self.root / "second.pyz"
        with patch.dict(os.environ, {"TZ": "Pacific/Honolulu"}):
            a = build_source_bundle(source, first)
        with patch.dict(os.environ, {"TZ": "Asia/Tokyo"}):
            b = build_source_bundle(source, second)
        self.assertEqual(a, b)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(
            f"sha256:{hashlib.sha256(first.read_bytes()).hexdigest()}", a.workload_digest
        )
        self.assertEqual(first.stat().st_size, a.size_bytes)
        with zipfile.ZipFile(first) as archive:
            provenance = json.loads(archive.read("_hawcx_build.json"))
            self.assertEqual(a.sdk_digest, provenance["sdk_digest"])
            self.assertIn("hawcx_haap/mcp_caller.py", archive.namelist())
            self.assertNotIn("hawcx_haap/bundle.py", archive.namelist())
            self.assertTrue(all(i.date_time == (1980, 1, 1, 0, 0, 0) for i in archive.infolist()))
        # No installed SDK/PYTHONPATH in the child: the measured closure must suffice.
        result = subprocess.run(
            [sys.executable, "-I", str(first)],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(f"{SDK_VERSION}\n", result.stdout)
        if os.name != "nt":
            self.assertTrue(first.stat().st_mode & stat.S_IXUSR)
            direct = subprocess.run(
                [str(first)], cwd=self.root, capture_output=True, text=True, check=True
            )
            self.assertEqual(result.stdout, direct.stdout)
        build_source_bundle(
            self.source({"__main__.py": b"print('changed')"}), self.root / "third.pyz"
        )
        self.assertNotEqual(first.read_bytes(), (self.root / "third.pyz").read_bytes())

    def test_closure_hash_commits_to_sdk_content_and_version_matches_package(self):
        files, digest = _runtime_sources()
        h = hashlib.sha256()
        for name, data in sorted(files.items()):
            encoded = name.encode()
            h.update(len(encoded).to_bytes(4, "big") + encoded)
            h.update(len(data).to_bytes(8, "big") + data)
        self.assertEqual(h.hexdigest(), digest)
        project = Path(__file__).resolve().parents[1] / "pyproject.toml"
        self.assertIn(f'version = "{SDK_VERSION}"', project.read_text())
        original = Path.read_bytes
        with patch.object(Path, "read_bytes", lambda p: original(p) + b"\n# SDK change\n"):
            self.assertNotEqual(digest, _runtime_sources()[1])

    def test_explicit_entrypoint_preserves_exit_status(self):
        source = self.source({"agent.py": b"def run():\n    print('ran'); return 7\n"})
        output = self.root / "out.pyz"
        build_source_bundle(source, output, main="agent:run")
        run = subprocess.run([sys.executable, "-I", str(output)], capture_output=True, text=True)
        self.assertEqual((7, "ran\n"), (run.returncode, run.stdout))

    def test_source_and_setup_hooks_never_execute_or_run_network(self):
        sentinel = self.root / "executed"
        malicious = (
            f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('oops')\n".encode()
        )
        source = self.source(
            {
                "__main__.py": malicious,
                "setup.py": malicious,
                "requirements.txt": b"--index-url https://invalid.example/\n",
            }
        )
        with (
            patch("subprocess.run", side_effect=AssertionError("builder ran a process")),
            patch("socket.socket", side_effect=AssertionError("builder opened a socket")),
        ):
            build_source_bundle(source, self.root / "out.pyz")
        self.assertFalse(sentinel.exists())

    def test_malicious_paths_types_and_formats_are_refused(self):
        bad_names = [
            "../escape.py",
            "/abs.py",
            "a/./b.py",
            "a//b.py",
            "a\\b.py",
            "C:/b.py",
            "hawcx_haap/agent.py",
            "HAWCX_HAAP.py",
            "hashlib.py",
            "json/__init__.py",
            "hawcx_haap-9.dist-info/METADATA",
            "unrelated.dist-info/METADATA",
            "_hawcx_build.json",
            "bad.pyc",
            "bad.so",
            "bad.pyd",
            "bad.dylib",
            "bad.exe",
            "bad\x00.py",
            "a" * 241 + ".py",
        ]
        for name in bad_names:
            with self.subTest(name=name):
                info = zipfile.ZipInfo(name)
                # ZipInfo remembers NUL truncation only until writing; craft the raw ZIP below.
                if "\x00" in name:
                    continue
                source = self.source({"__main__.py": b"print('ok')", info: b"x"})
                with self.assertRaises(BundleError):
                    build_source_bundle(source, self.root / "out.pyz")
                self.assertFalse((self.root / "out.pyz").exists())
        for mode in (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFCHR, stat.S_IFDIR):
            info = zipfile.ZipInfo("other.py")
            info.create_system = 3
            info.external_attr = (mode | 0o644) << 16
            with self.subTest(mode=mode), self.assertRaises(BundleError):
                build_source_bundle(
                    self.source({"__main__.py": b"pass", info: b"target"}), self.root / "out.pyz"
                )

    def test_duplicates_parent_conflicts_and_archive_corruption(self):
        variants = [
            [("x.py", b"pass"), ("X.py", b"pass")],
            [("x.py", b"pass"), ("x.py", b"pass")],
            [("a.py", b"pass"), ("a.py/b.py", b"pass")],
        ]
        for entries in variants:
            raw = io.BytesIO()
            with zipfile.ZipFile(raw, "w") as archive:
                archive.writestr("__main__.py", "pass")
                for name, content in entries:
                    with warnings.catch_warnings():
                        warnings.simplefilter(
                            "ignore", UserWarning
                        )  # intentional duplicate fixture
                        archive.writestr(name, content)
            source = self.root / "source.zip"
            source.write_bytes(raw.getvalue())
            with self.subTest(entries=entries), self.assertRaises(BundleError):
                build_source_bundle(source, self.root / "out.pyz")
        source.write_bytes(b"not a zip")
        with self.assertRaises(BundleError):
            build_source_bundle(source, self.root / "out.pyz")
        source = self.source({"__main__.py": b"pass", "bad0.py": b"pass"})
        source.write_bytes(source.read_bytes().replace(b"bad0.py", b"bad\x00.py"))
        with self.assertRaises(BundleError):
            build_source_bundle(source, self.root / "out.pyz")

    def test_bounds_include_zip_bombs(self):
        variants = [
            {"__main__.py": b"#" * (MAX_MEMBER_BYTES + 1)},
            {f"f{i}.txt": b"x" for i in range(MAX_ENTRIES + 1)},
            {f"f{i}.txt": b"x" * MAX_MEMBER_BYTES for i in range(5)},
        ]
        for files in variants:
            with self.subTest(count=len(files)), self.assertRaises(BundleError):
                build_source_bundle(self.source(files), self.root / "out.pyz")
        source = self.root / "large.zip"
        with source.open("wb") as file:
            file.truncate(MAX_SOURCE_BYTES + 1)
        with self.assertRaises(BundleError):
            build_source_bundle(source, self.root / "out.pyz")

    def test_zip_metadata_is_bounded_before_member_allocation(self):
        source = self.source()
        raw = bytearray(source.read_bytes())
        end = raw.rfind(b"PK\x05\x06")
        struct.pack_into("<HH", raw, end + 8, MAX_ENTRIES + 1, MAX_ENTRIES + 1)
        source.write_bytes(raw)
        with patch(
            "hawcx_haap.source_bundle.zipfile.ZipFile", side_effect=AssertionError("allocated")
        ):
            with self.assertRaises(BundleError):
                build_source_bundle(source, self.root / "out.pyz")

    def test_source_path_is_regular_and_no_symlink_following(self):
        source = self.source()
        if os.name != "nt":
            link = self.root / "link.zip"
            link.symlink_to(source)
            with self.assertRaises(BundleError):
                build_source_bundle(link, self.root / "out.pyz")
            fifo = self.root / "fifo.zip"
            os.mkfifo(fifo)
            with self.assertRaises(BundleError):
                build_source_bundle(fifo, self.root / "out.pyz")
        with self.assertRaises(BundleError):
            build_source_bundle(self.root, self.root / "out.pyz")

    def test_dependencies_syntax_and_entrypoint_refuse_without_output(self):
        for files, entry in [
            ({"agent.py": b"pass"}, None),
            ({"agent.py": b"pass"}, "agent:lambda"),
            ({"agent.py": b"def run(required): pass"}, "agent:run"),
            ({"agent.py": b"def run(*, required): pass"}, "agent:run"),
            ({"agent.py": b"async def run(): pass"}, "agent:run"),
            ({"agent.py": b"@decorator\ndef run(): pass"}, "agent:run"),
            ({"agent.py": b"pass"}, "absent:run"),
            ({"__main__.py": b"pass"}, "agent:run"),
            ({"__main__.py": b"import crewai"}, None),
            ({"__main__.py": b"import hawcx_haap.bundle"}, None),
            ({"__main__.py": b"pass", "data.txt": b"ELF\x00"}, None),
            ({"__main__.py": b"type Alias = int"}, None),
            ({"__main__.py": b"\xff"}, None),
        ]:
            with self.subTest(files=files, entry=entry), self.assertRaises(BundleError):
                build_source_bundle(self.source(files), self.root / "out.pyz", main=entry)
            self.assertFalse((self.root / "out.pyz").exists())
        with self.assertRaisesRegex(BundleError, "bare .pyc"):
            build_source_bundle(self.root / "agent.pyc", self.root / "out.pyz")

    def test_existing_output_and_write_failure_are_not_publishable(self):
        source = self.source()
        output = self.root / "out.pyz"
        output.write_bytes(b"preserve me")
        with self.assertRaises(BundleError):
            build_source_bundle(source, output)
        self.assertEqual(b"preserve me", output.read_bytes())
        output.unlink()
        with patch("os.fsync", side_effect=OSError("disk failed")), self.assertRaises(BundleError):
            build_source_bundle(source, output)
        self.assertFalse(output.exists())

    def test_cli_has_machine_readable_success_and_loud_failure(self):
        source = self.source()
        output = self.root / "out.pyz"
        with patch("sys.stdout", new_callable=io.StringIO) as stdout:
            self.assertEqual(0, main([str(source), "--output", str(output)]))
            report = json.loads(stdout.getvalue())
        self.assertEqual(
            f"sha256:{hashlib.sha256(output.read_bytes()).hexdigest()}", report["workload_digest"]
        )
        self.assertEqual("3.10", report["python_version"])
        with patch("sys.stderr", new_callable=io.StringIO) as stderr:
            self.assertEqual(1, main([str(source), "--output", str(output)]))
            self.assertIn("refused", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
