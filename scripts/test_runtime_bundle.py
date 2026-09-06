"""Packaging regressions; native release probes execute the actual downloaded crate."""
import importlib.util
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch
import subprocess
import zipfile
import tarfile
import io

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('bundle', Path(__file__).with_name('check-runtime-bundle.py'))
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)

archive_spec = importlib.util.spec_from_file_location('archive', Path(__file__).with_name('check-runtime-archive.py'))
archive = importlib.util.module_from_spec(archive_spec)
archive_spec.loader.exec_module(archive)


class RuntimeBundleTests(unittest.TestCase):
    def test_channels_share_pin_targets_and_multicall(self):
        versions = []
        targets = []
        for name in ('release.yml', 'release-node.yml', 'release-python.yml'):
            content = (ROOT / '.github/workflows' / name).read_text()
            versions.append(re.findall(r'HAWCX_MANAGER_VERSION: "([^"]+)"', content))
            targets.append(set(re.findall(r'target: ([a-z0-9_-]+)', content)))
            self.assertNotIn('cargo install haap-unseal-orch', content)
            self.assertIn('python scripts/check-runtime-bundle.py', content)
        self.assertEqual(versions, [['0.11.8']] * 3)
        self.assertEqual(targets[0], targets[1])
        self.assertEqual(targets[1], targets[2])

    def test_packaged_bytes_not_just_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'hawcx-manager').write_bytes(b'real runtime')
            for suffix in ('.whl', '.tgz'):
                for corrupt in (False, True):
                    file = root / ('package' + suffix)
                    contents = {'package/hawcx-manager': b'real runtime',
                                'package/haap-unseal-orch': b'stale' if corrupt else b'real runtime'}
                    if suffix == '.whl':
                        with zipfile.ZipFile(file, 'w') as out:
                            for name, data in contents.items():
                                out.writestr(name, data)
                    else:
                        with tarfile.open(file, 'w:gz') as out:
                            for name, data in contents.items():
                                member = tarfile.TarInfo(name)
                                member.size = len(data)
                                out.addfile(member, io.BytesIO(data))
                    if corrupt:
                        with self.assertRaises(ValueError):
                            archive.verify(file, root, 'package/')
                    else:
                        archive.verify(file, root, 'package/')

    def test_artifacts_and_dispatch_fail_loudly(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = Path(tmp) / 'hawcx-manager'
            orch = Path(tmp) / 'haap-unseal-orch'
            manager.write_bytes(b'runtime')
            with self.assertRaises(FileNotFoundError):
                bundle.verify(tmp, '0.11.8', True)
            orch.write_bytes(b'stale')
            with self.assertRaises(ValueError):
                bundle.verify(tmp, '0.11.8', True)
            orch.write_bytes(manager.read_bytes())
            bundle.verify(tmp, '0.11.8', True)
            version = subprocess.CompletedProcess([], 0, 'hawcx-manager 0.11.8\n', '')
            for result in (subprocess.CompletedProcess([], 0, 'USAGE', ''),
                           subprocess.CompletedProcess([], 127, '', 'linker failure'),
                           subprocess.CompletedProcess([], 0, 'haap.audit.security', '')):
                with patch.object(bundle.subprocess, 'run', side_effect=[version, result]):
                    with self.assertRaises(ValueError):
                        bundle.verify(tmp, '0.11.8')
            with patch.object(bundle.subprocess, 'run', side_effect=[version,
                    subprocess.CompletedProcess([], 1, '', 'haap.audit.security config refused')]):
                bundle.verify(tmp, '0.11.8')
            with patch.object(bundle.subprocess, 'run', return_value=version):
                with self.assertRaises(ValueError):
                    bundle.verify(tmp, '0.8.8')


if __name__ == '__main__':
    unittest.main()
