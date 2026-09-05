#!/usr/bin/env python3
"""Read the built package and compare both runtime entries to staged bytes."""
import argparse
from pathlib import Path
import tarfile
import zipfile


def verify(archive, directory, prefix):
    directory = Path(directory)
    ext = '.exe' if (directory / 'hawcx-manager.exe').exists() else ''
    expected = (directory / ('hawcx-manager' + ext)).read_bytes()
    if not expected:
        raise ValueError('empty staged runtime')
    archive = Path(archive)
    with (zipfile.ZipFile(archive) if archive.suffix == '.whl'
          else tarfile.open(archive)) as package:
        for role in ('hawcx-manager', 'haap-unseal-orch'):
            name = prefix + role + ext
            if isinstance(package, zipfile.ZipFile):
                if package.namelist().count(name) != 1:
                    raise ValueError('missing or duplicate runtime entry: ' + name)
                data = package.read(name)
            else:
                members = [m for m in package.getmembers() if m.name == name]
                if len(members) != 1 or not members[0].isfile():
                    raise ValueError('missing, duplicate, or non-file runtime entry: ' + name)
                data = package.extractfile(members[0]).read()
            if data != expected:
                raise ValueError('packaged runtime bytes differ: ' + name)
    print('PASS packaged multicall bytes:', archive)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive')
    parser.add_argument('--directory', required=True)
    parser.add_argument('--prefix', required=True)
    args = parser.parse_args()
    verify(args.archive, args.directory, args.prefix)
