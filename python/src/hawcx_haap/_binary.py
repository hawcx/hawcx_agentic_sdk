"""Binary path resolution for the bundled hawcx-manager binary.

The ``hawcx-manager`` binary is platform-specific. It is shipped as package
data inside a platform-tagged wheel (e.g. ``manylinux2014_x86_64``,
``macosx_11_0_arm64``, ``win_amd64``), bundled under ``hawcx_haap/_bin/``.

A pure-Python sdist (or a wheel built without the binary staged in) does NOT
contain the binary; in that case :func:`get_binary_path` raises a clear error.
This mirrors ``node/src/binary.ts``: the TypeScript client resolves the binary
out of a platform-specific optional dependency, and raises if it is absent.
"""

from __future__ import annotations

import os
import sys

#: Supported (sys.platform, os.uname-style machine) pairs, for error messages.
SUPPORTED_PLATFORMS = (
    "linux-x86_64 (manylinux2014_x86_64)",
    "linux-aarch64 (manylinux2014_aarch64)",
    "darwin-arm64 (macosx_11_0_arm64)",
    "win32-amd64 (win_amd64)",
    "win32-arm64 (win_arm64)",
)


def _binary_name() -> str:
    return "hawcx-manager.exe" if sys.platform == "win32" else "hawcx-manager"


def get_binary_path() -> str:
    """Return the absolute path to the bundled hawcx-manager binary.

    The binary is shipped as package data inside the platform-specific wheel,
    under ``hawcx_haap/_bin/``. Install ``hawcx-haap`` from a platform wheel
    (``pip install hawcx-haap``) to obtain it.

    Returns:
        Absolute filesystem path to the ``hawcx-manager`` (or
        ``hawcx-manager.exe`` on Windows) binary.

    Raises:
        RuntimeError: if the binary is not present in the installed package
            (e.g. installed from a pure-Python sdist, or on an unsupported
            platform).
    """
    binary_name = _binary_name()

    # The binary is shipped as package data under hawcx_haap/_bin/. It is a
    # real on-disk file in every install layout we ship (platform wheels), so a
    # __file__-relative path is the simplest reliable resolution.
    binary = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_bin", binary_name)

    if not os.path.isfile(binary):
        raise RuntimeError(
            f"hawcx-manager binary not found (expected bundled at "
            f"hawcx_haap/_bin/{binary_name}).\n"
            "This package was installed without the platform binary "
            "(pure-Python sdist or unsupported platform).\n"
            "Install hawcx-haap from a platform wheel: pip install hawcx-haap\n"
            "Supported platforms: " + ", ".join(SUPPORTED_PLATFORMS)
        )

    # Ensure the binary is executable (wheels may not preserve the bit on all
    # extraction paths; harmless no-op on Windows).
    if sys.platform != "win32":
        try:
            mode = os.stat(binary).st_mode
            if not mode & 0o111:
                os.chmod(binary, mode | 0o111)
        except OSError:  # pragma: no cover - best-effort
            pass

    return binary
