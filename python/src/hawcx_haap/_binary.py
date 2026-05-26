"""Binary path resolution for the bundled hawcx-manager binary."""

from __future__ import annotations

import os
import sys


def get_binary_path() -> str:
    """Return the absolute path to the hawcx-manager binary.

    The binary is bundled in the maturin-built wheel and installed into
    the Python environment's bin/ (Scripts/ on Windows) at pip-install time.

    Raises:
        RuntimeError: if the binary is not found.
    """
    if sys.platform == "win32":
        binary = os.path.join(sys.prefix, "Scripts", "hawcx-manager.exe")
    else:
        binary = os.path.join(sys.prefix, "bin", "hawcx-manager")

    if not os.path.isfile(binary):
        raise RuntimeError(
            f"hawcx-manager binary not found at {binary}.\n"
            "Install hawcx-haap from a pre-built wheel: pip install hawcx-haap\n"
            "For local development: "
            "maturin develop --release "
            "--manifest-path ../../hx_agent_client_auth_service/crates/hawcx-manager/Cargo.toml"
        )

    return binary
