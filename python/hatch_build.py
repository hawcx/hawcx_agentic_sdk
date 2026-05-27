"""Custom hatchling build hook for hawcx-haap.

The platform-specific ``hawcx-manager`` binary is staged into
``src/hawcx_haap/_bin/`` by the release workflow before building a
platform-tagged wheel. This hook force-includes that directory into the
wheel *only when it exists*, so that:

- platform wheel builds (binary staged) bundle the binary as package data;
- dev / editable installs and pure-Python builds (no binary staged) still
  succeed and simply omit it — ``get_binary_path()`` then raises a clear
  "install from a platform wheel" error at call time.

The wheel produced here is tagged ``py3-none-any``; the release workflow
retags it to the correct platform tag (``manylinux2014_*``, ``macosx_*``,
``win_*``) with ``python -m wheel tags`` after the build.
"""

from __future__ import annotations

import os

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

_BIN_DIR = os.path.join("src", "hawcx_haap", "_bin")


class HawcxBinaryBuildHook(BuildHookInterface):
    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict) -> None:
        bin_dir = os.path.join(self.root, _BIN_DIR)
        if not os.path.isdir(bin_dir):
            # No binary staged (dev / editable / pure-Python build). Nothing
            # to bundle; the wheel stays pure-Python.
            return

        entries = [e for e in os.listdir(bin_dir) if not e.startswith(".")]
        if not entries:
            return

        force_include = build_data.setdefault("force_include", {})
        force_include[bin_dir] = "hawcx_haap/_bin"
