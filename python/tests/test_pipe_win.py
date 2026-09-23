"""``pipe_win.connect`` reaches a pipe that grants it only the dial-only mask.

The supervisor grants a principal that only dials (``PIPE_DIAL_ACCESS``, no
``FILE_CREATE_PIPE_INSTANCE``) exactly that mask, and refuses an open asking
for ``GENERIC_WRITE``. This builds such a pipe for the current user and proves
the SDK's open lands and carries bytes both ways, with the old
``GENERIC_READ | GENERIC_WRITE`` open refused as the negative control.

Mutation killed (2026-09-23, Windows 11 Pro 10.0.26200): ``connect`` back on
``GENERIC_READ | GENERIC_WRITE`` -> ``IpcError`` ... ``(error 5)``.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows named pipes")

PIPE_ACCESS_DUPLEX = 0x3
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x0008_0000
GENERIC_READ_WRITE = 0xC0000000  # the open pipe_win.connect made before this change
ERROR_ACCESS_DENIED = 5
ERROR_PIPE_CONNECTED = 535


def _own_sid() -> str:
    out = subprocess.run(
        ["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True
    ).stdout
    return out.strip().split(",")[-1].strip('"')


def test_connect_dials_a_pipe_granting_only_the_dial_mask() -> None:
    import ctypes.wintypes as wt

    from hawcx_haap import pipe_win

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32.CreateNamedPipeW.restype = wt.HANDLE
    k32.CreateNamedPipeW.argtypes = [
        wt.LPCWSTR,
        wt.DWORD,
        wt.DWORD,
        wt.DWORD,
        wt.DWORD,
        wt.DWORD,
        wt.DWORD,
        ctypes.c_void_p,
    ]
    k32.CreateFileW.restype = wt.HANDLE
    k32.CreateFileW.argtypes = [
        wt.LPCWSTR,
        wt.DWORD,
        wt.DWORD,
        ctypes.c_void_p,
        wt.DWORD,
        wt.DWORD,
        wt.HANDLE,
    ]
    k32.ConnectNamedPipe.argtypes = [wt.HANDLE, ctypes.c_void_p]
    k32.ReadFile.argtypes = [
        wt.HANDLE,
        ctypes.c_void_p,
        wt.DWORD,
        ctypes.POINTER(wt.DWORD),
        ctypes.c_void_p,
    ]
    k32.WriteFile.argtypes = [
        wt.HANDLE,
        ctypes.c_void_p,
        wt.DWORD,
        ctypes.POINTER(wt.DWORD),
        ctypes.c_void_p,
    ]
    k32.CloseHandle.argtypes = [wt.HANDLE]
    k32.LocalFree.argtypes = [ctypes.c_void_p]
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wt.LPCWSTR,
        wt.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
    ]

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("nLength", wt.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wt.BOOL),
        ]

    sddl = f"D:P(A;;GA;;;SY)(A;;{pipe_win.PIPE_DIAL_ACCESS:#x};;;{_own_sid()})"
    psd = ctypes.c_void_p()
    assert adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(psd), None
    ), f"SDDL: error {ctypes.get_last_error()}"
    sa = SecurityAttributes(ctypes.sizeof(SecurityAttributes), psd, 0)
    name = rf"\\.\pipe\hawcx-sdk-dial-only-{os.getpid()}"
    server = k32.CreateNamedPipeW(
        name,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        0,
        1,
        4096,
        4096,
        0,
        ctypes.byref(sa),
    )
    k32.LocalFree(psd)
    invalid = ctypes.c_void_p(-1).value
    assert server not in (None, invalid), f"create: error {ctypes.get_last_error()}"
    try:
        # Control first: a refused open consumes nothing, an admitted one would.
        legacy = k32.CreateFileW(name, GENERIC_READ_WRITE, 0, None, 3, 0, None)
        legacy_err = ctypes.get_last_error()
        assert legacy in (None, invalid), "the pipe must refuse GENERIC_READ | GENERIC_WRITE"
        assert legacy_err == ERROR_ACCESS_DENIED, legacy_err

        client = pipe_win.connect(name, timeout_secs=2.0)
        try:
            if not k32.ConnectNamedPipe(server, None):
                assert ctypes.get_last_error() == ERROR_PIPE_CONNECTED
            client.sendall(b"hi")
            buf, n = ctypes.create_string_buffer(2), wt.DWORD(0)
            assert k32.ReadFile(server, buf, 2, ctypes.byref(n), None) and buf.raw == b"hi"
            assert k32.WriteFile(server, b"ok", 2, ctypes.byref(n), None)
            assert client.recv(2) == b"ok"
        finally:
            client.close()
    finally:
        k32.CloseHandle(server)


def test_a_failed_open_raises_at_connect_not_at_first_write() -> None:
    """``CreateFileW`` hands back ``INVALID_HANDLE_VALUE`` unsigned; compared with
    a bare ``-1`` the failure was returned as a socket and surfaced later as
    ``WriteFile`` error 6, naming the wrong operation and cause."""
    from hawcx_haap import pipe_win
    from hawcx_haap.errors import IpcError

    # ERROR_FILE_NOT_FOUND (2): an absent PIPE. A malformed name reads as a
    # relative file path and fails with ERROR_PATH_NOT_FOUND (3) instead.
    with pytest.raises(IpcError, match=r"CreateFileW failed .* \(error 2\)"):
        pipe_win.connect(rf"\\.\pipe\hawcx-sdk-no-such-pipe-{os.getpid()}", timeout_secs=1.0)
