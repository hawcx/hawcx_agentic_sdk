"""Windows Named Pipe client for the Assembler IPC.

Implemented via ``ctypes`` against ``kernel32``, plus CPython's own ``_winapi``
for the overlapped reads and writes, so the package has no required native
build. The returned object exposes the subset of :class:`socket.socket` that
:mod:`hawcx_haap.ipc` uses: ``recv``, ``sendall``, ``settimeout``, ``close``.

Reference: ``crates/haap-ipc/src/win_dacl.rs``. On the server side the pipe is
created with a DACL allowing only the current user (or LocalService); the
kernel refuses connections from other users at connect time.

This module is importable on any platform; the kernel32 bindings and
``connect()`` itself raise if invoked off Windows.
"""

from __future__ import annotations

import ctypes
import sys
import time
from typing import Any

from hawcx_haap.errors import IpcError

# wintypes is only meaningful on Windows; fall back to plain ctypes types so
# this module is importable for pytest collection / mypy on Unix.
if sys.platform == "win32":
    import _winapi
    import ctypes.wintypes as wt  # type: ignore[attr-defined]

    _kernel32: Any = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
else:  # pragma: no cover — stubs for non-Windows import
    class _Stub:
        def __getattr__(self, _name: str) -> Any:
            raise IpcError("hawcx_haap.pipe_win is Windows-only")

    class _WtStub:
        DWORD = ctypes.c_uint32
        BOOL = ctypes.c_int32
        HANDLE = ctypes.c_void_p
        LPCWSTR = ctypes.c_wchar_p

    wt = _WtStub()  # type: ignore[assignment]
    _kernel32 = _Stub()
    _winapi = _Stub()

# FILE_GENERIC_READ | FILE_WRITE_DATA: read, write and SYNCHRONIZE, and NOT
# GENERIC_WRITE. On a pipe GENERIC_WRITE maps to FILE_GENERIC_WRITE, whose
# FILE_APPEND_DATA (= FILE_CREATE_PIPE_INSTANCE) is the right to add a server
# instance of the name. The supervisor grants dial-only principals exactly this
# mask (hx_agent_client_auth_service `peer_identity::PIPE_DIAL_ACCESS`); asking
# for GENERIC_WRITE against such a grant is refused at open (measured, Windows 11
# 10.0.26200). A pipe granting GENERIC_READ | GENERIC_WRITE or more admits it too.
PIPE_DIAL_ACCESS = 0x0012008B
OPEN_EXISTING = 3
# As `CreateFileW` returns it through `restype = HANDLE` (`c_void_p`): the
# unsigned all-ones value. A bare `-1` never compares equal, so a failed open
# was returned as a socket and surfaced later as `WriteFile` error 6.
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
FILE_FLAG_OVERLAPPED = 0x40000000
ERROR_PIPE_BUSY = 231
ERROR_BROKEN_PIPE = 109
ERROR_NO_DATA = 232
ERROR_OPERATION_ABORTED = 995
ERROR_IO_PENDING = 997
WAIT_OBJECT_0 = 0
INFINITE = 0xFFFFFFFF

if sys.platform == "win32":  # pragma: no cover — Windows-only signatures
    _kernel32.CreateFileW.argtypes = [
        wt.LPCWSTR,
        wt.DWORD,
        wt.DWORD,
        ctypes.c_void_p,
        wt.DWORD,
        wt.DWORD,
        wt.HANDLE,
    ]
    _kernel32.CreateFileW.restype = wt.HANDLE

    _kernel32.WaitNamedPipeW.argtypes = [wt.LPCWSTR, wt.DWORD]
    _kernel32.WaitNamedPipeW.restype = wt.BOOL

    _kernel32.CloseHandle.argtypes = [wt.HANDLE]
    _kernel32.CloseHandle.restype = wt.BOOL


class WindowsPipeSocket:
    """Subset of :class:`socket.socket` backed by a Windows pipe handle."""

    def __init__(self, handle: int) -> None:
        self._handle = handle
        self._timeout: float | None = None

    def settimeout(self, timeout: float | None) -> None:
        # Enforced per read and write, like a socket's (#129). It used to be
        # stored and ignored, so a Windows read never timed out at all.
        self._timeout = timeout

    def _finish(self, ov: Any, err: int) -> int:
        """Wait out an overlapped read or write, cancelling it at the deadline.

        Returns the bytes moved; raises :class:`TimeoutError`, as a socket
        does, when the deadline passed first. ``_winapi`` owns the buffer and
        OVERLAPPED, and ``GetOverlappedResult(True)`` waits out the cancel,
        so nothing is written into freed memory after we give up.
        """
        if err == ERROR_IO_PENDING:
            ms = INFINITE if self._timeout is None else min(int(self._timeout * 1000), INFINITE - 1)
            if _winapi.WaitForSingleObject(ov.event, ms) != WAIT_OBJECT_0:
                ov.cancel()
        # A cancel that lost the race to completion still returns the data.
        n, err = ov.GetOverlappedResult(True)
        if err == ERROR_OPERATION_ABORTED:
            raise TimeoutError("timed out")
        return int(n)

    def sendall(self, data: bytes) -> None:
        try:
            ov, err = _winapi.WriteFile(self._handle, data, overlapped=True)
            written = self._finish(ov, err)
        except TimeoutError:
            raise
        except OSError as e:
            raise IpcError(f"WriteFile failed (error {e.winerror})") from e
        if written != len(data):
            raise IpcError(f"WriteFile failed (wrote {written}/{len(data)})")

    def recv(self, nbytes: int) -> bytes:
        if nbytes <= 0:
            return b""
        try:
            ov, err = _winapi.ReadFile(self._handle, nbytes, overlapped=True)
            self._finish(ov, err)
        except TimeoutError:
            raise
        except OSError as e:
            if e.winerror in (ERROR_BROKEN_PIPE, ERROR_NO_DATA):
                return b""
            raise IpcError(f"ReadFile failed (error {e.winerror})") from e
        return bytes(ov.getbuffer())

    def close(self) -> None:
        if self._handle and self._handle != INVALID_HANDLE_VALUE:
            _kernel32.CloseHandle(self._handle)
            self._handle = INVALID_HANDLE_VALUE  # type: ignore[assignment]


def connect(path: str, *, timeout_secs: float | None = 5.0) -> WindowsPipeSocket:
    """Open a Named Pipe handle to ``path`` and wrap it as a socket-like object."""
    if sys.platform != "win32":
        raise IpcError("hawcx_haap.pipe_win.connect() is Windows-only")
    deadline = time.monotonic() + timeout_secs if timeout_secs is not None else None
    while True:
        handle = _kernel32.CreateFileW(
            path,
            PIPE_DIAL_ACCESS,
            0,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            None,
        )
        if handle != INVALID_HANDLE_VALUE:
            sock = WindowsPipeSocket(handle)
            # As a Unix socket carries its connect timeout into the handshake.
            sock.settimeout(timeout_secs)
            return sock

        err = ctypes.get_last_error()
        if err != ERROR_PIPE_BUSY:
            raise IpcError(
                f"CreateFileW failed on {path!r} (error {err})"
            )

        if deadline is not None and time.monotonic() >= deadline:
            raise IpcError(f"Timed out waiting for named pipe {path!r}")

        wait_ms = 100
        if not _kernel32.WaitNamedPipeW(path, wait_ms):
            # Loop and retry CreateFileW; busy may have cleared.
            continue
