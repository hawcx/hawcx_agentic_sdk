"""Windows Named Pipe client for the Assembler IPC.

Implemented via ``ctypes`` against ``kernel32`` so the package has no required
native build. The returned object exposes the subset of :class:`socket.socket`
that :mod:`hawcx_haap.ipc` uses: ``recv``, ``sendall``, ``settimeout``,
``close``.

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

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = -1
ERROR_PIPE_BUSY = 231
ERROR_BROKEN_PIPE = 109
ERROR_NO_DATA = 232

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

    _kernel32.ReadFile.argtypes = [
        wt.HANDLE,
        ctypes.c_void_p,
        wt.DWORD,
        ctypes.POINTER(wt.DWORD),
        ctypes.c_void_p,
    ]
    _kernel32.ReadFile.restype = wt.BOOL

    _kernel32.WriteFile.argtypes = [
        wt.HANDLE,
        ctypes.c_void_p,
        wt.DWORD,
        ctypes.POINTER(wt.DWORD),
        ctypes.c_void_p,
    ]
    _kernel32.WriteFile.restype = wt.BOOL

    _kernel32.CloseHandle.argtypes = [wt.HANDLE]
    _kernel32.CloseHandle.restype = wt.BOOL


class WindowsPipeSocket:
    """Subset of :class:`socket.socket` backed by a Windows pipe handle."""

    def __init__(self, handle: int) -> None:
        self._handle = handle
        self._timeout: float | None = None

    def settimeout(self, timeout: float | None) -> None:
        # Named Pipe timeouts via overlapped I/O are non-trivial; we fall back
        # to per-call best-effort. For v0.1.0a1 the timeout is advisory and the
        # client is expected to close on shutdown.
        self._timeout = timeout

    def sendall(self, data: bytes) -> None:
        written = wt.DWORD(0)
        buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
        ok = _kernel32.WriteFile(self._handle, buf, len(data), ctypes.byref(written), None)
        if not ok or written.value != len(data):
            err = ctypes.get_last_error()  # type: ignore[attr-defined]
            raise IpcError(
                f"WriteFile failed (error {err}, wrote {written.value}/{len(data)})"
            )

    def recv(self, nbytes: int) -> bytes:
        if nbytes <= 0:
            return b""
        buf = (ctypes.c_char * nbytes)()
        read = wt.DWORD(0)
        ok = _kernel32.ReadFile(self._handle, buf, nbytes, ctypes.byref(read), None)
        if not ok:
            err = ctypes.get_last_error()  # type: ignore[attr-defined]
            if err in (ERROR_BROKEN_PIPE, ERROR_NO_DATA):
                return b""
            raise IpcError(f"ReadFile failed (error {err})")
        # ctypes c_char array indexing returns bytes per element; flatten.
        return b"".join(buf[i] for i in range(read.value))

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
            GENERIC_READ | GENERIC_WRITE,
            0,
            None,
            OPEN_EXISTING,
            0,
            None,
        )
        if handle != INVALID_HANDLE_VALUE:
            return WindowsPipeSocket(handle)

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
