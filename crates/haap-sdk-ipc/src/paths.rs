//! Default IPC socket paths.
//!
//! Resolution prefers `$XDG_RUNTIME_DIR/hawcx/` (which systemd creates
//! with mode `0o700` on Linux). `/tmp/hawcx/` is refused by default —
//! it lives on a world-writable directory and historically allowed a
//! local attacker to symlink-race the socket parent (TOCTOU window
//! between `mkdir` and `set_permissions`). Operators who must use
//! `/tmp/hawcx/` (containerised hosts without an XDG_RUNTIME_DIR)
//! must explicitly opt in via `HAAP_SDK_ALLOW_TMP_IPC=1`.
//!
//! Before returning an existing directory, the resolver `stat`s it
//! and refuses if the owner UID does not match the current process
//! UID or if any group/other mode bit is set. This catches the case
//! where an earlier (less-privileged) process created the directory
//! and the current process inherited it — the old directory's mode
//! is the load-bearing access-control gate for everything inside,
//! including the UDS file the SDK is about to create.

use crate::error::IpcError;
use std::path::PathBuf;

/// Resolves the per-user IPC socket directory:
///
/// - Prefer `$XDG_RUNTIME_DIR/hawcx/`. On Linux+systemd this is
///   `/run/user/<uid>/hawcx/`, a per-UID `0o700` directory the kernel
///   tears down at logout. On macOS, `XDG_RUNTIME_DIR` is unset by
///   default but operators can set it to a per-user directory under
///   `$HOME/Library/Caches/`.
/// - Fall back to `$TMPDIR/hawcx/` (macOS) only when XDG_RUNTIME_DIR
///   is unset and `$TMPDIR` is set.
/// - Refuse `/tmp/hawcx/` unless `HAAP_SDK_ALLOW_TMP_IPC=1`.
///
/// In every case, an existing directory is validated:
///
/// - Owner UID must equal `getuid()` (no inheriting a directory
///   created by a different user).
/// - Mode bits MUST be `0o7XX` where `XX == 00` — i.e., no group or
///   other access. The SDK will not "tighten" an existing directory
///   on the operator's behalf; that would be a load-bearing privilege
///   escalation in the wrong direction.
///
/// If the directory does not exist, the SDK creates it with mode
/// `0o700` directly (no permissive intermediate state).
pub fn ipc_socket_dir() -> Result<PathBuf, IpcError> {
    let dir = pick_base_dir()?.join("hawcx");

    if dir.exists() {
        validate_existing_dir(&dir)?;
        return Ok(dir);
    }

    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

/// Pick the base directory we'll suffix `hawcx/` onto.
///
/// The `/tmp/hawcx/` opt-in is gated by `HAAP_SDK_ALLOW_TMP_IPC=1` —
/// a tool the operator must reach for explicitly when running on a
/// host that lacks `$XDG_RUNTIME_DIR`. The default rejection avoids
/// the silent-fallback foot-gun where a hardened deployment quietly
/// regresses to /tmp because the systemd unit didn't pass through
/// the env var.
fn pick_base_dir() -> Result<PathBuf, IpcError> {
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg));
        }
    }
    if let Ok(tmp) = std::env::var("TMPDIR") {
        if !tmp.is_empty() {
            return Ok(PathBuf::from(tmp));
        }
    }
    if std::env::var("HAAP_SDK_ALLOW_TMP_IPC").as_deref() == Ok("1") {
        return Ok(PathBuf::from("/tmp"));
    }
    Err(IpcError::Io(std::io::Error::other(
        "no IPC base dir found: set XDG_RUNTIME_DIR (preferred) or TMPDIR, \
         or pass HAAP_SDK_ALLOW_TMP_IPC=1 to fall back to /tmp/hawcx/ \
         (not recommended — see haap-sdk-ipc::paths docs)",
    )))
}

/// Validate an already-existing IPC directory. Refuses on:
///
/// - owner UID mismatch
/// - any group/other mode bit set (mask `0o077`)
fn validate_existing_dir(dir: &std::path::Path) -> Result<(), IpcError> {
    let meta = std::fs::metadata(dir).map_err(IpcError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let dir_uid = meta.uid();
        // SAFETY: getuid is always safe; returns a libc::uid_t.
        let our_uid = unsafe { libc::getuid() };
        if dir_uid != our_uid {
            return Err(IpcError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "IPC dir {} is owned by uid {} but this process is uid {}; \
                     refusing to use a directory created by another user",
                    dir.display(),
                    dir_uid,
                    our_uid
                ),
            )));
        }
        let mode_bits = meta.mode() & 0o777;
        if mode_bits & 0o077 != 0 {
            return Err(IpcError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "IPC dir {} has mode {:o}; refusing to use a dir with group/other bits set. \
                     chmod 700 the directory, or delete it and let the SDK recreate it.",
                    dir.display(),
                    mode_bits
                ),
            )));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
    }
    Ok(())
}

/// Convenience: `ipc_socket_dir()` joined with a given filename.
pub fn ipc_socket_path(name: &str) -> Result<PathBuf, IpcError> {
    Ok(ipc_socket_dir()?.join(name))
}
