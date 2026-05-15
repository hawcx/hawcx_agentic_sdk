//! Default IPC socket paths.

use crate::error::IpcError;
use std::path::PathBuf;

/// Resolves the per-user IPC socket directory:
/// - Linux: `$XDG_RUNTIME_DIR/hawcx/` if set, else `$TMPDIR/hawcx/`
/// - macOS: `$TMPDIR/hawcx/`
///
/// Creates the directory with mode 0700 if missing.
pub fn ipc_socket_dir() -> Result<PathBuf, IpcError> {
    #[cfg(target_os = "linux")]
    let base = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .or_else(|| std::env::var("TMPDIR").ok())
        .unwrap_or_else(|| "/tmp".to_string());

    #[cfg(not(target_os = "linux"))]
    let base = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());

    let dir = PathBuf::from(base).join("hawcx");
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(dir)
}

/// Convenience: `ipc_socket_dir()` joined with a given filename.
pub fn ipc_socket_path(name: &str) -> Result<PathBuf, IpcError> {
    Ok(ipc_socket_dir()?.join(name))
}
