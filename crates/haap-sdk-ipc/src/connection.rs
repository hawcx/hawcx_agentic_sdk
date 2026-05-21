//! `IpcServer`, `IpcClient`, `IpcConnection` — Unix domain socket
//! abstractions with SO_PEERCRED enforcement.
//!
//! The connection ferries opaque byte payloads; callers handle their
//! own serialization (typically bincode or postcard).

use crate::error::IpcError;
use crate::framing::{read_frame, write_frame};
use crate::peer_cred::{peer_identity, PeerIdentity};
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};

pub struct IpcServer {
    listener: UnixListener,
    expected_peer_uid: u32,
    path: PathBuf,
}

impl IpcServer {
    /// Bind a UDS at `path` and accept only peers presenting
    /// `expected_peer_uid`.
    ///
    /// TOCTOU hardening (M-3, 2026-05-20): the previous implementation
    /// called `UnixListener::bind` and then `chmod 0o600` in a second
    /// syscall. Between those two syscalls the socket exists on disk
    /// with whatever mode the process's `umask` permitted (often
    /// 0o755 = world-readable, or even 0o777 on some hosts). A local
    /// attacker who managed to `connect(2)` in that window could open
    /// a session before the chmod landed. The bind + chmod race is
    /// short but observable.
    ///
    /// Mitigation: save the current umask, raise it to `0o077` so the
    /// new socket inode is born with mode `0o700` (no group, no other
    /// access), bind, then restore the umask. We still apply
    /// `set_permissions(0o600)` afterwards as a belt-and-braces step
    /// — `0o700` from umask covers most kernels, but a few BSD-derived
    /// kernels create UDS inodes ignoring umask, so the explicit
    /// chmod backstops them. Same pattern as the CAA M-5 fix
    /// (`hx_agent_client_admin_service/crates/haap-admin-auth-bin/`).
    pub async fn bind(path: &Path, expected_peer_uid: u32) -> Result<Self, IpcError> {
        let _ = std::fs::remove_file(path);

        #[cfg(unix)]
        let saved_umask = unsafe {
            // libc::umask returns the previous mask. 0o077 strips
            // group + other rwx on every inode the process creates,
            // including the UDS we are about to bind. Holding the
            // restricted mask only for the duration of `bind` keeps
            // the blast radius tight; the saved mask is restored at
            // the end of this function regardless of bind outcome.
            libc::umask(0o077)
        };

        let bind_result = UnixListener::bind(path);

        #[cfg(unix)]
        unsafe {
            // Restore the saved umask. We do this before the `?`
            // propagates a bind failure so a panicking caller never
            // sees a process-wide umask change as a side effect of
            // our bind attempt.
            libc::umask(saved_umask);
        }

        let listener = bind_result?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Belt-and-braces: the umask above should already have
            // produced an inode with no group/other bits, but a
            // couple of BSD-derived kernels create UDS inodes
            // ignoring the umask. The explicit chmod ensures we
            // converge to 0o600 even on those.
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(Self {
            listener,
            expected_peer_uid,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn accept(&self) -> Result<IpcConnection, IpcError> {
        let (stream, _addr) = self.listener.accept().await?;
        let peer = peer_identity(&stream)?;
        if peer.uid != self.expected_peer_uid {
            return Err(IpcError::PeerCredMismatch {
                peer_uid: peer.uid,
                expected_uid: self.expected_peer_uid,
            });
        }
        Ok(IpcConnection { stream, peer })
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub struct IpcClient;

impl IpcClient {
    /// Connect to the Assembler/peer at `path` and validate the peer's
    /// effective UID via `SO_PEERCRED` / `LOCAL_PEEREUID`.
    ///
    /// H-4 (2026-05-20): the previous implementation called
    /// `peer_identity` and then ignored the result — any process with
    /// access to the socket file could connect, including unrelated
    /// daemons running under a different UID that happened to share
    /// the same `/tmp/hawcx/` parent directory.
    ///
    /// Resolution order for the expected peer UID:
    ///
    /// 1. `HAAP_SDK_EXPECTED_PEER_UID` env var (decimal u32). Set this
    ///    when the operator wires the Assembler under a different UID
    ///    than the SDK process (e.g., a sandboxed Assembler container
    ///    with a fixed UID).
    /// 2. The socket file's owner UID (via `std::fs::metadata`). This
    ///    is the right default for the typical "supervisor created
    ///    the socket as itself, SDK runs as the same user" pattern.
    ///
    /// Mismatched peers cause the connection to close before any IPC
    /// bytes are exchanged.
    pub async fn connect(path: &Path) -> Result<IpcConnection, IpcError> {
        let expected_uid = resolve_expected_peer_uid(path)?;
        let stream = UnixStream::connect(path).await?;
        let peer = peer_identity(&stream)?;
        if peer.uid != expected_uid {
            return Err(IpcError::PeerCredMismatch {
                peer_uid: peer.uid,
                expected_uid,
            });
        }
        Ok(IpcConnection { stream, peer })
    }
}

/// Resolve the expected peer UID per the documented precedence in
/// [`IpcClient::connect`]. Extracted so the policy is unit-testable.
fn resolve_expected_peer_uid(path: &Path) -> Result<u32, IpcError> {
    if let Ok(s) = std::env::var("HAAP_SDK_EXPECTED_PEER_UID") {
        return s.parse::<u32>().map_err(|e| {
            IpcError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "HAAP_SDK_EXPECTED_PEER_UID={s:?} could not be parsed as u32: {e}"
                ),
            ))
        });
    }
    let meta = std::fs::metadata(path).map_err(IpcError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(meta.uid())
    }
    #[cfg(not(unix))]
    {
        let _ = meta; // suppress unused
        Err(IpcError::PeerCredUnsupported)
    }
}

pub struct IpcConnection {
    stream: UnixStream,
    peer: PeerIdentity,
}

impl IpcConnection {
    pub fn peer(&self) -> &PeerIdentity {
        &self.peer
    }

    /// Send a raw byte payload. Caller handles serialization.
    pub async fn send_bytes(&mut self, payload: &[u8]) -> Result<(), IpcError> {
        write_frame(&mut self.stream, payload).await
    }

    /// Receive a raw byte payload. Caller handles deserialization.
    pub async fn recv_bytes(&mut self) -> Result<Vec<u8>, IpcError> {
        let bytes = read_frame(&mut self.stream).await?;
        Ok(bytes.to_vec())
    }

    pub async fn shutdown(mut self) -> Result<(), IpcError> {
        self.stream.shutdown().await?;
        Ok(())
    }
}
