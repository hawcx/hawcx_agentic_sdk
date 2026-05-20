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
    pub async fn connect(path: &Path) -> Result<IpcConnection, IpcError> {
        let stream = UnixStream::connect(path).await?;
        let peer = peer_identity(&stream)?;
        Ok(IpcConnection { stream, peer })
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
