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
    pub async fn bind(path: &Path, expected_peer_uid: u32) -> Result<Self, IpcError> {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
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
