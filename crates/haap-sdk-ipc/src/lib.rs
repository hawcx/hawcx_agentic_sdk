//! Unix domain socket IPC primitives with SO_PEERCRED-enforced peer
//! identity. SDK-owned (no protocol code).
//!
//! Provided as a re-usable building block for SDK components that need
//! same-host process boundaries (CLI ↔ helpers, future bin-to-bin
//! coordination). The five customer-side binaries from hx_labs handle
//! their own IPC internally; this crate is for SDK orchestration.

pub mod connection;
pub mod error;
pub mod framing;
pub mod paths;
pub mod peer_cred;

pub use connection::{IpcClient, IpcConnection, IpcServer};
pub use error::IpcError;
pub use paths::{ipc_socket_dir, ipc_socket_path};
pub use peer_cred::{current_uid, peer_identity, PeerIdentity};
