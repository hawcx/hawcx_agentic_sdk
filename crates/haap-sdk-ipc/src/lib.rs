//! SDK-internal local IPC primitives with kernel-enforced peer identity.
//!
//! Provided as a re-usable building block for SDK components that need
//! same-host process boundaries (CLI ↔ helpers, future bin-to-bin
//! coordination). The five protected child binaries from `hx_labs` handle
//! their own IPC internally per CS v7.2.5 §39.12 (Cross-Platform IPC
//! Transport); this crate is for SDK orchestration, not on the protocol
//! surface.
//!
//! ## Platform support
//!
//! - **Unix family (Linux, macOS):** Unix domain sockets + `SO_PEERCRED`
//!   / `LOCAL_PEERCRED` peer-credential verification per §39.12.1.
//! - **Windows:** Named-pipe support is a follow-up; the spec form is
//!   the `haap_ipc::win_dacl` abstraction in `hx_labs` (§39.12.2). On
//!   Windows today, only the platform-agnostic modules (`error`,
//!   `framing`) build; the listener / peer-cred surface is `cfg(unix)`.

pub mod error;
pub mod framing;
pub mod paths;

#[cfg(unix)]
pub mod connection;
#[cfg(unix)]
pub mod peer_cred;

#[cfg(unix)]
pub use connection::{IpcClient, IpcConnection, IpcServer};
pub use error::IpcError;
pub use paths::{ipc_socket_dir, ipc_socket_path};
#[cfg(unix)]
pub use peer_cred::{current_uid, peer_identity, PeerIdentity};
