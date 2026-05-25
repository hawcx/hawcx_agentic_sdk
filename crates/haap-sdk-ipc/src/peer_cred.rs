//! SO_PEERCRED helpers for OS-enforced peer process identity.
//!
//! On Linux, uses `struct ucred` via `nix::sys::socket::sockopt::PeerCredentials`.
//! On macOS, uses `LOCAL_PEERPID` + `LOCAL_PEEREUID` via raw `libc::getsockopt`.

use crate::error::IpcError;
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::io::BorrowedFd;

#[derive(Debug, Clone, Copy)]
pub struct PeerIdentity {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

#[cfg(target_os = "linux")]
pub fn peer_identity<T: AsRawFd>(stream: &T) -> Result<PeerIdentity, IpcError> {
    use nix::sys::socket::sockopt::PeerCredentials;
    use nix::sys::socket::getsockopt;
    // nix 0.27 requires `AsFd` (not a raw fd) on getsockopt. Borrow the
    // raw fd into a BorrowedFd scoped to this function — caller's
    // `&T` (typically &UnixStream) guarantees the fd is open for the
    // duration of this borrow.
    // SAFETY: stream borrows the fd for the duration of this call.
    let fd = unsafe { BorrowedFd::borrow_raw(stream.as_raw_fd()) };
    let creds = getsockopt(&fd, PeerCredentials)?;
    Ok(PeerIdentity {
        pid: creds.pid(),
        uid: creds.uid(),
        gid: creds.gid(),
    })
}

#[cfg(target_os = "macos")]
pub fn peer_identity<T: AsRawFd>(stream: &T) -> Result<PeerIdentity, IpcError> {
    use std::mem;
    use std::os::raw::{c_int, c_void};

    const SOL_LOCAL: c_int = 0;
    const LOCAL_PEERPID: c_int = 2;
    const LOCAL_PEEREUID: c_int = 3;
    // LOCAL_PEEREGID does not exist on macOS; we approximate via getpeereid().

    let fd = stream.as_raw_fd();
    let mut pid: i32 = 0;
    let mut pid_len: libc::socklen_t = mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: getsockopt with a writable buffer of correct length.
    let r = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERPID,
            &mut pid as *mut i32 as *mut c_void,
            &mut pid_len,
        )
    };
    if r < 0 {
        return Err(IpcError::Io(std::io::Error::last_os_error()));
    }

    let mut uid: u32 = 0;
    let mut uid_len: libc::socklen_t = mem::size_of::<u32>() as libc::socklen_t;
    // SAFETY: see above.
    let r = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEEREUID,
            &mut uid as *mut u32 as *mut c_void,
            &mut uid_len,
        )
    };
    if r < 0 {
        return Err(IpcError::Io(std::io::Error::last_os_error()));
    }

    // GID via getpeereid (BSD/macOS).
    let mut peer_uid: libc::uid_t = 0;
    let mut peer_gid: libc::gid_t = 0;
    // SAFETY: getpeereid populates uid/gid with valid integers for a connected UDS.
    let r = unsafe { libc::getpeereid(fd, &mut peer_uid, &mut peer_gid) };
    if r < 0 {
        return Err(IpcError::Io(std::io::Error::last_os_error()));
    }

    Ok(PeerIdentity {
        pid,
        uid,
        gid: peer_gid as u32,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn peer_identity<T: AsRawFd>(_stream: &T) -> Result<PeerIdentity, IpcError> {
    Err(IpcError::PeerCredUnsupported)
}

/// Returns the current process's UID — useful for `IpcServer::bind`
/// where the expected peer UID is the same as the current process.
pub fn current_uid() -> u32 {
    // SAFETY: getuid is always safe; returns a libc::uid_t.
    unsafe { libc::getuid() }
}
