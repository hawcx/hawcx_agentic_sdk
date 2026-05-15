//! Length-prefixed binary framing for UDS IPC.
//!
//! Frame layout: `u32_be(payload_len) || payload_bytes`.
//! Maximum frame size: 16 MiB.

use crate::error::IpcError;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Bytes, IpcError> {
    let len = reader.read_u32().await?;
    if len > MAX_FRAME {
        return Err(IpcError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;
    Ok(Bytes::from(buf))
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), IpcError> {
    let len: u32 = payload
        .len()
        .try_into()
        .map_err(|_| IpcError::FrameTooLarge(u32::MAX))?;
    if len > MAX_FRAME {
        return Err(IpcError::FrameTooLarge(len));
    }
    writer.write_u32(len).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}
