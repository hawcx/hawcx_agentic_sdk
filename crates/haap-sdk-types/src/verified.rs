use zeroize::Zeroizing;

/// The RSV's `verify_and_decrypt` output: session metadata + plaintext
/// body + the per-request response_key the MCP server uses to encrypt
/// its response.
pub struct VerifiedRequest {
    pub session_id: u64,
    pub jti: [u8; 22],
    pub plaintext_body: Vec<u8>,
    pub response_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for VerifiedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedRequest")
            .field("session_id", &self.session_id)
            .field("jti", &String::from_utf8_lossy(&self.jti))
            .field("plaintext_body_len", &self.plaintext_body.len())
            .field("response_key", &"[REDACTED]")
            .finish()
    }
}
