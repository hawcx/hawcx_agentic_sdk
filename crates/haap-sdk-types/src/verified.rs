use zeroize::Zeroizing;
use hex;

/// The RSV's `verify_and_decrypt` output: session metadata + plaintext
/// body + the per-request response_key the MCP server uses to encrypt
/// its response.
///
/// JTI is `[u8; 16]` — the raw CSPRNG bytes from `TokenBody.jti` after
/// cascade decryption. The 22-byte wire-form base64url encoding lives
/// in `haap_wire::ParsedToken.jti`.
pub struct VerifiedRequest {
    pub session_id: u64,
    pub jti: [u8; 16],
    pub plaintext_body: Vec<u8>,
    pub response_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for VerifiedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedRequest")
            .field("session_id", &self.session_id)
            .field("jti", &hex::encode(self.jti))
            .field("plaintext_body_len", &self.plaintext_body.len())
            .field("response_key", &"[REDACTED]")
            .finish()
    }
}
