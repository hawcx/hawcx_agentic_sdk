use serde::{Deserialize, Serialize};

/// Opaque container for sealed identity material.
///
/// Internal layout depends on the sealer backend. Always treat as
/// opaque bytes — only the matching sealer can unseal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBundle {
    pub backend_tag: String,
    pub ciphertext: Vec<u8>,
}
