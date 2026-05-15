//! `SubstrateMaterial` — what the CAA writes to customer Redis under
//! `haap:session:<u64_decimal>`, what RSV reads at verify time.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct SubstrateMaterial {
    pub session_id: u64,
    pub k_session_root: [u8; 32],
    pub verifier_secret: [u8; 32],
    pub scope: String,
    pub policy_epoch: u64,
}

impl std::fmt::Debug for SubstrateMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubstrateMaterial")
            .field("session_id", &self.session_id)
            .field("k_session_root", &"[REDACTED]")
            .field("verifier_secret", &"[REDACTED]")
            .field("scope", &self.scope)
            .field("policy_epoch", &self.policy_epoch)
            .finish()
    }
}
