//! Customer Redis SessionMaterial reader.
//!
//! The CAA writes `SubstrateMaterial` to customer-deployed Redis under
//! `haap:session:<u64_decimal>`. RSV reads at verify time. Only the
//! reader lives here — the writer is in `hx_agent_client_admin_service`.

use haap_sdk_types::{SubstrateMaterial, SubstrateReaderError};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;

fn map_redis(e: redis::RedisError) -> SubstrateReaderError {
    SubstrateReaderError::Redis(e.to_string())
}

pub struct CustomerSubstrateReader {
    conn: ConnectionManager,
}

impl CustomerSubstrateReader {
    pub async fn connect(url: &str) -> Result<Self, SubstrateReaderError> {
        let client = redis::Client::open(url).map_err(map_redis)?;
        let conn = ConnectionManager::new(client).await.map_err(map_redis)?;
        Ok(Self { conn })
    }

    /// Fetch SubstrateMaterial keyed by `haap:session:<session_id_decimal>`.
    pub async fn fetch_session(
        &mut self,
        session_id: u64,
    ) -> Result<Option<SubstrateMaterial>, SubstrateReaderError> {
        let key = format!("haap:session:{}", session_id);
        let bytes: Option<Vec<u8>> = self.conn.get(&key).await.map_err(map_redis)?;
        match bytes {
            Some(b) => Ok(Some(bincode::deserialize(&b)?)),
            None => Ok(None),
        }
    }

    pub fn connection(&self) -> ConnectionManager {
        self.conn.clone()
    }
}
