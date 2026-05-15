//! Customer Redis SessionMaterial reader.
//!
//! The CAA writes `RawSessionRecord` to customer-deployed Redis as
//! a hash under `hawcx:session:{session_id}` via
//! `haap_redis::set_session`. The RSV reads via this crate, which
//! delegates to `haap_redis::get_session` for byte-identical schema
//! handling.

use haap_redis::{get_session, RawSessionRecord};
use haap_sdk_types::SubstrateReaderError;
use redis::aio::ConnectionManager;

fn map_redis(e: redis::RedisError) -> SubstrateReaderError {
    SubstrateReaderError::Redis(e.to_string())
}

fn map_redis_store(e: haap_redis::RedisStoreError) -> SubstrateReaderError {
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

    /// Fetch `RawSessionRecord` from `hawcx:session:{session_id}` via
    /// `haap_redis::get_session`. Returns `None` if the session key
    /// is absent.
    pub async fn fetch_session(
        &mut self,
        session_id: u64,
    ) -> Result<Option<RawSessionRecord>, SubstrateReaderError> {
        let mut conn = self.conn.clone();
        get_session(&mut conn, session_id)
            .await
            .map_err(map_redis_store)
    }

    pub fn connection(&self) -> ConnectionManager {
        self.conn.clone()
    }
}
