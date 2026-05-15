//! Substrate material — what the CAA writes to customer Redis and
//! RSV reads at verify time.
//!
//! Per Phase 0.4 of the RSV cascade adapter PR
//! (docs/rsv_adapter_helper_signatures.md), the SDK's previous
//! `SubstrateMaterial` shape was substantially incomplete vs what
//! `haap_core::cascade::verify_and_decrypt_request` requires. This
//! module now re-exports `haap_redis::RawSessionRecord` as the
//! canonical substrate format. The CAA already writes records in
//! this shape via `haap_redis::set_session`; the SDK reads via
//! `haap_redis::get_session`.
//!
//! `RawSessionRecord` is the byte-level (un-decompressed Ristretto)
//! form. The cascade consumes `SessionRecord` (with decompressed
//! points), produced via the `TryFrom<RawSessionRecord> for
//! SessionRecord` impl gated on `haap-core/redis-backend`.

pub use haap_redis::RawSessionRecord as SubstrateMaterial;
