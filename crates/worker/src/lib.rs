//! Cloudflare Worker adapter boundary for better-auth.
//!
//! This crate keeps Worker request/response conversion and Worker v1 capability
//! validation host-testable. Runtime bindings, D1 persistence, and Wrangler
//! smoke coverage are layered on top by later phases.

mod capabilities;
mod config;
mod conversion;
mod d1;

pub use capabilities::{WorkerRuntimeCapabilities, WorkerRuntimeCapabilitiesBuilder};
pub use config::{
    ValidatedWorkerV1Config, WorkerDeferredCapability, WorkerPasswordHasherPolicy, WorkerV1Config,
    validate_worker_v1_config,
};
pub use conversion::{
    WorkerRequestParts, WorkerResponseParts, auth_request_from_worker_parts,
    worker_response_from_auth_response,
};
pub use d1::{
    D1_MIGRATIONS_DIR, D1Database, D1DatabaseAdapter, D1PreparedStatement, D1QueryResult, D1Row,
    D1StatementMethod, D1Value, lint_d1_migration_sql,
};
