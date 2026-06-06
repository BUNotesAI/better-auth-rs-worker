//! Cloudflare Worker adapter boundary for better-auth.
//!
//! This crate keeps Worker request/response conversion and Worker v1 capability
//! validation host-testable. Runtime bindings, D1 persistence, and Wrangler
//! smoke coverage are layered on top by later phases.

mod capabilities;
mod config;
mod conversion;

pub use capabilities::{WorkerRuntimeCapabilities, WorkerRuntimeCapabilitiesBuilder};
pub use config::{
    ValidatedWorkerV1Config, WorkerDeferredCapability, WorkerPasswordHasherPolicy, WorkerV1Config,
    validate_worker_v1_config,
};
pub use conversion::{
    WorkerRequestParts, WorkerResponseParts, auth_request_from_worker_parts,
    worker_response_from_auth_response,
};
