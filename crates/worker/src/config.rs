use better_auth_core::{AuthError, AuthResult};

/// Worker v1 capabilities that are intentionally deferred until their runtime
/// support has real Worker/D1 evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WorkerDeferredCapability {
    ApiKey,
    Passkey,
    TwoFactor,
    Organization,
    DurableRateLimiting,
    DurableObjects,
}

impl WorkerDeferredCapability {
    pub fn label(self) -> &'static str {
        match self {
            Self::ApiKey => "api-key",
            Self::Passkey => "passkey",
            Self::TwoFactor => "two-factor",
            Self::Organization => "organization",
            Self::DurableRateLimiting => "durable rate limiting",
            Self::DurableObjects => "Durable Objects",
        }
    }
}

/// Password hashing strategy selected for Worker production config.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum WorkerPasswordHasherPolicy {
    #[default]
    Missing,
    Injected,
    WorkerValidatedBuiltin { benchmark_evidence: String },
}

/// Worker v1 config accepted by the adapter boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerV1Config {
    deferred_capabilities: Vec<WorkerDeferredCapability>,
    password_hasher: WorkerPasswordHasherPolicy,
}

impl WorkerV1Config {
    pub fn new() -> Self {
        Self {
            deferred_capabilities: Vec::new(),
            password_hasher: WorkerPasswordHasherPolicy::Missing,
        }
    }

    pub fn with_deferred_capability(mut self, capability: WorkerDeferredCapability) -> Self {
        self.deferred_capabilities.push(capability);
        self
    }

    pub fn with_injected_password_hasher(mut self) -> Self {
        self.password_hasher = WorkerPasswordHasherPolicy::Injected;
        self
    }

    pub fn with_worker_validated_builtin_hasher(
        mut self,
        benchmark_evidence: impl Into<String>,
    ) -> Self {
        self.password_hasher = WorkerPasswordHasherPolicy::WorkerValidatedBuiltin {
            benchmark_evidence: benchmark_evidence.into(),
        };
        self
    }

    pub fn deferred_capabilities(&self) -> &[WorkerDeferredCapability] {
        &self.deferred_capabilities
    }

    pub fn password_hasher(&self) -> &WorkerPasswordHasherPolicy {
        &self.password_hasher
    }

    pub fn validate(self) -> AuthResult<ValidatedWorkerV1Config> {
        validate_worker_v1_config(self)
    }
}

impl Default for WorkerV1Config {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedWorkerV1Config {
    config: WorkerV1Config,
}

impl ValidatedWorkerV1Config {
    pub fn deferred_capabilities(&self) -> &[WorkerDeferredCapability] {
        self.config.deferred_capabilities()
    }

    pub fn password_hasher(&self) -> &WorkerPasswordHasherPolicy {
        self.config.password_hasher()
    }
}

pub fn validate_worker_v1_config(config: WorkerV1Config) -> AuthResult<ValidatedWorkerV1Config> {
    if !config.deferred_capabilities.is_empty() {
        let labels = config
            .deferred_capabilities
            .iter()
            .map(|capability| capability.label())
            .collect::<Vec<_>>()
            .join(", ");

        return Err(AuthError::config(format!(
            "Worker v1 does not support deferred capabilities: {labels}"
        )));
    }

    match config.password_hasher() {
        WorkerPasswordHasherPolicy::Missing => Err(AuthError::config(
            "Worker production config requires an injected or Worker-validated password hasher",
        )),
        WorkerPasswordHasherPolicy::WorkerValidatedBuiltin { benchmark_evidence }
            if benchmark_evidence.trim().is_empty() =>
        {
            Err(AuthError::config(
                "Worker-validated password hasher requires benchmark evidence",
            ))
        }
        WorkerPasswordHasherPolicy::Injected
        | WorkerPasswordHasherPolicy::WorkerValidatedBuiltin { .. } => {
            Ok(ValidatedWorkerV1Config { config })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_v1_rejects_deferred_plugins() {
        let config = WorkerV1Config::new()
            .with_injected_password_hasher()
            .with_deferred_capability(WorkerDeferredCapability::ApiKey)
            .with_deferred_capability(WorkerDeferredCapability::Passkey)
            .with_deferred_capability(WorkerDeferredCapability::TwoFactor)
            .with_deferred_capability(WorkerDeferredCapability::Organization)
            .with_deferred_capability(WorkerDeferredCapability::DurableRateLimiting)
            .with_deferred_capability(WorkerDeferredCapability::DurableObjects);

        let err = validate_worker_v1_config(config).unwrap_err();
        let AuthError::Config(message) = err else {
            panic!("expected config error");
        };

        for label in [
            "api-key",
            "passkey",
            "two-factor",
            "organization",
            "durable rate limiting",
            "Durable Objects",
        ] {
            assert!(
                message.contains(label),
                "expected config error to mention {label}, got {message}"
            );
        }
    }

    #[test]
    fn worker_password_hashing_rejects_unsafe_defaults() {
        let err = WorkerV1Config::new().validate().unwrap_err();
        let AuthError::Config(message) = err else {
            panic!("expected config error");
        };

        assert!(message.contains("password hasher"));
        assert!(message.contains("injected"));
    }

    #[test]
    fn worker_v1_accepts_explicit_password_hasher_config() {
        let config = WorkerV1Config::new()
            .with_worker_validated_builtin_hasher("argon2id smoke p95 under local Worker budget");

        let validated = validate_worker_v1_config(config).unwrap();

        assert!(validated.deferred_capabilities().is_empty());
        assert!(matches!(
            validated.password_hasher(),
            WorkerPasswordHasherPolicy::WorkerValidatedBuiltin { .. }
        ));
    }
}
