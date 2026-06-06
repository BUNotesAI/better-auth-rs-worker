#[cfg(not(feature = "native-id"))]
use crate::error::AuthError;
use crate::error::AuthResult;

#[cfg(feature = "native-id")]
pub(crate) fn new_optional_uuid_v4_string() -> Option<String> {
    Some(uuid::Uuid::new_v4().to_string())
}

#[cfg(not(feature = "native-id"))]
pub(crate) fn new_optional_uuid_v4_string() -> Option<String> {
    None
}

#[cfg(feature = "native-id")]
pub(crate) fn new_required_id(_kind: &str) -> AuthResult<String> {
    Ok(uuid::Uuid::new_v4().to_string())
}

#[cfg(not(feature = "native-id"))]
pub(crate) fn new_required_id(kind: &str) -> AuthResult<String> {
    Err(AuthError::config(format!(
        "Native {kind} ID generation requires the `native-id` feature or an injected ID generator"
    )))
}

pub(crate) fn supplied_or_generated_id(id: Option<String>, kind: &str) -> AuthResult<String> {
    match id {
        Some(id) => Ok(id),
        None => new_required_id(kind),
    }
}

pub(crate) fn new_session_token() -> AuthResult<String> {
    Ok(format!("session_{}", new_required_id("session token")?))
}
