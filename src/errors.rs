//! Typed errors surfaced to MCP callers.
//!
//! Display strings deliberately omit the secret path, the token, the bearer
//! header value, and the full URL. The caller already knows the path; echoing
//! it back risks leaking it into client-side logs.

use rmcp::ErrorData as McpError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KyttiError {
    #[error("vault returned NotFound")]
    NotFound,

    #[error("vault returned Forbidden — check token policy")]
    Forbidden,

    #[error("vault is sealed")]
    Sealed { will_retry: bool },

    #[error("path not allowed by policy")]
    BadPath,

    #[error("vault network error: {0}")]
    Network(String),

    #[error("vault internal error: {0}")]
    Internal(String),
}

impl KyttiError {
    /// Stable string tag for the variant — surfaced in the MCP error `data`
    /// payload so clients can branch on it.
    pub fn kind(&self) -> &'static str {
        match self {
            KyttiError::NotFound => "NotFound",
            KyttiError::Forbidden => "Forbidden",
            KyttiError::Sealed { .. } => "Sealed",
            KyttiError::BadPath => "BadPath",
            KyttiError::Network(_) => "Network",
            KyttiError::Internal(_) => "Internal",
        }
    }
}

impl From<KyttiError> for McpError {
    fn from(err: KyttiError) -> Self {
        let data = match &err {
            KyttiError::Sealed { will_retry } => {
                serde_json::json!({ "kind": err.kind(), "will_retry": will_retry })
            }
            _ => serde_json::json!({ "kind": err.kind() }),
        };
        let msg = err.to_string();
        match err {
            KyttiError::NotFound => McpError::resource_not_found(msg, Some(data)),
            KyttiError::Forbidden => McpError::invalid_request(msg, Some(data)),
            KyttiError::BadPath => McpError::invalid_params(msg, Some(data)),
            KyttiError::Sealed { .. } | KyttiError::Network(_) | KyttiError::Internal(_) => {
                McpError::internal_error(msg, Some(data))
            }
        }
    }
}

impl From<reqwest::Error> for KyttiError {
    fn from(e: reqwest::Error) -> Self {
        // Keep messages short and free of URL/token info. reqwest's Display
        // sometimes includes the URL for builder errors, so we summarise.
        let msg = if e.is_timeout() {
            "timeout".to_string()
        } else if e.is_connect() {
            "connect failed".to_string()
        } else if e.is_decode() {
            return KyttiError::Internal("vault response malformed".to_string());
        } else if e.is_request() {
            "request failed".to_string()
        } else {
            "transport error".to_string()
        };
        KyttiError::Network(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variant_tags_are_stable() {
        assert_eq!(KyttiError::NotFound.kind(), "NotFound");
        assert_eq!(KyttiError::Forbidden.kind(), "Forbidden");
        assert_eq!(KyttiError::Sealed { will_retry: true }.kind(), "Sealed");
        assert_eq!(KyttiError::BadPath.kind(), "BadPath");
        assert_eq!(KyttiError::Network("x".into()).kind(), "Network");
        assert_eq!(KyttiError::Internal("x".into()).kind(), "Internal");
    }

    #[test]
    fn display_does_not_leak_path_or_token() {
        let cases = [
            KyttiError::NotFound.to_string(),
            KyttiError::Forbidden.to_string(),
            KyttiError::Sealed { will_retry: true }.to_string(),
            KyttiError::BadPath.to_string(),
            KyttiError::Network("connect failed".into()).to_string(),
        ];
        for s in cases {
            assert!(!s.contains("X-Vault-Token"));
            assert!(!s.contains("hvs."));
            assert!(!s.contains("/v1/secret/"));
        }
    }

    #[test]
    fn into_mcp_error_carries_kind() {
        let mcp: McpError = KyttiError::NotFound.into();
        let data = mcp.data.expect("data populated");
        assert_eq!(data["kind"], "NotFound");
    }

    #[test]
    fn sealed_carries_will_retry() {
        let mcp: McpError = KyttiError::Sealed { will_retry: true }.into();
        let data = mcp.data.expect("data populated");
        assert_eq!(data["kind"], "Sealed");
        assert_eq!(data["will_retry"], true);
    }
}
