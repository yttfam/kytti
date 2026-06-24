//! Vault HTTP client — three calls (status / get / list), pure-function
//! parsers tested in isolation, and a single typed error mapper.
//!
//! KV v2 path scheme: the CLI hides the `data`/`metadata` segment.
//!   `vault kv get  secret/<path>`  → `GET    /v1/secret/data/<path>`
//!   `vault kv list secret/<path>`  → `LIST   /v1/secret/metadata/<path>`
//! Read responses wrap the user's k/v map under `.data.data`. List
//! responses put folder names under `.data.keys`. List on a leaf (a path
//! that's actually a secret) returns 404 — same as a missing folder.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Method;
use serde::Serialize;
use serde_json::Value;

use crate::config::ConfigStore;
use crate::errors::KyttiError;

#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct VaultStatus {
    pub sealed: bool,
    pub initialized: bool,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_name: Option<String>,
}

pub struct VaultClient {
    http: reqwest::Client,
    store: ConfigStore,
}

impl VaultClient {
    pub fn new(store: ConfigStore) -> Result<Self, KyttiError> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| KyttiError::Internal(format!("http client build: {e}")))?;
        Ok(Self { http, store })
    }

    fn snapshot(&self) -> Arc<crate::config::Loaded> {
        self.store.snapshot()
    }

    pub async fn status(&self) -> Result<VaultStatus, KyttiError> {
        let snap = self.snapshot();
        let url = status_url(&snap.config.vault.addr);
        let resp = self.http.get(url).send().await?;
        let status = resp.status();
        if !status.is_success() {
            // seal-status itself failing is a transport/internal problem —
            // the endpoint replies 200 even on a sealed vault.
            return Err(KyttiError::Internal(format!(
                "seal-status returned {}",
                status.as_u16()
            )));
        }
        let body: Value = resp.json().await.map_err(KyttiError::from)?;
        parse_status_response(&body)
    }

    pub async fn get(
        &self,
        path: &str,
        field: Option<&str>,
    ) -> Result<BTreeMap<String, String>, KyttiError> {
        let snap = self.snapshot();
        let url = read_url(&snap.config.vault.addr, path);
        let resp = self
            .http
            .request(Method::GET, url)
            .header("X-Vault-Token", &snap.token)
            .send()
            .await?;
        let body = collect_body(resp).await?;
        let mut data = parse_get_response(&body)?;
        if let Some(name) = field {
            let value = data.remove(name).ok_or(KyttiError::NotFound)?;
            let mut out = BTreeMap::new();
            out.insert(name.to_string(), value);
            Ok(out)
        } else {
            Ok(data)
        }
    }

    /// Renew the token kytti is currently holding via `auth/token/renew-self`.
    /// Returns the new TTL in seconds. The token string itself is unchanged —
    /// no store update needed.
    pub async fn renew_self(&self) -> Result<u64, KyttiError> {
        let snap = self.snapshot();
        let url = renew_url(&snap.config.vault.addr);
        let resp = self
            .http
            .post(&url)
            .header("X-Vault-Token", &snap.token)
            .send()
            .await?;
        let body = collect_body(resp).await?;
        let ttl = body
            .get("auth")
            .and_then(|a| a.get("lease_duration"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        Ok(ttl)
    }

    pub async fn list(&self, path: &str) -> Result<Vec<String>, KyttiError> {
        let snap = self.snapshot();
        let url = list_url(&snap.config.vault.addr, path);
        // KV v2 list uses the LIST verb (some servers also accept
        // `?list=true`). reqwest exposes Method::from_bytes for arbitrary
        // verbs, which Vault honours.
        let method = Method::from_bytes(b"LIST")
            .map_err(|e| KyttiError::Internal(format!("bad method: {e}")))?;
        let resp = self
            .http
            .request(method, url)
            .header("X-Vault-Token", &snap.token)
            .send()
            .await?;
        let body = collect_body(resp).await?;
        parse_list_response(&body)
    }
}

/// Drain a vault response into a parsed JSON `Value`, mapping HTTP status to
/// `KyttiError` first. Body is read only on 2xx (so we never try to JSON-
/// decode an HTML error page).
async fn collect_body(resp: reqwest::Response) -> Result<Value, KyttiError> {
    let status = resp.status().as_u16();
    if status == 200 {
        return resp.json().await.map_err(KyttiError::from);
    }
    // Try to peek at the body for the sealed-flag check; vault returns JSON
    // for nearly every error too. Best-effort — if it's not JSON, fall back
    // to status-only mapping.
    let body: Option<Value> = resp.json().await.ok();
    Err(map_status_code(status, body.as_ref()))
}

pub fn map_status_code(status: u16, body: Option<&Value>) -> KyttiError {
    match status {
        403 => KyttiError::Forbidden,
        404 => KyttiError::NotFound,
        503 => {
            let sealed = body
                .and_then(|b| b.get("sealed"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if sealed {
                KyttiError::Sealed { will_retry: true }
            } else {
                KyttiError::Internal("vault unavailable".to_string())
            }
        }
        s if (500..=599).contains(&s) => KyttiError::Internal(format!("vault returned {s}")),
        s if (400..=499).contains(&s) => KyttiError::Internal("vault rejected request".to_string()),
        s => KyttiError::Internal(format!("vault returned {s}")),
    }
}

pub fn renew_url(addr: &str) -> String {
    format!("{}/v1/auth/token/renew-self", addr.trim_end_matches('/'))
}

pub fn read_url(addr: &str, path: &str) -> String {
    format!(
        "{}/v1/secret/data/{}",
        addr.trim_end_matches('/'),
        path.trim_matches('/')
    )
}

pub fn list_url(addr: &str, path: &str) -> String {
    format!(
        "{}/v1/secret/metadata/{}",
        addr.trim_end_matches('/'),
        path.trim_matches('/')
    )
}

pub fn status_url(addr: &str) -> String {
    format!("{}/v1/sys/seal-status", addr.trim_end_matches('/'))
}

pub fn parse_status_response(body: &Value) -> Result<VaultStatus, KyttiError> {
    let sealed = body
        .get("sealed")
        .and_then(Value::as_bool)
        .ok_or_else(|| KyttiError::Internal("vault response malformed".to_string()))?;
    let initialized = body
        .get("initialized")
        .and_then(Value::as_bool)
        .ok_or_else(|| KyttiError::Internal("vault response malformed".to_string()))?;
    let version = body
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let cluster_name = body
        .get("cluster_name")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    Ok(VaultStatus {
        sealed,
        initialized,
        version,
        cluster_name,
    })
}

/// Extract `.data.data` from a KV v2 read and coerce each value to a string
/// (option A from the spec — the documented schema is `Map<String,String>`).
pub fn parse_get_response(body: &Value) -> Result<BTreeMap<String, String>, KyttiError> {
    let inner = body
        .get("data")
        .and_then(|v| v.get("data"))
        .and_then(Value::as_object)
        .ok_or_else(|| KyttiError::Internal("vault response malformed".to_string()))?;
    let mut out = BTreeMap::new();
    for (k, v) in inner {
        out.insert(k.clone(), coerce_value(v));
    }
    Ok(out)
}

pub fn parse_list_response(body: &Value) -> Result<Vec<String>, KyttiError> {
    let keys = body
        .get("data")
        .and_then(|v| v.get("keys"))
        .and_then(Value::as_array)
        .ok_or_else(|| KyttiError::Internal("vault response malformed".to_string()))?;
    let mut out = Vec::with_capacity(keys.len());
    for k in keys {
        match k.as_str() {
            Some(s) => out.push(s.to_string()),
            None => return Err(KyttiError::Internal("vault response malformed".to_string())),
        }
    }
    Ok(out)
}

fn coerce_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn url_builders_handle_trailing_slashes() {
        assert_eq!(
            read_url("http://10.10.0.3:8200/", "infra/telegram"),
            "http://10.10.0.3:8200/v1/secret/data/infra/telegram"
        );
        assert_eq!(
            read_url("http://10.10.0.3:8200", "/infra/telegram/"),
            "http://10.10.0.3:8200/v1/secret/data/infra/telegram"
        );
        assert_eq!(
            list_url("http://10.10.0.3:8200", "infra"),
            "http://10.10.0.3:8200/v1/secret/metadata/infra"
        );
        assert_eq!(
            status_url("http://10.10.0.3:8200/"),
            "http://10.10.0.3:8200/v1/sys/seal-status"
        );
    }

    #[test]
    fn parses_unsealed_status() {
        let body = json!({
            "sealed": false,
            "initialized": true,
            "version": "1.21.4",
            "cluster_name": "vault-cluster-x"
        });
        let s = parse_status_response(&body).unwrap();
        assert!(!s.sealed);
        assert!(s.initialized);
        assert_eq!(s.version, "1.21.4");
        assert_eq!(s.cluster_name.as_deref(), Some("vault-cluster-x"));
    }

    #[test]
    fn parses_sealed_status_without_cluster_name() {
        let body = json!({
            "sealed": true,
            "initialized": true,
            "version": "1.21.4",
        });
        let s = parse_status_response(&body).unwrap();
        assert!(s.sealed);
        assert!(s.initialized);
        assert!(s.cluster_name.is_none());
    }

    #[test]
    fn parses_get_response_extracts_data_data() {
        let body = json!({
            "data": {
                "data": { "lou_bot": "abc", "main": "xyz" },
                "metadata": { "version": 3 }
            }
        });
        let map = parse_get_response(&body).unwrap();
        assert_eq!(map.get("lou_bot"), Some(&"abc".to_string()));
        assert_eq!(map.get("main"), Some(&"xyz".to_string()));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn parses_get_coerces_non_string_values() {
        let body = json!({
            "data": {
                "data": { "n": 42, "b": true, "obj": { "x": 1 } },
                "metadata": {}
            }
        });
        let map = parse_get_response(&body).unwrap();
        assert_eq!(map.get("n"), Some(&"42".to_string()));
        assert_eq!(map.get("b"), Some(&"true".to_string()));
        assert_eq!(map.get("obj"), Some(&"{\"x\":1}".to_string()));
    }

    #[test]
    fn get_field_selector_returns_only_named_field() {
        // emulate the field-selector slice from VaultClient::get
        let body = json!({"data":{"data":{"lou_bot":"abc","main":"xyz"},"metadata":{}}});
        let mut data = parse_get_response(&body).unwrap();
        let v = data.remove("lou_bot").unwrap();
        assert_eq!(v, "abc");
    }

    #[test]
    fn get_missing_field_is_not_found() {
        let body = json!({"data":{"data":{"a":"1"},"metadata":{}}});
        let mut data = parse_get_response(&body).unwrap();
        assert!(data.remove("nope").is_none(), "missing field → NotFound");
    }

    #[test]
    fn parses_list_response_keys() {
        let body = json!({
            "data": { "keys": ["default", "telegram", "opnsense"] }
        });
        let keys = parse_list_response(&body).unwrap();
        assert_eq!(keys, vec!["default", "telegram", "opnsense"]);
    }

    #[test]
    fn malformed_get_response_is_internal_error() {
        let body = json!({"unexpected": "shape"});
        let e = parse_get_response(&body).unwrap_err();
        assert_eq!(e.kind(), "Internal");
    }

    #[test]
    fn map_404_to_not_found() {
        assert!(matches!(map_status_code(404, None), KyttiError::NotFound));
    }

    #[test]
    fn map_403_to_forbidden() {
        assert!(matches!(map_status_code(403, None), KyttiError::Forbidden));
    }

    #[test]
    fn map_503_with_sealed_flag_to_sealed() {
        let body = json!({"sealed": true});
        let e = map_status_code(503, Some(&body));
        match e {
            KyttiError::Sealed { will_retry } => assert!(will_retry),
            other => panic!("expected Sealed, got {other:?}"),
        }
    }

    #[test]
    fn map_503_without_sealed_flag_to_internal() {
        let e = map_status_code(503, None);
        assert_eq!(e.kind(), "Internal");
    }

    #[test]
    fn list_on_leaf_returns_not_found() {
        // Vault returns 404 for LIST against a path that is a secret (leaf),
        // not a folder. We map it the same way as a missing folder — the
        // caller can't tell the difference and shouldn't have to.
        let e = map_status_code(404, None);
        assert!(matches!(e, KyttiError::NotFound));
    }
}
