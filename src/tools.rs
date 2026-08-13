//! rmcp tool router — three thin wrappers over `vault::VaultClient` plus
//! path validation against the optional allowlist.

use std::collections::BTreeMap;
use std::sync::Arc;

use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars, tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};

use crate::config::ConfigStore;
use crate::errors::KyttiError;
use crate::vault::{VaultClient, VaultStatus};

#[derive(Clone)]
pub struct Kytti {
    store: ConfigStore,
    client: Arc<VaultClient>,
    #[allow(dead_code)]
    tool_router: ToolRouter<Kytti>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetArgs {
    /// CLI-style KV v2 path under `secret/` — e.g. `infra/telegram`,
    /// `apps/cloudflare_dns`. No leading slash, no `secret/` prefix.
    pub path: String,
    /// Optional field name. When set, only that field's value is returned
    /// (the most common usage). Missing field → NotFound.
    #[serde(default)]
    pub field: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListArgs {
    /// CLI-style KV v2 folder path — e.g. `infra` lists every secret under
    /// `secret/infra/`. Empty string lists the root. Path that resolves to
    /// a leaf (an actual secret) returns NotFound.
    pub path: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct GetResult {
    /// Populated when `field` was supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Populated when `field` was omitted: the full key/value map at this
    /// path, with non-string values coerced to their JSON representation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ListResult {
    pub keys: Vec<String>,
}

impl Kytti {
    pub fn new(store: ConfigStore) -> Result<Self, KyttiError> {
        let client = Arc::new(VaultClient::new(store.clone())?);
        Ok(Self {
            store,
            client,
            tool_router: Self::tool_router(),
        })
    }

    fn validate_path(&self, path: &str) -> Result<String, KyttiError> {
        let trimmed = path.trim_matches('/');
        // Reject control chars / NUL outright.
        if trimmed.chars().any(|c| c.is_control() || c == '\0') {
            return Err(KyttiError::BadPath);
        }
        // Reject empty, ".", ".." segments. An empty trimmed string is OK
        // for `vault_list` (root listing), but check segments otherwise.
        if !trimmed.is_empty() {
            for seg in trimmed.split('/') {
                if seg.is_empty() || seg == "." || seg == ".." {
                    return Err(KyttiError::BadPath);
                }
            }
        }
        let allowlist = &self.store.snapshot().config.security.path_allowlist;
        if allowlist.is_empty() {
            return Ok(trimmed.to_string());
        }
        let allowed = allowlist.iter().any(|prefix| {
            let p = prefix.trim_matches('/');
            trimmed == p || trimmed.starts_with(&format!("{p}/"))
        });
        if !allowed {
            return Err(KyttiError::BadPath);
        }
        Ok(trimmed.to_string())
    }

    fn validate_get_path(&self, path: &str) -> Result<String, KyttiError> {
        // `vault_get` always needs a concrete path — empty doesn't
        // address a secret.
        let p = self.validate_path(path)?;
        if p.is_empty() {
            return Err(KyttiError::BadPath);
        }
        Ok(p)
    }
}

#[tool_router]
impl Kytti {
    #[tool(
        description = "Vault health probe. Hits /v1/sys/seal-status (no auth). Returns sealed (bool), initialized (bool), version (string), cluster_name (optional string). Use this before reads if you've just rebooted the host or to confirm whether a 503 from a read is going to keep happening."
    )]
    async fn vault_status(&self) -> Result<CallToolResult, McpError> {
        let res: Result<VaultStatus, KyttiError> = self.client.status().await;
        finish(res.map(|s| serde_json::to_value(s).unwrap_or_default()))
    }

    #[tool(
        description = "Read a Vault KV v2 secret. Path is CLI-style — e.g. \"infra/telegram\", \"apps/cloudflare_dns\" — with no leading slash and no \"secret/\" prefix (kytti adds the data/metadata segments). With `field` set, returns only that field's value as a plain string — the most common usage (replaces `vault kv get -field=… secret/<path>`). Without `field`, returns the full key/value map at the path. Errors: NotFound (path missing OR field missing), Forbidden (token policy), Sealed (vault unavailable)."
    )]
    async fn vault_get(
        &self,
        Parameters(args): Parameters<GetArgs>,
    ) -> Result<CallToolResult, McpError> {
        let res: Result<GetResult, KyttiError> = async {
            let path = self.validate_get_path(&args.path)?;
            let map = self.client.get(&path, args.field.as_deref()).await?;
            if let Some(name) = args.field.as_deref() {
                let value = map.get(name).cloned().ok_or(KyttiError::Internal(
                    "field selector lost value".to_string(),
                ))?;
                Ok(GetResult {
                    value: Some(value),
                    data: None,
                })
            } else {
                Ok(GetResult {
                    value: None,
                    data: Some(map),
                })
            }
        }
        .await;
        finish(res.map(|r| serde_json::to_value(r).unwrap_or_default()))
    }

    #[tool(
        description = "List the entries under a Vault KV v2 folder. Path is CLI-style — e.g. \"infra\" lists every secret under secret/infra/. Empty string lists the root. Folder names returned by Vault end in \"/\"; leaf secrets don't. A path that points to a leaf (an actual secret rather than a folder) returns NotFound — same as a missing folder, by design. Errors: NotFound, Forbidden, Sealed."
    )]
    async fn vault_list(
        &self,
        Parameters(args): Parameters<ListArgs>,
    ) -> Result<CallToolResult, McpError> {
        let res: Result<ListResult, KyttiError> = async {
            let path = self.validate_path(&args.path)?;
            let keys = self.client.list(&path).await?;
            Ok(ListResult { keys })
        }
        .await;
        finish(res.map(|r| serde_json::to_value(r).unwrap_or_default()))
    }
}

fn finish(res: Result<serde_json::Value, KyttiError>) -> Result<CallToolResult, McpError> {
    match res {
        Ok(v) => {
            let body = if let serde_json::Value::String(s) = &v {
                s.clone()
            } else {
                v.to_string()
            };
            Ok(CallToolResult::success(vec![ContentBlock::text(body)]))
        }
        Err(e) => Err(e.into()),
    }
}

#[tool_handler]
impl ServerHandler for Kytti {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_protocol_version(ProtocolVersion::V_2025_11_25)
            .with_instructions(
                "kytti — read-only HashiCorp Vault gateway. \
                 Tools: vault_status, vault_get, vault_list. \
                 Paths are CLI-style (e.g. \"infra/telegram\"), no leading slash, \
                 no \"secret/\" prefix — kytti adds the KV v2 data/metadata segments. \
                 vault_get with `field` returns just that field's value as a string \
                 (the common case); without `field` returns the full key/value map. \
                 vault_list on a leaf returns NotFound, same as a missing folder. \
                 Read-only by design — no put, no delete, no policy ops."
                    .to_string(),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ConfigStore, KyttiConfig, Loaded, SecuritySection, ServerSection, VaultSection,
    };
    use arc_swap::ArcSwap;
    use std::path::PathBuf;

    fn make_kytti(allowlist: Vec<String>) -> Kytti {
        let loaded = Loaded {
            config: KyttiConfig {
                vault: VaultSection {
                    addr: "http://127.0.0.1:8200".into(),
                    token_path: PathBuf::from("/dev/null"),
                },
                server: ServerSection::default(),
                security: SecuritySection {
                    path_allowlist: allowlist,
                },
            },
            token: "test-token".into(),
        };
        let store = ConfigStore::for_tests(Arc::new(ArcSwap::from_pointee(loaded)));
        Kytti::new(store).expect("client builds")
    }

    #[test]
    fn validation_rejects_traversal() {
        let k = make_kytti(vec![]);
        assert!(matches!(
            k.validate_path("foo/../bar"),
            Err(KyttiError::BadPath)
        ));
        assert!(matches!(k.validate_path("./bar"), Err(KyttiError::BadPath)));
        assert!(matches!(
            k.validate_path("foo//bar"),
            Err(KyttiError::BadPath)
        ));
    }

    #[test]
    fn validation_strips_outer_slashes() {
        let k = make_kytti(vec![]);
        assert_eq!(
            k.validate_path("/infra/telegram/").unwrap(),
            "infra/telegram"
        );
        assert_eq!(k.validate_path("infra").unwrap(), "infra");
    }

    #[test]
    fn validation_rejects_control_chars() {
        let k = make_kytti(vec![]);
        assert!(matches!(
            k.validate_path("foo\nbar"),
            Err(KyttiError::BadPath)
        ));
        assert!(matches!(
            k.validate_path("foo\0bar"),
            Err(KyttiError::BadPath)
        ));
    }

    #[test]
    fn validation_empty_allowlist_accepts_anything() {
        let k = make_kytti(vec![]);
        assert!(k.validate_path("anywhere/at/all").is_ok());
        assert!(k.validate_path("").is_ok(), "empty ok for list root");
    }

    #[test]
    fn validation_with_allowlist_accepts_prefix_match() {
        let k = make_kytti(vec!["infra".into(), "apps/foo".into()]);
        assert!(k.validate_path("infra").is_ok());
        assert!(k.validate_path("infra/telegram").is_ok());
        assert!(k.validate_path("apps/foo").is_ok());
        assert!(k.validate_path("apps/foo/bar").is_ok());
    }

    #[test]
    fn validation_with_allowlist_rejects_non_match() {
        let k = make_kytti(vec!["infra".into()]);
        assert!(matches!(
            k.validate_path("apps/foo"),
            Err(KyttiError::BadPath)
        ));
        // Prefix must be on a path-segment boundary — "infra-secret" must
        // NOT match prefix "infra".
        assert!(matches!(
            k.validate_path("infra-secret"),
            Err(KyttiError::BadPath)
        ));
    }

    #[test]
    fn validate_get_path_rejects_empty() {
        let k = make_kytti(vec![]);
        assert!(matches!(k.validate_get_path(""), Err(KyttiError::BadPath)));
        assert!(matches!(k.validate_get_path("/"), Err(KyttiError::BadPath)));
    }
}
