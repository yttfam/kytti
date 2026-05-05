//! TOML config + token-file load, atomically swappable via SIGHUP.

use anyhow::{Context, Result, bail};
use arc_swap::ArcSwap;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Debug, Deserialize)]
pub struct VaultSection {
    pub addr: String,
    pub token_path: PathBuf,
}

fn default_bind() -> String {
    "0.0.0.0:6339".to_string()
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerSection {
    #[serde(default = "default_bind")]
    pub bind: String,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            bind: default_bind(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct SecuritySection {
    /// CLI-style path prefixes (no leading `secret/`, no leading slash).
    /// Empty = trust the token's policy.
    #[serde(default)]
    pub path_allowlist: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct KyttiConfig {
    pub vault: VaultSection,
    #[serde(default)]
    pub server: ServerSection,
    #[serde(default)]
    pub security: SecuritySection,
}

impl KyttiConfig {
    pub fn from_toml_str(s: &str) -> Result<Self> {
        let cfg: KyttiConfig = toml::from_str(s).context("parse kytti config")?;
        if cfg.vault.addr.trim().is_empty() {
            bail!("vault.addr is empty");
        }
        if cfg.vault.token_path.as_os_str().is_empty() {
            bail!("vault.token_path is empty");
        }
        Ok(cfg)
    }
}

/// One coherent snapshot: parsed config + the token loaded from disk.
#[derive(Clone, Debug)]
pub struct Loaded {
    pub config: KyttiConfig,
    pub token: String,
}

impl Loaded {
    fn from_path(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read kytti config {}", path.display()))?;
        let config = KyttiConfig::from_toml_str(&raw)?;
        let token = std::fs::read_to_string(&config.vault.token_path)
            .with_context(|| format!("read vault token {}", config.vault.token_path.display()))?
            .trim()
            .to_string();
        if token.is_empty() {
            bail!(
                "vault token at {} is empty",
                config.vault.token_path.display()
            );
        }
        Ok(Loaded { config, token })
    }
}

/// Atomically-swappable wrapper around `Loaded`. SIGHUP rebuilds it from the
/// configured path; in-flight handlers keep using the old `Arc` until they
/// drop it.
#[derive(Clone)]
pub struct ConfigStore {
    inner: Arc<ArcSwap<Loaded>>,
    path: PathBuf,
}

impl ConfigStore {
    pub fn load_from(path: PathBuf) -> Result<Self> {
        let loaded = Loaded::from_path(&path)?;
        Ok(Self {
            inner: Arc::new(ArcSwap::from_pointee(loaded)),
            path,
        })
    }

    pub fn snapshot(&self) -> Arc<Loaded> {
        self.inner.load_full()
    }

    pub fn reload(&self) -> Result<()> {
        let new = Loaded::from_path(&self.path)?;
        self.inner.store(Arc::new(new));
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(test)]
    pub(crate) fn for_tests(inner: Arc<ArcSwap<Loaded>>) -> Self {
        Self {
            inner,
            path: PathBuf::from("/dev/null"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn parses_full_config() {
        let s = r#"
[vault]
addr = "http://10.10.0.3:8200"
token_path = "/etc/kytti/token"

[server]
bind = "0.0.0.0:6339"

[security]
path_allowlist = ["infra", "apps/foo"]
"#;
        let cfg = KyttiConfig::from_toml_str(s).unwrap();
        assert_eq!(cfg.vault.addr, "http://10.10.0.3:8200");
        assert_eq!(cfg.server.bind, "0.0.0.0:6339");
        assert_eq!(cfg.security.path_allowlist, vec!["infra", "apps/foo"]);
    }

    #[test]
    fn defaults_apply_to_optional_sections() {
        let s = r#"
[vault]
addr = "http://127.0.0.1:8200"
token_path = "/tmp/t"
"#;
        let cfg = KyttiConfig::from_toml_str(s).unwrap();
        assert_eq!(cfg.server.bind, "0.0.0.0:6339");
        assert!(cfg.security.path_allowlist.is_empty());
    }

    #[test]
    fn rejects_empty_addr() {
        let s = r#"
[vault]
addr = ""
token_path = "/tmp/t"
"#;
        assert!(KyttiConfig::from_toml_str(s).is_err());
    }

    #[test]
    fn loaded_reads_token_from_disk() {
        let mut tok = NamedTempFile::new().unwrap();
        writeln!(tok, "hvs.exampletoken").unwrap();
        let mut cfg = NamedTempFile::new().unwrap();
        writeln!(
            cfg,
            r#"
[vault]
addr = "http://127.0.0.1:8200"
token_path = "{}"
"#,
            tok.path().display()
        )
        .unwrap();
        let loaded = Loaded::from_path(cfg.path()).unwrap();
        assert_eq!(loaded.token, "hvs.exampletoken");
        assert_eq!(loaded.config.vault.addr, "http://127.0.0.1:8200");
    }

    #[test]
    fn loaded_rejects_empty_token_file() {
        let tok = NamedTempFile::new().unwrap();
        let mut cfg = NamedTempFile::new().unwrap();
        writeln!(
            cfg,
            r#"
[vault]
addr = "http://127.0.0.1:8200"
token_path = "{}"
"#,
            tok.path().display()
        )
        .unwrap();
        assert!(Loaded::from_path(cfg.path()).is_err());
    }

    #[test]
    fn store_reload_picks_up_token_change() {
        let mut tok = NamedTempFile::new().unwrap();
        writeln!(tok, "first").unwrap();
        let mut cfg = NamedTempFile::new().unwrap();
        writeln!(
            cfg,
            r#"
[vault]
addr = "http://127.0.0.1:8200"
token_path = "{}"
"#,
            tok.path().display()
        )
        .unwrap();
        let store = ConfigStore::load_from(cfg.path().to_path_buf()).unwrap();
        assert_eq!(store.snapshot().token, "first");
        std::fs::write(tok.path(), "second\n").unwrap();
        store.reload().unwrap();
        assert_eq!(store.snapshot().token, "second");
    }
}
