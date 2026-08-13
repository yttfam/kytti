//! kytti — read-only Vault gateway MCP. v0.1: status / get / list.
//!
//! Bootstrap mirrors prompto: env config path, tracing init, SIGHUP-driven
//! arc-swap reload, streamable-http on `/mcp` (or stdio with `--stdio`).

mod config;
mod errors;
mod tools;
mod vault;

use anyhow::{Context, Result};
use config::ConfigStore;
use rmcp::{
    ServiceExt,
    transport::{
        stdio,
        streamable_http_server::{
            StreamableHttpServerConfig, StreamableHttpService,
            session::local::LocalSessionManager,
        },
    },
};
use tokio_util::sync::CancellationToken;
use tools::Kytti;
use tracing_subscriber::EnvFilter;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("kytti=info")),
        )
        .with_writer(std::io::stderr)
        .compact()
        .init();
}

fn print_help() {
    eprintln!(
        "kytti {} — read-only Vault gateway over MCP
Usage:
  kytti                       Serve MCP over Streamable HTTP at POST /mcp
  kytti --stdio               Serve MCP over stdio (for local Claude Code)
  kytti --help                Show this message
  kytti --version             Print version and exit

Environment:
  KYTTI_CONFIG               (default /etc/kytti/config.toml)
  KYTTI_BIND                 (overrides [server] bind from the toml)
  KYTTI_ALLOWED_HOSTS        (default localhost,127.0.0.1,::1 — set to \"*\" to disable)
  RUST_LOG                   (default kytti=info)
",
        env!("CARGO_PKG_VERSION")
    );
}

fn spawn_token_renewer(store: ConfigStore) {
    use tokio::time::{Duration, sleep};
    tokio::spawn(async move {
        // Renew every 24 h — well within the 768 h period. On failure we log
        // and retry next cycle rather than crashing; a single missed renewal
        // is harmless given the long period.
        let interval = Duration::from_secs(24 * 3600);
        loop {
            sleep(interval).await;
            let client = match vault::VaultClient::new(store.clone()) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(?e, "token renewer: failed to build vault client");
                    continue;
                }
            };
            match client.renew_self().await {
                Ok(ttl) => tracing::info!(ttl_secs = ttl, "vault token renewed"),
                Err(e) => tracing::error!(?e, "vault token renewal failed — will retry in 24 h"),
            }
        }
    });
}

#[cfg(unix)]
fn spawn_sighup_reloader(store: ConfigStore) {
    use tokio::signal::unix::{SignalKind, signal};
    tokio::spawn(async move {
        let mut sig = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(?e, "failed to install SIGHUP handler — reloads disabled");
                return;
            }
        };
        while sig.recv().await.is_some() {
            match store.reload() {
                Ok(()) => tracing::info!("config + token reloaded on SIGHUP"),
                Err(e) => tracing::error!(?e, "reload failed — keeping previous"),
            }
        }
    });
}

#[cfg(not(unix))]
fn spawn_sighup_reloader(_: ConfigStore) {}

#[tokio::main]
async fn main() -> Result<()> {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    match raw_args.first().map(String::as_str) {
        Some("--help" | "-h") => {
            print_help();
            return Ok(());
        }
        Some("--version" | "-V") => {
            println!("kytti {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        _ => {}
    }

    init_tracing();

    let cfg_path = env_or("KYTTI_CONFIG", "/etc/kytti/config.toml");
    let store = ConfigStore::load_from(cfg_path.clone().into())
        .with_context(|| format!("loading kytti config from {cfg_path}"))?;
    tracing::info!(path = %store.path().display(), "config + token loaded");
    spawn_sighup_reloader(store.clone());
    spawn_token_renewer(store.clone());

    let stdio_mode = raw_args.iter().any(|a| a == "--stdio");
    if stdio_mode {
        tracing::info!("transport: stdio");
        let kytti = Kytti::new(store.clone()).context("build kytti tool router")?;
        let service = kytti.serve(stdio()).await.context("stdio serve")?;
        service.waiting().await?;
        return Ok(());
    }

    // env wins over toml for the bind, per locked decision #5.
    let bind =
        std::env::var("KYTTI_BIND").unwrap_or_else(|_| store.snapshot().config.server.bind.clone());
    tracing::info!(%bind, "transport: streamable-http");

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("bind {bind}"))?;
    let cancel = CancellationToken::new();

    let mut http_config = StreamableHttpServerConfig::default()
        .with_cancellation_token(cancel.child_token())
        // Sessionless mode: kytti has no per-session state, every request is
        // independently handled. Eliminates the redeploy-404 class entirely
        // and aligns with the MCP 2026-07-28 stateless path. Legacy clients
        // (2025-03-26 / 2025-11-25) are still served — protocol negotiation
        // happens per-request, no initialize handshake required.
        .with_legacy_session_mode(false);
    match std::env::var("KYTTI_ALLOWED_HOSTS") {
        Ok(raw) if raw.trim() == "*" => {
            tracing::warn!(
                "KYTTI_ALLOWED_HOSTS=* — DNS rebinding protection DISABLED. Ensure the listener is behind a trusted firewall."
            );
            http_config = http_config.disable_allowed_hosts();
        }
        Ok(raw) => {
            let hosts: Vec<String> = raw
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            tracing::info!(?hosts, "Host header allowlist");
            http_config = http_config.with_allowed_hosts(hosts);
        }
        Err(_) => {
            tracing::info!(
                "Host header allowlist defaults to localhost — set KYTTI_ALLOWED_HOSTS to accept remote clients."
            );
        }
    }

    let store_for_factory = store.clone();
    let service = StreamableHttpService::new(
        move || {
            Kytti::new(store_for_factory.clone()).map_err(|e| std::io::Error::other(e.to_string()))
        },
        LocalSessionManager::default().into(),
        http_config,
    );

    let app = axum::Router::new().nest_service("/mcp", service);

    let cancel_for_signal = cancel.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        cancel_for_signal.cancel();
    });

    axum::serve(listener, app)
        .with_graceful_shutdown(async move { cancel.cancelled().await })
        .await
        .context("http serve")?;

    Ok(())
}
