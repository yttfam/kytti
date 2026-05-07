<p align="center"><img src="assets/logo.png" alt="kytti" width="180"/></p>

# kytti

Read-only HashiCorp Vault gateway exposed as an MCP server. Three typed tools so any [Claude Code](https://claude.ai/code) (or other MCP client) session can pull credentials from Vault without re-implementing `curl -H "X-Vault-Token: …" /v1/secret/data/<path> | jq -r .data.data.<field>` boilerplate every time.

> *"Now is the time of value."*
> — also Bruno Bucciarati, but he was talking about money

YTT-family sibling of [bucciarati](https://github.com/calibrae/bucciarati), [prompto](https://github.com/calibrae/prompto), [palazzo](https://github.com/calibrae/palazzo). Same Rust + [rmcp](https://github.com/modelcontextprotocol/rust-sdk) + axum + streamable-http stack.

## Why

Every agent in the homelab needs the same handful of secrets — a Telegram token here, a Cloudflare DNS key there. The options before kytti:

1. **Hardcode the Vault token in every agent's env** — fine if you trust the LAN, but scattered.
2. **Make every tool reimplement KV v2 path mapping** (`secret/foo` in CLI = `secret/data/foo` over HTTP, `secret/metadata/foo` for list) — tedious and a frequent source of off-by-one bugs.
3. **Hand the agent a root token** — no.

kytti centralises the token (one periodic `agent-read` token, file-mode 0640) and exposes three small, typed tools. Agents call `vault_get path=infra/telegram field=lou_bot` and get back a string. That's it.

## Tools

| Tool | Purpose |
|---|---|
| `vault_status` | Health probe. Hits `/v1/sys/seal-status` (no auth). Returns `sealed`, `initialized`, `version`, optional `cluster_name`. |
| `vault_get` | Read a KV v2 secret. Path is CLI-style. With `field`, returns the single value as a string (the common case). Without `field`, returns the full key/value map. |
| `vault_list` | List entries under a KV v2 folder. CLI-style path; root listing on empty string. Leaf paths return `NotFound`, same as missing folders. |

Read-only by design. No `vault_put`, no `vault_delete`, no policy ops. Those need root and stay manual.

## Trust model

kytti is a fixed-token reverse proxy, **not** a per-caller auth gateway. Whoever can reach `:6339` gets the authority of the token kytti holds. Bind it to a trusted LAN.

The token kytti expects is bound to the `agent-read` policy:

```
path "secret/data/*"     { capabilities = ["read"] }
path "secret/metadata/*" { capabilities = ["read", "list"] }
```

That's all. A compromised kytti can't write, can't delete, can't escalate.

## Quickstart (dev)

```bash
cargo build --release
KYTTI_CONFIG=/path/to/config.toml ./target/release/kytti --stdio
```

For HTTP transport (default):

```bash
KYTTI_CONFIG=/path/to/config.toml ./target/release/kytti
# listens on 0.0.0.0:6339 — POST /mcp
```

Minimal `config.toml`:

```toml
[vault]
addr = "http://10.10.0.3:8200"
token_path = "/etc/kytti/token"

[server]
bind = "0.0.0.0:6339"

[security]
path_allowlist = []   # empty = trust the token's policy
```

The token file is the bare bearer token (e.g. `hvs.CAES…`), no quotes, no header. kytti reads it once at startup; SIGHUP re-reads it.

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `KYTTI_CONFIG` | `/etc/kytti/config.toml` | Path to the TOML config |
| `KYTTI_BIND` | (from `[server] bind`) | HTTP listen address. Env wins over the toml. |
| `KYTTI_ALLOWED_HOSTS` | `localhost,127.0.0.1,::1` | Host-header allowlist (DNS-rebinding protection). Set to `*` to disable on a trusted LAN. |
| `RUST_LOG` | `kytti=info` | Log level |

CLI flags: `--stdio` for stdio transport, `--version`, `--help`.

Reload: `kill -HUP $(pidof kytti)` re-reads both the toml and the token file. In-flight requests keep using the old config until they drop it (arc-swap).

## Path validation

`config.toml`'s `[security] path_allowlist` is empty by default — kytti trusts whatever the token's policy permits. To layer a CLI-style prefix allowlist on top:

```toml
[security]
path_allowlist = ["infra", "apps/foo"]
```

Then `vault_get path=infra/telegram` succeeds, `vault_get path=secrets-i-shouldnt-see` is rejected with `BadPath` before any HTTP call. Prefix matching is path-segment-aware: `infra` matches `infra` and `infra/anything`, but **not** `infra-secret`.

`..`, `.`, double-slash, control chars, NUL — all rejected unconditionally regardless of the allowlist setting.

## Errors

Every error variant is a typed enum surfaced through MCP's `ErrorData`:

| Variant | When |
|---|---|
| `NotFound` | 404 from Vault — missing secret, missing field, list on a leaf |
| `Forbidden` | 403 — token policy doesn't allow this read |
| `Sealed { will_retry }` | 503 with `sealed: true` — wait or fail |
| `BadPath` | Path failed validation (allowlist or hygiene check) |
| `Network` | Transport error: connect failed, timeout, DNS |
| `Internal` | Anything else (malformed body, 5xx without sealed flag, etc.) |

Display strings deliberately omit the path, the token, the bearer header, and the full URL. The caller already knows the path it sent; echoing it back risks leaking it into client-side logs.

## Registering with Claude Code

```bash
claude mcp add --transport http --scope user kytti http://YOUR-HOST:6339/mcp
```

## Deployment

A static-pie musl binary is the supported shipping format:

```bash
cargo build --release --target x86_64-unknown-linux-musl
scp target/x86_64-unknown-linux-musl/release/kytti YOUR-HOST:/tmp/
```

On the target host (root):

1. Create the user: `useradd --system --no-create-home --home-dir /var/lib/kytti --shell /usr/sbin/nologin kytti`
2. Drop the binary at `/usr/local/bin/kytti` (mode 0755)
3. Drop `/etc/kytti/config.toml` (0640 root:kytti) and `/etc/kytti/token` (0640 root:kytti — kytti needs read access)
4. Install a hardened systemd unit (`ProtectSystem=strict`, `NoNewPrivileges=yes`, `MemoryDenyWriteExecute=yes`, `RestrictAddressFamilies=AF_INET AF_INET6`, empty `CapabilityBoundingSet=`, no `ReadWritePaths`)
5. `systemctl enable --now kytti`

Runtime footprint: **~8 MB RSS** at idle (measured on Debian 13). Static-pie musl binary is ~7 MB stripped.

## Stack

- Rust 2024
- [rmcp](https://github.com/modelcontextprotocol/rust-sdk) 1.5 (server, macros, streamable-http)
- [axum](https://github.com/tokio-rs/axum) 0.8 + [tokio](https://tokio.rs/)
- [reqwest](https://github.com/seanmonstar/reqwest) 0.12 + rustls (no native-tls)
- [arc-swap](https://github.com/vorner/arc-swap) for SIGHUP reload
- [serde](https://serde.rs/) + [serde_json](https://github.com/serde-rs/json) + [toml](https://github.com/toml-rs/toml)

No `vaultrs` — three endpoints fit in ~100 LoC of `reqwest` + `serde_json`.

## License

MIT — see [LICENSE](LICENSE).
