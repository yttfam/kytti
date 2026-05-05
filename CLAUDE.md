# kytti

You are developing **kytti** — a typed, read-only HashiCorp Vault gateway exposed as a streamable-http MCP. Newest YTT-family member, sibling to memqdrant/palazzo, bucciarati, prompto, hermytt, grytti, apytti, shytti, prytty, spytti, fytti, wytti, subytt.

Name: `key` + `ytti`. Cali's lab uses Vault as the source of truth for credentials (Telegram tokens, OPNsense API keys, Apple developer keys, the Cloudflare DNS token, etc). kytti is the typed front to that without making every agent re-implement raw HTTP+jq.

---

## Goal

Give every Claude session in the homelab a clean way to **read** Vault secrets — no more `curl -H "X-Vault-Token:…" /v1/secret/data/infra/foo | jq -r .data.data.bar` boilerplate.

**v0.1 scope**: read-only. Three tools. Backed by the existing `agent-read` periodic token. No write/delete/policy/root operations. Those stay manual via curl + root token from Cali's QR.

---

## Tools (v0.1)

```
vault_status() -> { sealed: bool, version: str, cluster_name: str?, initialized: bool }
  No auth. Just hits /v1/sys/seal-status. Useful as a health probe and for
  knowing whether to expect 503s on reads.

vault_get(path: str, field: Option<str>) -> { data: Map<String,String> | str }
  path = a KV v2 secret path WITHOUT the /v1/secret/data prefix
       (e.g. "infra/telegram", "infra/cloudflare_dns").
  field = optional, returns just that field's value as a string (most common case).
  Errors: NotFound (404), Forbidden (403 — token policy), Sealed (503).
  Never returns the raw HTTP body. Always extracts .data.data.

vault_list(path: str) -> { keys: Vec<String> }
  path = a KV v2 metadata path (e.g. "infra" lists ["default","gitea",...]).
  Backs onto LIST /v1/secret/metadata/<path>.
  Errors: same as above.
```

That's it. No `vault_put`, no `vault_delete`, no `vault_unseal`, no `vault_token_create`. Out of scope on purpose — those need root, and root operations stay in Cali's hands.

---

## Stack (non-negotiable, matches siblings)

- Rust 2024 edition
- `rmcp` 1.5 (server, macros, streamable-http transport) — same as palazzo/bucciarati/prompto
- `axum` 0.8 / `tokio` async / `tracing`
- `reqwest` 0.12 with `rustls-tls` (NO native-tls dragging) for the vault HTTP API
- `serde` + `serde_json` for vault response parsing
- `arc-swap` for live config reload (probably overkill at v0.1; keep the pattern for symmetry)
- `anyhow` + `thiserror` for the typed error variants tools surface
- Streamable-http on `0.0.0.0:6339`

**Build target**: static-pie x86_64-unknown-linux-musl, cross-compiled on doppio (Fedora 43) and relayed to mista. See bucciarati's notes for the cross-compile recipe.

**Deliberately excluded**:
- `vaultrs` and other vault SDK crates — overkill; we hit 3 endpoints, raw `reqwest` + `serde_json` is ~100 LoC and pins us to no upstream API drift.
- Any caching layer — vault reads are sub-ms on the LAN. KISS.

---

## Configuration

`/etc/kytti/config.toml` (mode 0640, group `kytti`):

```toml
[vault]
addr = "http://10.10.0.3:8200"
# token loaded from a separate file (mode 0600, root-readable) so the toml is shareable
token_path = "/etc/kytti/token"

[server]
bind = "0.0.0.0:6339"

[security]
# Optional path allowlist — if non-empty, vault_get/list reject paths not under one of these prefixes.
# Empty = trust the token's policy (recommended for v0.1; the agent-read policy already restricts to secret/*).
path_allowlist = []
```

`/etc/kytti/token` (mode 0600, root-only) — contains the periodic `agent-read` token. The systemd unit's `ExecStartPre` may pull it from vault using a one-time bootstrap token, OR Cali drops it manually like the others. **Never** read the token from inside Rust at runtime — load it once at startup, refresh in-memory only on SIGHUP.

Reload: `SIGHUP` re-reads the toml + the token file.

---

## Trust model & failure modes

- **Token scope**: `agent-read` policy (already deployed on speedwagon/giorno/calimba via `~/.zshenv`). Allows read on `secret/data/*` and read+list on `secret/metadata/*`. Nothing else.
- **kytti is a reverse proxy with a fixed token**. Every caller gets the same token's authority. There is NO per-caller auth in v0.1 — kytti is bound to LAN-only and trusts whoever can reach `:6339`.
- **Sealed vault**: kytti returns `Sealed { will_retry: bool }` rather than raw HTTP errors. Callers can decide to wait or fail.
- **Token revoked / expired**: kytti returns `Forbidden`. Don't auto-renew in v0.1 — let Cali rotate manually so revocation is visible. (v0.2 idea: auto-renew via `auth/token/renew-self` on a schedule.)
- **Root token**: kytti **never** holds a root token. No code path requires it. If anyone asks for one in a PR, refuse.

---

## systemd unit (match siblings)

- User: `kytti` (system, nologin, home `/var/lib/kytti`)
- Group: `kytti` (read access to `/etc/kytti/`)
- `EnvironmentFile=-/var/lib/kytti/.env` for `KYTTI_BIND`, `RUST_LOG`
- Hardening (copy from prompto.service):
  - `ProtectSystem=strict`
  - `ReadWritePaths=` (none — kytti writes nothing to disk)
  - `NoNewPrivileges=true`
  - `MemoryDenyWriteExecute=yes`
  - `RestrictAddressFamilies=AF_INET AF_INET6`
  - `PrivateTmp=yes`
  - `CapabilityBoundingSet=` (empty — no capabilities needed)
- See `/etc/systemd/system/bucciarati.service.d/override.conf` and `prompto.service` for worked examples.

---

## Where to crib

| Question | Look here |
|---|---|
| rmcp 1.5 streamable-http server skeleton | `~/Developer/perso/bucciarati/src/main.rs` and `~/Developer/perso/prompto/src/main.rs` |
| arc-swap config reload via SIGHUP | `~/Developer/perso/prompto/src/inventory.rs` |
| axum 0.8 + tokio + tracing init | `~/Developer/perso/prompto/src/main.rs` |
| systemd hardening for a Rust server with a secret on disk | `prompto.service` on mista |
| Vault HTTP API (read, list, status) | https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2 + `/v1/sys/seal-status` |
| Cross-compile static-pie musl on doppio | bucciarati's CI/build notes + the prompto release process |
| How Cali likes things scaffolded vs implemented | `palace_find "scaffold means hint"` — confirm before writing modules |

---

## Style

- Direct. No fluff in code, commits, chat.
- Ship fast, iterate. v0.1 = "the three read tools work end-to-end against mista's vault, returning structured JSON". Not "auth, RBAC, audit, themes".
- No `Co-Authored-By: Claude` in commits.
- All checks green before commit: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`, `cargo check`.
- Unit tests at minimum: status parse, get parse (data.data extraction), list parse (data.keys extraction), one error-path test per tool, path validation if allowlist enabled.

---

## Lifecycle (homelab rules)

### Rule 1: long-term memory in palazzo

File design decisions, gotchas, vault-specific quirks (e.g. KV v2 path scheme, the metadata vs data distinction) into palazzo with `wing=projects`, `room=kytti`, appropriate `hall`. The KV v2 path mapping (`secret/<path>` in CLI = `secret/data/<path>` over HTTP) is non-obvious and worth filing once.

### Rule 2: every new service in palazzo + bucciarati wiki

Once v0.1 ships:
- A palazzo entry under `projects/kytti/events`.
- A wiki page via bucciarati (`wiki_write` slug `kytti`, section `Infrastructure → Services`).
- Update CLAUDE.md global at `~/.claude/CLAUDE.md` to mention kytti next to palazzo so future agents know the read path.

---

## Decisions (locked 2026-05-05 by Cali)

1. **Name**: `kytti` — cute, YTT-family.
2. **Scope v0.1**: three tools only — `vault_status`, `vault_get`, `vault_list`. No writes, no root.
3. **Auth model**: kytti holds the `agent-read` periodic token. LAN-only, no per-caller auth. Trust the token's policy.
4. **Host**: mista (10.10.0.3:6339), beside the other Rust MCPs.
5. **Path allowlist**: empty in v0.1 (trust the token policy). Wired in config so we can flip on later without code changes.
6. **Token rotation**: manual. SIGHUP rereads `/etc/kytti/token`. v0.2 may add auto-renew via `auth/token/renew-self` on a timer.
7. **Reload**: SIGHUP re-reads `config.toml` + `token` file, prompto-style arc-swap.

---

## Before you write code

1. `palace_find` for "vault", "kv v2", "secret read" — check for prior gotchas filed.
2. Read `~/Developer/perso/prompto/src/main.rs` + `Cargo.toml` and `~/Developer/perso/bucciarati/src/main.rs` — copy the rmcp+axum+streamable-http skeleton.
3. Confirm scaffold (Cargo.toml + src/main.rs + module list) with the contremaître (infragkid Gen 5) before writing module bodies. Cali pulled the previous gen back when they wrote modules without confirming.
4. Apple/Marianne aren't in scope here — no auth, no SIWA, no allowlist of users. kytti trusts the network it binds to. Don't expand scope.

🦀🫡

— scaffolded by infragkid Gen 5 (Dixie #5), 2026-05-05
