# TowStrap Technical Manual

[Home](../../README_EN.md) · [User Guide](user-guide.md) · [中文](../../docs/zh/technical-manual.md)

For anyone integrating, auditing, or extending TowStrap. Everything below is written against the current code (`internal/`, `cmd/`); known limitations are listed at the end.

## Contents

1. [Architecture and data flows](#1-architecture-and-data-flows)
2. [WebSocket protocol](#2-websocket-protocol)
3. [Authentication and rate limiting](#3-authentication-and-rate-limiting)
4. [Data model and encryption](#4-data-model-and-encryption)
5. [Accounts and machines: the Hub](#5-accounts-and-machines-the-hub)
6. [Token lifecycle](#6-token-lifecycle)
7. [SSH session handling](#7-ssh-session-handling)
8. [The MCP layer](#8-the-mcp-layer)
9. [Skill and harnesses](#9-skill-and-harnesses)
10. [Configuration reference](#10-configuration-reference)
11. [CLI reference](#11-cli-reference)
12. [HTTP endpoint reference](#12-http-endpoint-reference)
13. [Audit event reference](#13-audit-event-reference)
14. [Security model and known limitations](#14-security-model-and-known-limitations)
15. [Build, test, release](#15-build-test-release)

---

## 1. Architecture and data flows

Three processes:

- **towstrap-server** (`cmd/towstrap-server`, `internal/server`): one process, two ports — an SSH port (gliderlabs/ssh) for humans, and an HTTP port serving the agent WebSocket (`/agent`), monitoring (`/health` `/status`), MCP (`/mcp`), token rotation (`/token/refresh`), and the public skill (`/skill`). The `Hub` is the core: a machine-ID → connected-agent map through which every session is established. Accounts live in SQLite (`internal/accounts`).
- **towstrap-agent** (`cmd/towstrap-agent`, `internal/client`): a daemon on the controlled machine. Dials out to `/agent`, spawns local processes on `open` (PTY or exec), pumps data both ways, handles `token` messages for remote rotation, and keeps a local audit log + notifications.
- **towstrap-mcp** (`cmd/towstrap-mcp`): a stdio MCP server. Hosts `mcpsrv.Server` whose execution backend is an SSH connection pool (`Pool`) — it acts as an SSH client to the server, same path as any `ssh` client.

```
SSH session:  ssh client ──SSH──> server(:2222) ──WS open/data──> agent ──> local shell/process
exec:         same path, pty=false; stdout/stderr on separate streams
MCP call:     LLM ──MCP──> towstrap-mcp (stdio, SSH to S) or /mcp (HTTP Bearer)
                        └── both land on server.Hub ──WS──> agent ──> shell -c
```

Flow details:

- **SSH interactive**: `handleSSH` resolves the login name to a machine → `Hub.OpenShell` sends `open` (window size/pty/command/from) → agent spawns and replies `ok` → `Hub.pipe` pumps `data` in both directions (32KB chunks), `resize` carries window changes, client stdin close sends `eof`, and process exit makes the agent reply `close` with the exit code.
- **exec**: same path with `pty=false`; the agent runs `shell -c`, stdout/stderr are split via the `s` field, stdin is a pipe.
- **MCP**: embedded mode's `mcpRunner.Run` calls `Hub.OpenShell` directly (pty=false); stdio mode's `Pool.Run` opens a real SSH exec session that lands on the same `handleSSH` → `Hub` → agent path. Both end at `shell -c` on the agent.

## 2. WebSocket protocol

Agent ↔ server share one WebSocket (`/agent`); messages are single-line JSON text frames. Types are defined in `internal/proto/proto.go`:

| `t` | Direction | Fields | Meaning |
| --- | --- | --- | --- |
| `hello` | agent→server | `name` (agent ID), `ver` (self-reported version) | first message after connect; anything else gets an `err` and a disconnect |
| `open` | server→agent | `id`, `cols`, `rows`, `pty`, `cmd`, `from` | open a session; empty `cmd` = interactive shell, `pty` selects PTY vs exec |
| `data` | both | `id`, `d` (base64), `s` | payload chunk; `s` empty = stdout/PTY, `"e"` = stderr (agent→server only) |
| `eof` | server→agent | `id` | client closed stdin; forwarded to the subprocess on exec sessions, ignored on PTY |
| `resize` | server→agent | `id`, `cols`, `rows` | PTY window change |
| `close` | both | `id`, `code` | session end; agent→server carries the exit code, server→agent means kill |
| `ok` | both | `id` | acknowledgement for `open`/`token` |
| `err` | both | `id`, `err` | failure reply (spawn failure, unwritable token file, …) |
| `token` | server→agent | `id`, `d` (new token, plaintext) | rotation push; agent replies `ok` after the atomic write, `err` otherwise |

Session IDs: sessions use `s<N>`, rotation requests `t<N>` (same counter, prefix distinguishes).

Limits and heartbeat (same values on both ends):

| Parameter | Value | Purpose |
| --- | --- | --- |
| `MaxMessageBytes` | 256 KiB | per-message cap (reader-side `SetReadLimit`) |
| `MaxCommandBytes` | 64 KiB | `open.cmd` cap; the server rejects before it ever hits the WebSocket |
| data chunking | 32 KiB | `data` payload slice size (~44KB after base64) |
| `PingPeriod` | 30 s | WS ping from both sides |
| `PongWait` | 90 s | no message at all (incl. pongs) for this long → disconnect |
| `WriteWait` | 10 s | per-message write timeout (a stalled peer blocks all sessions on that machine — they share one write lock) |

## 3. Authentication and rate limiting

### SSH auth paths (`internal/server/ssh.go`)

gliderlabs/ssh invokes three handlers in client-attempt order:

1. **password** (`sshAuthOK`): TOTP-bound accounts burn one bcrypt round (`BurnPassword`, timing side-channel) and are rejected outright — their password verification lives on the keyboard-interactive path. Otherwise `verifyPassword`: global allowlist → lockout check → bcrypt → account exists & enabled → account allowlist. On full success `guard.pass` clears counters and logs `AUTH-OK method=password`.
2. **keyboard-interactive** (`handleKbdInteractive`): asks the password first (same `verifyPassword`, `method=kbd-interactive`), then a TOTP code for enrolled accounts; wrong codes count against the limiter (`reason=totp`). Counters clear only after the **whole** flow including the code passes — clearing on a correct password alone would let an attacker with a leaked password reset the limiter every round.
3. **publickey** (`handlePublicKey`): global allowlist → key match (`VerifySSHKey`) → account exists & enabled → account allowlist. **No rate limiter** (clients try several keys in sequence; counting failures would cause false lockouts) and no TOTP — keys are the second credential meant for automation. Success logs `AUTH-OK method=publickey fp=SHA256:...` and marks the session context `publickey` (which `@` management commands and idle re-verification consult).

Timing side channels: unknown accounts, disabled accounts, and `BurnPassword` paths all run an equally expensive bcrypt comparison — username enumeration via response time is not feasible.

### authGuard (`internal/server/authguard.go`)

In-memory failure counters on two dimensions:

| Dimension | Key | Threshold | Window |
| --- | --- | --- | --- |
| account×IP | `user\|ip` | 5 failures | 15-minute sliding window |
| account aggregate | `user` | 50 failures | 15 minutes |

- At the threshold, a **1-minute** lockout starts; each further failure doubles it (shift capped at 6 → max **1 hour**)
- A fully successful auth (including TOTP) calls `pass()`, clearing both dimensions
- Each map holds at most 65,536 entries — expired entries are evicted first, then the oldest — so username-spraying can't blow up the tables
- **State is in memory; a restart clears it**
- The same guard covers `/token/refresh` password+TOTP checks and `@machine` TOTP re-verification

While locked, `/token/refresh` returns 429 and SSH rejects with `AUTH-FAIL reason=locked`.

### Idle re-verification (`idle_verify`, default 30m)

For TOTP-bound accounts + PTY sessions + non-publickey auth: the input stream is wrapped by `idleGate`, so the first input after the threshold triggers a fresh TOTP prompt inside the SSH channel (3 attempts; all wrong → disconnect). Output doesn't count as activity; exec sessions and public-key logins are exempt (injecting a code prompt into a script's stdin would break automation).

## 4. Data model and encryption

### SQLite schema (`internal/accounts/accounts.go`)

```sql
CREATE TABLE IF NOT EXISTS users (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	username        TEXT    NOT NULL UNIQUE,
	password_hash   TEXT    NOT NULL,
	contact         TEXT    NOT NULL DEFAULT '',
	totp_secret_enc BLOB,
	totp_last_step  INTEGER NOT NULL DEFAULT 0,
	allow_ips       TEXT    NOT NULL DEFAULT '',   -- JSON array
	ssh_pubkeys     TEXT    NOT NULL DEFAULT '',   -- JSON array
	disabled        INTEGER NOT NULL DEFAULT 0,
	created_at      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS machines (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	username        TEXT    NOT NULL,
	name            TEXT    NOT NULL,
	token_enc       BLOB    NOT NULL UNIQUE,       -- AES-GCM (deterministic)
	agent_allow_ips TEXT    NOT NULL DEFAULT '',   -- JSON array
	agent_last_ip   TEXT    NOT NULL DEFAULT '',
	created_at      TEXT    NOT NULL,
	UNIQUE(username, name)
);
CREATE INDEX IF NOT EXISTS idx_machines_token ON machines(token_enc);

CREATE TABLE IF NOT EXISTS mcp_clients (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT    NOT NULL UNIQUE,
	token_enc  BLOB    NOT NULL UNIQUE,            -- AES-GCM (seal "mcptoken")
	machines   TEXT    NOT NULL DEFAULT '',        -- JSON array; ["*"] = everything
	allow_ips  TEXT    NOT NULL DEFAULT '',        -- JSON array
	disabled   INTEGER NOT NULL DEFAULT 0,
	created_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mcp_token ON mcp_clients(token_enc);
```

Open parameters: `journal_mode=WAL`, `busy_timeout=5000`, single connection (SQLite writes serialize at the DB level anyway — avoids intra-process lock contention). File permissions are tightened to 0600.

### Encryption (`internal/accounts/crypto.go`)

- **Key file** `users.key`: 64 bytes = 32B AES-256 key + 32B HMAC key; auto-generated on first use (0600); default path derives from `users_db` (`.db` → `.key`). **Back up DB and key together** — losing the key orphans every token.
- **Deterministic AES-256-GCM**: the nonce is the first 12 bytes of `HMAC(macKey, purpose‖plaintext)` — same plaintext, same ciphertext, so ciphertexts can carry a UNIQUE index and equality lookups (`MachineByToken`, `MCPClientByToken` query by ciphertext); distinct plaintexts get distinct nonces, so no GCM nonce reuse. `purpose` (`"token"`/`"mcptoken"`/`"totp"`) binds the field — ciphertext moved to another purpose fails to decrypt.
- **Trade-off**: deterministic encryption leaks equality ("are these two tokens the same") — acceptable for random high-entropy tokens, and it buys indexability.
- **Passwords**: bcrypt (DefaultCost) with per-hash random salt; never stored in plaintext.
- **TOTP**: the secret is AES-GCM'd into `totp_secret_enc`; `totp_last_step` records the highest used time step so a code can't be replayed within its 30-second window (RFC 6238, 6 digits, 30s period).
- **Usernames are plaintext**: registration uniqueness and login lookup both key on it (`UNIQUE`).

### Legacy DB migration

`Open` idempotently does two things: `ensureColumn` adds `ssh_pubkeys` to old `users` tables; `migrateMachines` checks for a `token_enc` column on `users` — if present, each account's `token_enc/agent_allow_ips/agent_last_ip` is moved into `machines` (named `default`; same key + seal context means the BLOB moves as-is, no re-encryption), then `users` is rebuilt without those columns (SQLite's standard new-table → copy → drop → rename).

## 5. Accounts and machines: the Hub

- Machine ID = `account+machine` (`SplitMachineID` splits on `+`; `+` isn't a valid name character, so no ambiguity)
- `Hub.Attach`: a same-named (same account + machine) connection **replaces** the old one (old conn closed, its sessions reaped) and logs `AGENT-REPLACE`; different machine names under one account coexist
- `agentConn` remembers the token it attached with; **per-session re-checks** (`agentCredentialValid`: the token must still map to this machine) plus a **30-second sweep** (`revokeLoop` → `PruneInvalid`, drop + `AGENT-REVOKE`) make revocation (regen/remove/disable) effective on already-connected agents — not just new connections
- `remove` (`@machine`) and `--disable` trigger an immediate sweep instead of waiting 30s
- Per-machine concurrent session cap `max_sessions` (default 16)

## 6. Token lifecycle

```
Issue:   user add / machine add / @machine add → accounts.NewAgentToken() (tsa-)
         plaintext appears once in command output; the DB holds the ciphertext
Store:   machines.token_enc (deterministic AES-GCM, UNIQUE + index)
Lookup:  X-Agent-Token → MachineByToken (ciphertext equality) → machine + account-enabled check
Rotate (two-phase):
  ①  on the agent machine: towstrap-agent token refresh
       → POST /token/refresh (X-Agent-Token + JSON{password, totp, machines|all})
  ②  server: check token → caller's agent allowlist → lockout → password → TOTP
       → per target machine: Hub.RotateToken pushes a "token" message (10s ack wait)
  ③  agent: writeTokenFile (same-dir temp, 0600 → write → sync → rename)
       → ok + swap in-memory token; failure → err
  ④  server receives ok → SetMachineToken commits → agentConn.setToken updates
       (without this, the next sweep would drop the conn as a stale credential)
```

- **No ack, no commit**: `offline` (not connected), `no-file` (token not file-backed), `timeout` (10s), `not-found`, `error`
- **Inconsistency alarm**: agent wrote the token but the DB update failed → `slog.Error("token rotation inconsistent…")` + status=`error` — needs manual repair
- **Re-read on reconnect**: the agent re-reads the token file every reconnect (hand-edited files take effect)
- **Emergency path**: CLI `machine token --regen --admin` commits directly (logs `MACHINE-TOKEN-REGEN-ADMIN`); a connected agent on the old token is swept within 30s
- `/token/refresh` specifics: POST only + `Content-Type: application/json` + `X-Agent-Token`; body ≤64KB; bad password → `guard.fail`; full pass → `guard.pass`; response `{"results":[{machine,status,detail}]}`

## 7. SSH session handling

- **Machine selection**: a `+machine` suffix names the machine; without it, a single-machine account lands on it, a multi-machine account errors with the list (incl. online status), zero machines errors. Missing/offline/stale-credential cases each get a specific message + `SESSION-DENY` (reason=no-machine/ambiguous/offline/credential)
- **`@` prefix** routes to `handleMgmt` instead of the agent: public-key sessions are refused (reason=pubkey), TOTP accounts must supply a fresh code (3 attempts, failures count against the limiter); only `@machine list/add/remove/token/help` exist
- **PTY vs exec**: decided by `sess.Pty()`; PTY goes through a real pty (`pty.Start`, window size + `resize` relayed), exec runs `shell -c` with three pipes (stderr split via `s="e"`)
- **stdin/EOF**: client stdin close → server sends `eof` → exec sessions forward it to the subprocess (`cat` finishes on EOF); PTY sessions ignore it (Ctrl-D is just a byte in the stream)
- **Exit codes**: agent-side `exitCode()`: normal exit → ExitCode; signal kill → 128+signal; never-started → 255. Server-side `session.code` defaults to 255 and is only overwritten by the agent's `close.code` — a dropped agent never reads as 0. MCP `run_command` reports `timed_out=true` + `exit_code=-1` on SIGKILL timeout
- **Command length**: `open.cmd` caps at 64KB; over → `SESSION-DENY reason=cmd-too-long`
- **Environment**: `TOWSTRAP_AGENT_TOKEN` is stripped from child env; `TERM=xterm-256color` is set
- **Idle re-verification**: see §3

## 8. The MCP layer

### Structure (`internal/mcpsrv`)

- `Server` = config + compiled `Policy` + a `Runner` backend; two `Runner` implementations: `Pool` for stdio mode (lazy per-machine SSH connections, conn-level errors redial and retry once), `mcpRunner` for embedded mode (straight to the Hub — a passwordless exec, essentially)
- Embedded mode builds a fresh `mcpsrv.Server` per request (`getServer` callback); the visible machine set is computed from that request's client credential — grant changes need no restart
- `Implementation.Name = "towstrap-mcp"`; the `initialize` response carries `Instructions` (usage rules for the LLM + machine list + policy summary)

### The four tools (`tools.go`)

| Tool | Input | Output | Policy |
| --- | --- | --- | --- |
| `list_machines` | — | `machines[]`: name/description/roots/connected | none |
| `run_command` | `machine`, `command`, `cwd?`, `stdin?`, `timeout_seconds?` | `exit_code`, `stdout`, `stderr`, `timed_out`, `*_truncated`, `duration_ms`, `approval` | deny→reject; all-segments allow→run; else approval |
| `read_file` | `machine`, `path` | `content`, `bytes` | deny_paths; ≤max_file; NUL bytes rejected (binary) |
| `write_file` | `machine`, `path`, `content` | `bytes_written` | deny_paths; ≤max_file; inside roots → auto-allowed, else approval |

Implementation details: `run_command` with `cwd` wraps as `cd -- 'cwd' && (command)` (single-quote shellQuote); `read_file` is really `head -c max+1`; `write_file` is `cat > 'path'` on stdin; oversized output keeps head and tail halves with an elision marker (`CapWriter`); `timeout_seconds` above `max_timeout` is clamped and noted. Tool errors return `IsError` + text (not protocol errors — the LLM sees the reason).

### Policy engine (`policy.go`)

`Policy.Command` flow:

1. the whole command string against every deny regex first (defeats split-hiding)
2. naive split on `&&`, `||`, `;`, `|`, newlines; **each segment** re-checked against deny
3. a segment containing `` ` ``, `$(`, `>`, `<`, or `&` is marked unsafe (substitution/redirection/background may hide a second action)
4. safe + every segment allow-matched → `Run`; otherwise `policy.default`

`deny` beats everything. Built-in lists (setting the same key in yaml **replaces the whole list**):

- `DefaultAllow`: `ls/pwd/cat/head/tail/wc/grep/rg/find/stat/file/echo/which/whoami/id/uname/df/du/ps/date/tree`; bare `env`; `git status|diff|log|show|remote|rev-parse|ls-files|blame`, read-only `git branch` forms; `go build|test|vet|fmt|list|mod tidy|doc|version`; `npm/pnpm/yarn test|run test|run lint|run build|ls`; `cargo/make test|build|check|fmt`; `python/python3/node --version`; `gofmt`
- `DefaultDeny`: `rm -r /`, `rm ~`, `mkfs`, `dd of=/dev/`, `shutdown/reboot/halt/poweroff`, `curl|sh`, `wget|sh`, `find -exec/-delete`, `rg --pre`, `> /dev/sd`, `chmod 777 /`, `.ssh/id_*`, `.ssh/authorized_keys`, `/etc/shadow`, `/etc/sudoers`, `sudo`, `su`, `towstrap-agent` (the agent can't touch itself)
- `DefaultDenyPaths`: `.ssh/`, `.gnupg/`, `/etc/shadow`, `/etc/sudoers`, `.aws/credentials`, `towstrap/token`, `towstrap/agent.yaml`

### Path policy

- `deny_paths`: each regex matches against both the raw path and its `path.Clean`ed form
- `roots` (write_file auto-allow dirs): **textual prefix match**; only absolute or `~/`-prefixed paths qualify (relative paths never match — the remote home is unknowable); `~` is not expanded
- **Known limit**: remote symlinks aren't resolved — a `link -> /etc` inside roots lets `link/x` escape the prefix check. Keep no outward-pointing symlinks inside roots

### Human approval (`approval.go`)

Two mechanisms:

1. **elicitation (popup)**: clients declaring elicitation capability → the handler returns a `CallToolResult` with `InputRequests` (the go-sdk's MRTR/SEP-2322 pattern — compatible with old and new protocol revisions; the SDK completes the round-trip and re-invokes the handler with the answer in `InputResponses["approval"]`). Schema: `approve` (bool, required) and `remember` (bool, "don't ask again for this command this session")
2. **Local file fallback**: no popup support → a `<id>.json` lands in `approvals_dir` (`{id,machine,kind,detail,cwd,created,pid}`, 0600); stdio mode also fires a desktop notification; `approve <id>` writes `<id>.approved`, `deny` writes `<id>.denied`, and the server side polls every 500ms until `ask_timeout`

`remember` is scoped to the **client session** (keyed `machine + detail`, cleaned up on session end). Timeout/cancel → `Timeout`; no approval path at all → `Unavailable`. Entering/leaving approval logs `MCP-ASK` (via=elicit/local) and an outcome `MCP-APPROVED`/`MCP-DENIED`/`MCP-ASK-TIMEOUT`.

### Embedded-mode auth order (`internal/server/mcp.go`)

`/mcp` sits behind `RequireBearerToken`; `mcpBearer` checks in order: server global `allow_ips` → `mcp_clients` lookup (`MCPClientByToken`: valid and not disabled) → the client's own `allow_ips`. Any failure logs `MCP-AUTH-FAIL` (reason=allow-ip/token/client-allow-ip) and returns 401; the plaintext token never enters the request context. New sessions (no `Mcp-Session-Id` header) log `MCP-SESSION` (30s dedup). Streamable HTTP session timeout is 30 minutes.

Execution goes through `mcpRunner.Run`: the machine must be in the client's grant set (`machines` four forms expand: `'*'`→all, `'alice'`/`'alice+*'`→all of a non-disabled account, `'alice+office'`→one machine), online, and credential-re-checked; audit `SESSION-START mode=mcp from=mcp:client@IP`.

## 9. Skill and harnesses

- **Source**: `skills/towstrap/SKILL.md`; `skills/embed.go` `//go:embed`s it into `towstrap-mcp` and `towstrap-server` (the `/skill` endpoint serves exactly this)
- **Harness table** (`internal/harness/harness.go`, detected via home dirs):

| Harness | Detected by | Installs into |
| --- | --- | --- |
| Claude Code | `~/.claude` | `~/.claude/skills` |
| Codex | `~/.codex` | `~/.agents/skills` (shared dir, avoids duplication) |
| Grok Build | `~/.grok` | `~/.agents/skills` (same) |
| Cursor | `~/.cursor` | `~/.cursor/skills` |
| Gemini CLI | `~/.gemini` | `~/.gemini/skills` |
| OpenCode | `~/.config/opencode` | `~/.config/opencode/skills` |
| GitHub Copilot CLI | `~/.copilot` | `~/.copilot/skills` |
| Devin CLI | `~/.config/devin` | `~/.config/devin/skills` |

- **Manifest**: `<skills-dir>/towstrap/.towstrap-managed.json` holds `{version, sha256, installed_at}`. With a manifest → upgrade by version (user-modified content is overwritten with a notice); without → treated as a user-owned same-named skill and skipped (`--force` overrides). On uninstall, a mismatched sha (user edits) is skipped unless `--force`. Writes go through temp file + rename
- **print-mcp**: generates config snippets per client (pure functions). Field sources: Claude Code `{"type":"http",url,headers}` + the `claude mcp add` command; Codex `config.toml` `url` + `http_headers` (per developers.openai.com/codex/config-reference); Grok `url` + inline `headers` table (local grok docs); Cursor `url`/`headers` or `command`/`args`; Gemini `httpUrl` + `headers` (`url` is the SSE transport — don't mix); OpenCode `{"type":"remote",url,headers}` / `{"type":"local","command":[…]}`

## 10. Configuration reference

### server.yaml (`internal/config`)

| Key | Type | Default | Meaning / flag |
| --- | --- | --- | --- |
| `http` | string | `:8080` | HTTP bind / `--http` |
| `ssh` | string | `:2222` | SSH bind / `--ssh` |
| `host_key` | string | `ssh_host_key` next to users_db | SSH host key / `--host-key` |
| `users_db` | string | `/etc/towstrap/users.db` | account DB / `--users-db` |
| `users_key` | string | `users_db` minus `.db` + `.key` | encryption key / `--users-key` |
| `admin_token` | string | empty | `/status` admin password / `--admin-token` |
| `public_url` | string | empty | public `wss://` address for install hints / `--public-url` |
| `tls` | bool | `false` | HTTPS/WSS / `--tls` |
| `cert` / `key` | string | empty | certs / `--cert` `--key`; empty self-signs to `./tls_cert.pem` `./tls_key.pem` |
| `allow_ips` | []string | empty | global allowlist / `--allow-ip` (repeatable) |
| `idle_verify` | duration | `30m` | TOTP idle re-verify threshold, `0` off / `--idle-verify` |
| `min_agent_version` | string | empty | agent version floor / `--min-agent-version` |
| `audit_log` | string | below | audit path / `--audit-log`; `/dev/null` disables |
| `max_sessions` | int | `16` | per-machine concurrent sessions / `--max-sessions` |
| `max_conns` | int | `4096` | per-port total connections / `--max-conns` |
| `max_conns_per_ip` | int | `64` | SSH per-IP connections / `--max-conns-per-ip` |
| `ssh_idle_timeout` | duration | `0` | SSH idle timeout / `--ssh-idle-timeout` |
| `ssh_max_timeout` | duration | `24h` | absolute SSH lifetime / `--ssh-max-timeout` |
| `mcp.enabled` | bool | `false` | embedded MCP switch (no flag) |
| `mcp.path` | string | `/mcp` | mount path |
| `mcp.allow_plain_http` | bool | `false` | plaintext + non-loopback override |
| `mcp.approvals_dir` | string | `approvals/` next to audit log | pending-approval dir |
| `mcp.machines.<id>.description` / `.roots` | string / []string | — | MCP-side metadata; key is the full machine ID |
| `mcp.policy` / `mcp.limits` | — | built-in defaults | same format as mcp.yaml |

Default audit path: root → `/var/lib/towstrap/server-audit.log`, others → `~/.towstrap/server-audit.log`.

### agent.yaml

| Key | Type | Default | Meaning / flag |
| --- | --- | --- | --- |
| `agent.server` | string | required | `ws(s)://` (`http(s)://` accepted too) / `--server` |
| `agent.agent_token` | string | — | literal token / `--agent-token` (visible in ps) |
| `agent.agent_token_file` | string | — | 0600 file (recommended, remotely rotatable) / `--agent-token-file` |
| `agent.shell` | string | `$SHELL` → `/bin/bash` | shell for remote sessions / `--shell` |
| `agent.insecure` | bool | `false` | skip TLS verification / `--insecure` |
| `agent.quiet` | bool | `false` | mute notifications (audit still written) / `--quiet` |
| `agent.audit_log` | string | root `/var/lib/towstrap/audit.log`, others `~/.towstrap/audit.log` | / `--audit-log` |

The env var `TOWSTRAP_AGENT_TOKEN` is also recognized. Token source precedence (`resolveAgentToken`): `--agent-token` > `--agent-token-file` > env > yaml `agent_token` > yaml `agent_token_file`; for everything else it's flag > yaml > default.

### mcp.yaml (stdio, `internal/mcpsrv/config.go`)

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `server` | string | required | server SSH entry `host:port` |
| `key` | string | required | passphrase-less private key |
| `known_hosts` | string | — | host-key verification (one of the two required) |
| `host_key` | string | — | pinned SHA256 fingerprint; overrides known_hosts |
| `machines.<login>.description` | string | — | description shown to the LLM |
| `machines.<login>.roots` | []string | — | write_file auto-allow dirs |
| `policy.default` | string | `ask` | `run`/`ask`/`deny` |
| `policy.allow` / `deny` / `deny_paths` | []regex | built-in lists | setting replaces the whole list |
| `policy.ask_timeout` | duration | `5m` | approval wait ceiling |
| `limits.timeout` | duration | `120s` | default run_command timeout |
| `limits.max_timeout` | duration | `1h` | cap for timeout_seconds |
| `limits.max_output` | int | `65536` | per-stream cap (≥1024) |
| `limits.max_file` | int | `1048576` | read/write file cap |
| `approvals_dir` | string | `~/.config/towstrap/approvals` | pending-approval dir |

Validation: `timeout ≤ max_timeout`; `max_output ≥ 1024`; stdio mode requires `server`/`key`/`machines`. Default config path: `~/.config/towstrap/mcp.yaml`.

## 11. CLI reference

### towstrap-server

```
towstrap-server [flags]                                  run the server
towstrap-server user add|list|set|remove|token|totp      account management
towstrap-server machine add|list|set|remove|token        machine management
towstrap-server mcp add|list|set|remove|token|pending|approve|deny
towstrap-server version                                  version
```

Shared options (all management subcommands): `--config server.yaml` (reads users_db/users_key/public_url/audit_log/the mcp section), `--users-db`, `--users-key`, `--server-url`; some take `--audit-log`, `--admin`.

- `user add NAME [--password] [--contact] [--allow-ip]... [--agent-allow-ip]... [--ssh-key]... [--ssh-key-file]`: without `--password` a 16-char random one is printed once; auto-creates the `default` machine
- `user set`: `--password` `--name` `--contact`/`--clear-contact` `--allow-ip`/`--clear-allow` `--agent-allow-ip`/`--clear-agent-allow` `--ssh-key`/`--ssh-key-file`/`--remove-ssh-key`/`--clear-ssh-keys` `--disable`/`--enable`
- `user token NAME [--regen] [--admin]`: single-machine accounts only; owner confirmation; `--regen` requires `--admin`
- `user totp NAME [--remove]`: enroll (prints otpauth URI + secret, confirms with a code)/unenroll
- `machine add ACCOUNT NAME [--agent-allow-ip]... [--admin]`: owner confirmation
- `machine list [ACCOUNT]` / `machine set ACCOUNT NAME [--agent-allow-ip]... [--clear-agent-allow]` / `machine remove ACCOUNT NAME` / `machine token ACCOUNT NAME [--regen] [--admin]`
- `mcp add NAME --machine GRANT... [--allow-ip]...`: issues a tsm- token + prints client config + skill install commands; `--machine` forms `*`/`alice`/`alice+*`/`alice+office`
- `mcp list` / `mcp set NAME [--machine]... [--allow-ip]... [--clear-allow] [--disable|--enable]` / `mcp remove` / `mcp token [--regen]`
- `mcp pending` / `mcp approve <id>|--all` / `mcp deny <id>|--all`: `--approvals-dir` > yaml `mcp.approvals_dir` > `approvals/` next to the audit log

### towstrap-agent

```
towstrap-agent [flags]                                    run the daemon
towstrap-agent token refresh [--machine NAME]... [--all] [--allow-plain]
```

Flags: `--config --server --agent-token --agent-token-file --shell --insecure --audit-log --quiet`. `refresh` interactively asks password + TOTP; exit code 0 all-ok / 1 partial / 2 argument-or-auth error.

### towstrap-mcp

```
towstrap-mcp [--config mcp.yaml]              run the stdio MCP server
towstrap-mcp pending|approve <id>|--all|deny <id>|--all   approval fallback
towstrap-mcp connect [list|uninstall|print-mcp] [--path] [--force] [--dry-run]
                [--url URL --token tsm-...] | [--stdio]
```

## 12. HTTP endpoint reference

| Path | Methods | Auth | Notes |
| --- | --- | --- | --- |
| `/health` | GET | none | liveness, `200 ok` |
| `/status` | GET | `X-Admin-Token` (full view) or `X-Agent-Token` (self only) | `{"ok","http","ssh","users":[{user,machine,online,disabled?}]}`; 503 when nothing is online |
| `/agent` | GET(Upgrade) | `X-Agent-Token` | WebSocket entry; 401 bad token, 403 agent allowlist |
| `/mcp` | POST etc. | `Authorization: Bearer tsm-…` | Streamable HTTP MCP; 401 logged as `MCP-AUTH-FAIL`; plaintext + non-loopback refuses to start |
| `/token/refresh` | POST | `X-Agent-Token` + JSON password/TOTP | see §6; `{"results":[…]}`; 401/403/429 logged as `TOKEN-REFRESH-DENY` |
| `/skill` | GET/HEAD | none (public document) | `text/markdown; charset=utf-8`, `Cache-Control: public, max-age=3600`; other methods 405 |

Fixed HTTP server parameters: `ReadHeaderTimeout 10s`, `IdleTimeout 2m`, `MaxHeaderBytes 16KB`; TLS minimum version 1.2.

## 13. Audit event reference

Format: `<RFC3339 time> <event> k=v`; `cmd` truncated past 512 bytes; control characters in values are scrubbed.

**Server side** (`server-audit.log`):

| Event | Key fields | Fires when |
| --- | --- | --- |
| `AUTH-OK` | user ip method(password/kbd-interactive/publickey) [totp=true] [fp] | SSH auth success |
| `AUTH-FAIL` | user ip method reason(locked/password/disabled/allow-ip/totp) | auth failure |
| `AGENT-CONNECT` | id ip version | agent attaches |
| `AGENT-REPLACE` | id ip | same-name takeover |
| `AGENT-DISCONNECT` | id ip | conn dropped |
| `AGENT-REVOKE` | id | sweep found a dead credential; dropped on the spot |
| `AGENT-DENY` | id ip reason(agent-allow/old-version) [ver min] | attach refused |
| `AGENT-IPCHANGE` | id old new | source IP changed (no allowlist) |
| `SESSION-START` | user from id mode(pty/exec/mcp) machine cmd | session opened |
| `SESSION-END` | user from id code | session closed (exit code) |
| `SESSION-DENY` | user from reason | session refused |
| `MGMT-DENY` | user from reason(pubkey/locked/totp) | `@` command refused |
| `MACHINE-ADD` `MACHINE-REMOVE` `MACHINE-TOKEN` | user machine from | SSH self-service |
| `MACHINE-ADD-ADMIN` `MACHINE-TOKEN-ADMIN` `MACHINE-TOKEN-REGEN-ADMIN` | user machine | CLI `--admin` skipped owner confirmation (written by the CLI process) |
| `TOKEN-REFRESH` | user machine from(agent:caller@ip) status | one line per rotated machine |
| `TOKEN-REFRESH-DENY` | [user] ip reason | rotation refused |
| `MCP-SESSION` | client ip | new MCP session (30s dedup) |
| `MCP-AUTH-FAIL` | ip reason | Bearer check failed |
| `MCP-POLICY-DENY` | client ip machine kind detail reason | policy rejection |
| `MCP-ASK` | client ip machine kind detail via(elicit/local) | entered approval |
| `MCP-APPROVED` `MCP-DENIED` `MCP-ASK-TIMEOUT` | client ip machine kind detail | approval outcome |

**Agent side** (`audit.log`):

| Event | Fields | Fires when |
| --- | --- | --- |
| `AGENT-START` | version id server shell insecure quiet uid audit | process start |
| `START` | id from mode(pty/exec) cmd | session start (`from` failing the format check is sanitized to "unknown source") |
| `END` | id from | session end |
| `TOKEN-ROTATED` | id | a pushed token was written to the file |

## 14. Security model and known limitations

### Trust boundaries

| Boundary | Notes |
| --- | --- |
| agent OS user | **the real boundary**: remote commands run as the agent's OS user. A dedicated low-privilege user is required, not optional |
| server | whoever holds users.db + users.key can decrypt every stored credential (tokens are decryptable for display); the 0600 files are a backstop |
| MCP policy | a filter, not a sandbox: naive splitting loses to full shell semantics |
| source IP | allowlists/rate-limiting/IPCHANGE all judge by TCP source IP — a reverse proxy breaks all three |

### Known limitations

- **Reverse proxies**: see the README security notice; front the server with L4 passthrough (preserving source IP) or a cloud firewall if you must
- **Running as root**: warns but doesn't stop (`warnIfRoot`, audit `uid=`)
- **roots symlinks**: prefix matching doesn't resolve remote links — see §8
- **Plaintext**: `/mcp` has a refuse-to-start guard; plain agent connections over `ws://` are not blocked (intranet use), but `token refresh` requires `--allow-plain` to send a password over non-loopback plaintext
- **Public-key login bypasses the rate limiter**: clients try several keys and counting would false-lock; keys aren't guessable anyway. The cost: key probing is unthrottled (and not per-attempt audited)
- **Agent version is self-reported**: `min_agent_version` is an ops floor, not a security control
- **Rate-limit state is in-memory**: a restart clears it
- **Deterministic encryption leaks equality**: see §4
- **`@machine` management requires password-class login**: public-key automation can't manage machines (deliberate trade-off)
- **No scp/sftp**: file transfer goes through cat/heredoc or the MCP file tools

## 15. Build, test, release

- **Make targets**: `build` (three binaries into `bin/`), `test` (`go vet` + `go test ./...`), `release` (cross-compile darwin/linux × amd64/arm64 → `dist/` + `SHA256SUMS`, minisign signing when `MINISIGN_KEY_FILE` is set), `clean`
- **Version injection**: `-ldflags "-X github.com/towstrap/towstrap/internal/version.Version=$(cat VERSION)"`; the `version` command and the `hello` message's `ver` both use it
- **Test layout**: per-package unit tests under `internal/*` plus `internal/e2e` end-to-end — e2e spins up a **real in-process server and real agent connections**, covering SSH password/TOTP/public-key login, brute-force lockout, exec, multi-machine, token rotation, MCP over HTTP and stdio, `@machine`, revocation, and more
- **Dependencies**: all-static Go (modernc sqlite, no CGO) — three binaries, zero runtime deps
