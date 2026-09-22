# TowStrap User Guide

[Home](../../README_EN.md) · [Technical Manual](technical-manual.md) · [中文](../../docs/zh/user-guide.md)

TowStrap makes machines behind NAT/firewalls securely reachable: an agent on the controlled machine opens an outbound WebSocket to your server; humans connect over SSH, LLMs over MCP, and both land on that machine through the server. This guide follows the order of use: install → server → agent → accounts → login → commands → MCP → monitoring & troubleshooting.

> ⚠️ Read the [security notice in the README](../../README_EN.md) first: run the agent as a dedicated low-privilege user, treat tokens as credentials, enable TLS in production, and don't put the server behind a reverse proxy.

## Contents

1. [Installation](#1-installation)
2. [The server](#2-the-server)
3. [The agent](#3-the-agent)
4. [Accounts and machines](#4-accounts-and-machines)
5. [Login and authentication](#5-login-and-authentication)
6. [Running commands & automation](#6-running-commands--automation)
7. [Self-service machine management (@machine)](#7-self-service-machine-management-machine)
8. [Rotating tokens](#8-rotating-tokens)
9. [MCP: for LLMs](#9-mcp-for-llms)
10. [Installing the skill for LLM assistants](#10-installing-the-skill-for-llm-assistants)
11. [Monitoring](#11-monitoring)
12. [Audit logs](#12-audit-logs)
13. [Troubleshooting](#13-troubleshooting)
14. [Upgrade notes](#14-upgrade-notes)

---

## 1. Installation

Three binaries, three jobs:

| Binary | Runs on | Purpose |
| --- | --- | --- |
| `towstrap-server` | a server with a public IP | SSH/HTTP entry + account/machine/MCP credential management |
| `towstrap-agent` | every machine to control | dials out to the server, executes remote sessions |
| `towstrap-mcp` | the machine running the LLM app (optional) | stdio MCP entry + skill installer |

### go install (recommended)

```bash
go install github.com/towstrap/towstrap/cmd/towstrap-server@latest
go install github.com/towstrap/towstrap/cmd/towstrap-agent@latest
go install github.com/towstrap/towstrap/cmd/towstrap-mcp@latest
```

### Build from source

```bash
git clone https://github.com/towstrap/towstrap && cd towstrap
make build    # produces bin/towstrap-server, towstrap-agent, towstrap-mcp
```

### Prebuilt binaries

See [Releases](https://github.com/towstrap/towstrap/releases); artifacts are named like `towstrap-agent-linux-arm64`. `make release` also produces `SHA256SUMS` and (with a signing key) minisign signatures — **verify before installing**:

```bash
shasum -a 256 -c SHA256SUMS --ignore-missing
minisign -Vm towstrap-agent-linux-amd64   # when a signature file exists
```

Linux, macOS and Windows are supported (amd64/arm64). On Windows the agent runs commands through `cmd.exe` (set `shell` to `powershell`/`pwsh`/git-bash `bash` — the flag is picked from the shell name: `/c` or `-Command`), but **there is no PTY** — `ssh host cmd` and MCP `run_command` work, interactive `ssh -t` returns unsupported. The server compiles for Windows too but that's a niche setup; its default paths (`/etc/towstrap` etc.) are Unix-style, so set them explicitly via flags or config.

---

## 2. The server

### Starting

```bash
# Minimal: SSH on :2222, HTTP on :8080, account DB /etc/towstrap/users.db
towstrap-server

# With a config file (recommended; examples/server.yaml is a fully-commented template)
towstrap-server --config server.yaml
```

The account DB defaults to `/etc/towstrap/users.db` — root only. Non-root users should pass `--users-db` to every `towstrap-server` command:

```bash
towstrap-server --users-db ~/.towstrap/users.db user add alice
towstrap-server --users-db ~/.towstrap/users.db &
```

At startup the server logs the **effective configuration** (`http=... ssh=... tls=... max_sessions=...` — secrets only show as set/unset). Check that line when wondering whether the yaml took effect.

### server.yaml reference

Precedence: **explicit CLI flags > yaml > built-in defaults** (flags are the yaml keys with `-` for `_`).

| Key | Default | Meaning |
| --- | --- | --- |
| `http` | `:8080` | HTTP port: `/health`, `/agent`, `/status`, `/mcp`, `/token/refresh`, `/skill` |
| `ssh` | `:2222` | SSH entry |
| `host_key` | `ssh_host_key` next to users_db | SSH host key; generated only if absent — unreadable/unparseable file aborts startup (never silently regenerated) |
| `users_db` | `/etc/towstrap/users.db` | account SQLite DB |
| `users_key` | `users_db` minus `.db` plus `.key` | token encryption key (0600, auto-generated; **back it up** — losing it orphans every token) |
| `admin_token` | empty | admin password for the full `/status` view; without it only agent tokens work (self view) |
| `public_url` | empty | public `wss://` address baked into install commands printed by `user add`/`machine add` |
| `tls` | `false` | serve the HTTP port over HTTPS/WSS |
| `cert` / `key` | empty | certificate paths; with `tls: true` and no cert, a self-signed pair is generated at `./tls_cert.pem`/`./tls_key.pem` |
| `allow_ips` | empty (allow all) | global source allowlist for SSH (also applies to `/mcp`) |
| `idle_verify` | `30m` | for TOTP-bound accounts, a session idle this long requires a fresh code on next keystroke; `0` disables |
| `min_agent_version` | empty (no limit) | reject agents self-reporting below this version (fleet rollout aid; self-reported, not a security control) |
| `audit_log` | root: `/var/lib/towstrap/server-audit.log`; others: `~/.towstrap/server-audit.log` | server audit log; `/dev/null` disables |
| `max_sessions` | `16` | concurrent SSH sessions per machine (`0` = unlimited) |
| `max_conns` | `4096` | total concurrent connections per port, SSH and HTTP each (`0` = unlimited) |
| `max_conns_per_ip` | `64` | per-source-IP SSH connection cap (SSH only; `0` = unlimited) |
| `ssh_idle_timeout` | `0` (off) | SSH idle timeout; kills hung unauthenticated connections but also idle interactive sessions — enable with care |
| `ssh_max_timeout` | `24h` | absolute SSH connection lifetime (`0` = unlimited) |
| `mcp` | off | embedded MCP section, see [9.2](#92-option-2-server-embedded-http-mcp) |

Corresponding flags: `--config --http --ssh --host-key --users-db --users-key --admin-token --public-url --tls --cert --key --allow-ip --idle-verify --min-agent-version --audit-log --max-sessions --max-conns --max-conns-per-ip --ssh-idle-timeout --ssh-max-timeout` (`--allow-ip` is repeatable).

### TLS

```bash
# With a real certificate (recommended, e.g. Let's Encrypt)
towstrap-server --tls --cert cert.pem --key key.pem --http :443

# No certificate: a self-signed pair is generated at ./tls_cert.pem / ./tls_key.pem (reused on restart)
towstrap-server --tls --http :443
```

With a self-signed cert, agents need `--insecure` (skips server identity verification — intranet/temporary use only). Use a trusted certificate for anything public.

TLS only affects the HTTP port (agent WebSocket, `/mcp`, `/status`, …); the SSH port has its own encryption either way.

### Audit log & resource limits

See the table above for audit log paths; the file rotates to `.1` at 16MB (the old file is overwritten) with 0600 permissions. Connection/session limits: `max_sessions`, `max_conns`, `max_conns_per_ip`, `ssh_idle_timeout`, `ssh_max_timeout`. The HTTP port additionally enforces a fixed 10s header-read timeout (Slowloris) and 2-minute idle timeout; `/agent` long-lived connections are unaffected.

---

## 3. The agent

### Running it

```bash
# Token from a file (recommended — the only source that supports remote rotation)
echo 'tsa-…' > ~/.towstrap-token && chmod 600 ~/.towstrap-token
towstrap-agent --server wss://your-server:443 --agent-token-file ~/.towstrap-token
```

`--server` accepts `ws://` and `wss://` (`http://`/`https://` are also understood and converted). On disconnect it retries with exponential backoff: starts at 2s, caps at 30s, with random jitter; a connection that stayed up for over a minute resets the backoff.

### Four ways to supply the token (in order of preference)

| Source | How | Remote rotation |
| --- | --- | --- |
| File (recommended) | `--agent-token-file path` or yaml `agent_token_file` (0600) | ✅ `token refresh` rewrites it atomically |
| Config file | yaml `agent_token` | ❌ |
| Environment | `TOWSTRAP_AGENT_TOKEN` | ❌ |
| Command line | `--agent-token tsa-...` (visible in `ps` — don't) | ❌ |

The agent strips `TOWSTRAP_AGENT_TOKEN` from the environment of spawned shells, so SSH users can't see it via `env`.

### agent.yaml reference

```yaml
agent:
  server: wss://your-server:443       # required; ws:// when the server has no TLS
  agent_token_file: /path/to/token    # recommended: 0600 file, supports remote rotation
  # agent_token: tsa-...              # literal token (no remote rotation)
  # shell: /bin/bash                  # defaults to $SHELL, then /bin/bash
  # insecure: true                    # only for self-signed server certs
  # quiet: true                       # mute desktop notifications/wall (audit still written)
  # audit_log: /path/audit.log        # default /var/lib/towstrap/audit.log (root) or ~/.towstrap/audit.log
```

Flags: `--config --server --agent-token --agent-token-file --shell --insecure --audit-log --quiet`.

### systemd

`examples/towstrap-agent.service` is a ready-made unit with full setup steps in its comments. The gist:

```bash
sudo useradd -r -m -s /bin/bash towstrap
sudo mkdir -p /etc/towstrap && sudo cp agent.yaml /etc/towstrap/
sudo chown towstrap:towstrap /etc/towstrap/agent.yaml /path/to/token_file
sudo chmod 600 /path/to/token_file     # the towstrap user must be able to read AND write it (refresh rewrites it)
sudo cp towstrap-agent.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now towstrap-agent
```

Note the unit uses `ProtectSystem=true`, not `full`: `full` mounts `/etc` read-only, which would break the atomic token-file rewrite during rotation.

### On-machine visibility

The agent keeps the machine's owner in the loop by default:

- **Notifications**: a desktop notification (macOS Notification Center / Linux `notify-send`) plus a `wall` broadcast fire when the active-session count goes 0→1 and 1→0; per-source cooldown is 10 minutes (audit still records everything — it just doesn't spam)
- **Audit**: every start logs `AGENT-START` (version, server, shell, insecure/quiet, uid); every session logs `START`/`END` (source `login@IP`, command, end)
- `--quiet` / `quiet: true` mutes notifications only; audit is always written; failed notifications don't affect sessions
- Running as root logs a warning: `agent is running as root: remote logins get a root shell`

---

## 4. Accounts and machines

### Concepts

- Login name = `account+machine` (e.g. `alice+office`). An account with exactly one machine can also log in with just the account name
- Creating an account automatically creates a machine named `default`; an account can own any number of machines, each with its own token
- Account and machine names: letters, digits, `.`, `_`, `-` (1–64 chars); `+` is the separator and can't appear in a name
- A second agent connecting with the same machine name replaces the old connection; different machine names under one account don't interfere
- Renaming an account (`user set --name`) doesn't affect agents — they authenticate by token, not name

### `user` subcommands

All run on the server against the account DB; shared options `--config` (reads users_db/users_key/public_url from yaml), `--users-db`, `--users-key`, `--server-url`.

| Command | Purpose |
| --- | --- |
| `user add NAME [--password P] [--contact C] [--allow-ip A]... [--agent-allow-ip A]... [--ssh-key K]... [--ssh-key-file F]` | create account; auto-creates the `default` machine and prints its token + install command |
| `user list` | list accounts: status, TOTP, key count, contact, allowlist, machines |
| `user set NAME [--password] [--name NEW] [--contact] [--clear-contact] [--allow-ip]... [--clear-allow] [--agent-allow-ip]... [--clear-agent-allow] [--ssh-key]... [--ssh-key-file] [--remove-ssh-key KEY-or-SHA256]... [--clear-ssh-keys] [--disable\|--enable]` | change password/rename/contact/allowlists/keys/disable |
| `user remove NAME` | delete account; all its machine tokens die |
| `user token NAME [--regen] [--admin]` | show token (single-machine accounts only). Owner confirmation required; `--regen` is the emergency path and needs `--admin` |
| `user totp NAME [--remove]` | enroll/unenroll TOTP |

Notes:

- Without `--password` a **16-char random password is generated and shown once** (only a bcrypt hash is stored); minimum password length is 10
- `user set --agent-allow-ip` applies to the account's single machine; use `machine set` when there are several
- `--disable` blocks both SSH and agents; connected agents are kicked within 30s
- Allowlist entries: IP, CIDR, `IP:port`, hostname, `*.domain`, `*`; unset = unrestricted

### `machine` subcommands

| Command | Purpose |
| --- | --- |
| `machine add ACCOUNT NAME [--agent-allow-ip A]... [--admin]` | add a machine, print its token (once). Owner confirmation required |
| `machine list [ACCOUNT]` | list machines (all accounts if omitted): login name, agent allowlist, token, created |
| `machine set ACCOUNT NAME [--agent-allow-ip]... [--clear-agent-allow]` | change this machine's agent source allowlist |
| `machine remove ACCOUNT NAME` | delete; token dies, connected agent dropped immediately |
| `machine token ACCOUNT NAME [--regen] [--admin]` | show this machine's token. Owner confirmation; `--regen` emergency needs `--admin` |

### Owner confirmation and --admin

Commands that issue or expose tokens — `machine add`, `machine token`, `user token` — first **ask for the account's SSH password** (plus a TOTP code if enrolled): shell access to the server doesn't imply the right to mint tokens for other people's accounts. `--admin` skips this but logs a warning and writes `MACHINE-ADD-ADMIN` / `MACHINE-TOKEN-ADMIN` / `MACHINE-TOKEN-REGEN-ADMIN` to the server audit log.

---

## 5. Login and authentication

### Password login

```bash
ssh -p 2222 alice@server          # single-machine account
ssh -p 2222 alice+office@server   # multi-machine accounts must name the machine
```

Logging into a multi-machine account without a suffix prints the machine list (with online status) and fails.

### TOTP second factor

```bash
towstrap-server user totp alice          # prints otpauth:// URI + manual secret; enter a code to confirm
towstrap-server user totp alice --remove # unenroll, back to password-only
```

Once enrolled:

- `ssh alice@...` asks for the password, then a 6-digit code (keyboard-interactive — every standard client supports it). The plain-password path **rejects TOTP-bound accounts outright**
- A code works only once within its time step (replay protection); wrong codes count toward brute-force limiting
- **Idle re-verification**: PTY sessions idle longer than `idle_verify` (default 30m, `0` disables) must enter a fresh code on the next keystroke (3 attempts); program output doesn't count as activity. Applies only to password-auth interactive sessions — public-key and exec sessions are exempt
- TOTP-bound accounts can't use password-only automation like `sshpass`; use a public key instead

### Public-key login (for automation)

```bash
towstrap-server user add bot --ssh-key "$(cat ~/.ssh/id_ed25519.pub)" --allow-ip automation-host-IP
towstrap-server user set bot --ssh-key-file ~/.ssh/towstrap_bot.pub   # add to existing account
```

Public-key login skips TOTP and the rate limiter (clients try several keys; counting failures would cause false lockouts). Pair it with `--allow-ip` to pin the source. Public-key logins **cannot** run `@machine` management commands.

### Rate limiting & lockout

Password-class authentication is limited on two dimensions (exact numbers in the [technical manual](technical-manual.md)):

- `account|source IP`: 5 failures within a 15-minute window → 1-minute lockout, doubling per further failure, capped at 1 hour — affects only that account from that IP
- `account` (all sources combined): 50 failures in 15 minutes → same schedule — rotating IPs against one account still gets caught
- Successful login clears both counters; server restart clears all; attempts while locked count as failures

### Allowlists (three layers)

| Layer | Controls | Set via |
| --- | --- | --- |
| Global `allow_ips` | who can reach the SSH port (and `/mcp`) | server.yaml / `--allow-ip` |
| Account `allow_ips` | who can SSH into this account | `user add/set --allow-ip` |
| Per-machine `agent_allow_ips` | where this machine's agent may connect from | `user add/set --agent-allow-ip` (single), `machine add/set --agent-allow-ip` (multi) |

- Allowlists are **hard checks**: off-list sources are rejected (SSH logs `AUTH-FAIL reason=allow-ip`, agents log `AGENT-DENY`)
- An unset agent allowlist permits any source, but a changed source IP logs `AGENT-IPCHANGE` and warns — a stolen token used elsewhere becomes visible immediately; set it when the machine's egress IP is stable
- Same entry syntax as the global list: IP, CIDR, `IP:port`, hostname, `*.domain`, `*`

Cloud firewalls (security groups) and these allowlists are two separate layers: packets pass the security group first, then TowStrap.

---

## 6. Running commands & automation

```bash
ssh -p 2222 alice@S 'uname -a'                 # run a command; stdout/stderr separate, real exit code
ssh -p 2222 -T alice@S                         # non-interactive shell without PTY
echo hello | ssh -p 2222 alice@S 'cat'         # stdin pipe; EOF reaches the subprocess
```

- Exit codes: the subprocess code is returned as-is; signal kills follow the shell convention 128+signal; "never started"/broken sessions return 255, and agent-side spawn failures appear on stderr with an `agent: ` prefix
- Single command limit is 64KB; every command runs in a fresh shell — `cd` and environment variables don't carry over
- **No scp/sftp**: transfer files with `cat`/heredoc (`ssh alice@S 'cat > f' < f`) or the MCP `read_file`/`write_file` tools
- Terminal-capable AI assistants (Claude Code, Codex, …) can use it as a plain ssh host with zero adaptation; for custom programs, any SSH library + public key works
- Every remote session gets a shell as **the OS user running the agent**

---

## 7. Self-service machine management (@machine)

Commands starting with `@` are executed by the server itself and never reach the agent. After SSH login, the account owner manages their machines:

```bash
ssh alice@S -p 2222 '@machine list'                 # machines: ID, online/offline, agent allowlist (no tokens)
ssh alice@S -p 2222 '@machine add build'            # add a machine; prints its token + install command
ssh alice@S -p 2222 '@machine add build --agent-allow-ip 10.0.0.5'
ssh alice@S -p 2222 '@machine remove build'         # delete; a connected agent drops immediately
ssh alice@S -p 2222 '@machine token build'          # show this machine's token
ssh alice@S -p 2222 '@machine help'                 # usage
```

Restrictions:

- **Password-class logins only**: public-key sessions are rejected (`MGMT-DENY reason=pubkey`) — keys are for automation, not management
- **TOTP-bound accounts must enter a fresh code** (the one used at login can't be replayed); 3 wrong codes disconnect, each logged as `MGMT-DENY reason=totp` and counted by the login rate limiter
- A `+machine` suffix in the login name is fine — it's handled by the account part
- Token rotation doesn't live here — run `towstrap-agent token refresh` on the machine (next section)

---

## 8. Rotating tokens

### Normal path: initiated on the controlled machine

```bash
# On one of alice's agent machines:
towstrap-agent token refresh                  # this machine only
towstrap-agent token refresh --machine build  # the "build" machine under the same account (must be online)
towstrap-agent token refresh --all            # every machine under the account
```

You'll be asked for the **account password** (plus a TOTP code if enrolled) — the authentication is twofold: the local agent token proves "you're on a registered machine", and password+TOTP proves "you're the account owner".

The flow is **push + acknowledgement**: the server sends the new token over the target machine's existing WebSocket, the agent writes it atomically to its token file (same-dir temp file → rename, 0600) and acknowledges; **only then does the server retire the old token in the DB**. The connection stays up, the agent doesn't restart.

Prerequisites and notes:

- The target's token must come **from a file** (`--agent-token-file` / `agent_token_file`), otherwise the result is `no-file`
- The target must be **online**, otherwise `offline`
- Over plaintext `ws://` to a non-loopback server, password submission requires `--allow-plain` (passwords mustn't travel in the clear)
- The agent re-reads the token file on every reconnect, so editing the file by hand also takes effect

### Per-machine result statuses

| status | Meaning |
| --- | --- |
| `ok` | new token written to that machine's token file |
| `offline` | agent not connected; nothing changed |
| `no-file` | token didn't come from a file; can't be rotated remotely |
| `timeout` | agent didn't acknowledge within the deadline (10s); DB unchanged |
| `not-found` | machine doesn't exist |
| `error` | anything else; watch for "agent wrote the new token but the server DB update failed" — an inconsistency needing manual repair |

Exit code: 0 if all ok, 1 on partial failure, 2 on argument/auth errors.

### Emergency rotation (machine offline or lost)

```bash
towstrap-server machine token alice build --regen --admin   # warns + logs MACHINE-TOKEN-REGEN-ADMIN
```

The old token dies immediately; afterwards write the new token into that machine's token file (the agent re-reads it on reconnect) or pass it via `--agent-token` on restart.

---

## 9. MCP: for LLMs

LLMs get four MCP tools on controlled machines: `list_machines` (what machines exist), `run_command` (run a command; separate stdout/stderr/exit_code), `read_file`, `write_file`. Both transports behave identically — the difference is where the MCP server runs:

| | stdio (`towstrap-mcp`) | server-embedded HTTP (`/mcp`) |
| --- | --- | --- |
| MCP server runs on | machine B running the LLM | the TowStrap server S |
| Needed on B | `towstrap-mcp` + a passphrase-less SSH key | nothing — URL + Bearer token |
| Execution path | B SSHes to S, lands on the agent | S reaches the agent directly via the Hub |
| Which machines | hardcoded in mcp.yaml | per-client `--machine` grants on the token |
| Approval fallback | `towstrap-mcp pending/approve/deny` (on B) | `towstrap-server mcp pending/approve/deny` (on S) |
| Best for | your own machine | handing access to others / many clients |

### 9.1 Option 1: stdio (towstrap-mcp)

Config defaults to `~/.config/towstrap/mcp.yaml` (`--config` overrides; `examples/mcp.yaml` is a fully-commented template):

```yaml
server: ssh.example.com:2222        # the TowStrap server's SSH entry
key: ~/.ssh/towstrap_bot            # passphrase-less private key (no way to type one)
known_hosts: ~/.ssh/known_hosts     # or pin with host_key: SHA256:... (one of the two required)
machines:
  office:                            # key = SSH login name (account or account+machine)
    description: dev box, code in ~/work/app
    roots: [~/work]                  # write_file inside these dirs is auto-allowed
policy:
  default: ask                       # run|ask|deny, default ask
  ask_timeout: 5m
limits:
  timeout: 120s                      # default run_command timeout
  max_timeout: 1h                    # cap for the timeout_seconds parameter
  max_output: 65536                  # per-stream return cap; overruns keep head+tail
  max_file: 1048576                  # read_file/write_file size cap
approvals_dir: ~/.config/towstrap/approvals   # pending approvals land here (no popup support)
```

First register the public key with the account: `towstrap-server user set office --ssh-key-file ~/.ssh/towstrap_bot.pub`. If known_hosts lacks the server, run `ssh-keyscan -p 2222 server >> ~/.ssh/known_hosts`, or write `host_key: SHA256:...` in the yaml.

Claude Code `mcpServers` snippet (`command` must be absolute):

```json
{
  "mcpServers": {
    "towstrap": {
      "command": "/usr/local/bin/towstrap-mcp",
      "args": ["--config", "/Users/you/.config/towstrap/mcp.yaml"]
    }
  }
}
```

### 9.2 Option 2: server-embedded HTTP (/mcp)

Add an `mcp:` section to `server.yaml` (off by default):

```yaml
mcp:
  enabled: true
  # path: /mcp                 # mount path, default /mcp
  # allow_plain_http: false    # plaintext HTTP + non-loopback bind refuses to start; enable only for intranet/tunnel
  # approvals_dir: /var/lib/towstrap/approvals   # default: approvals/ next to the audit log
  # machines:                  # optional: descriptions and write_file roots shown to MCP clients
  #   bot+default: { description: "office box", roots: ["~/work"] }   # key = full machine ID
  # policy / limits: same format as mcp.yaml; built-in defaults when absent
```

Then issue a token per client:

```bash
towstrap-server mcp add laptop --machine alice            # all of alice's machines
towstrap-server mcp add builder --machine alice+build     # one machine only
towstrap-server mcp add everything --machine '*'          # all machines
towstrap-server mcp add ops --machine alice --machine bob # several accounts
```

Four `--machine` forms: `'*'` (everything), `'alice'` (all of the account's), `'alice+*'` (same, explicit wildcard), `'alice+office'` (one machine). Referencing a not-yet-existing machine only warns — you can mint credentials before creating machines.

Clients (Claude Code etc.) only need URL + token (`mcp add` prints a ready-made snippet):

```json
{
  "mcpServers": {
    "towstrap": {
      "type": "http",
      "url": "https://server:8080/mcp",
      "headers": { "Authorization": "Bearer tsm-..." }
    }
  }
}
```

`tsm-` tokens are shown once; rotate with `mcp token NAME --regen` (the old one dies instantly).

### 9.3 MCP client subcommands

| Command | Purpose |
| --- | --- |
| `mcp add NAME --machine GRANT... [--allow-ip A]...` | issue a client token (shown once); prints client config + skill install commands |
| `mcp list` | list clients: machine grants, source allowlist, status, created |
| `mcp set NAME [--machine]... [--allow-ip]... [--clear-allow] [--disable\|--enable]` | change grants/allowlist/enabled |
| `mcp remove NAME` | delete; token dies |
| `mcp token NAME [--regen]` | show/rotate token |
| `mcp pending [--approvals-dir DIR] [--config server.yaml]` | list pending approvals |
| `mcp approve <id>\|--all` / `mcp deny <id>\|--all` | approve/deny pending requests |

Approvals-dir lookup order: `--approvals-dir` > `mcp.approvals_dir` in server.yaml > `approvals/` next to the audit log.

`--allow-ip` adds a per-client source allowlist (off-list sources are rejected even with a valid token — `MCP-AUTH-FAIL reason=client-allow-ip`).

### 9.4 The three policy levels

Every `run_command` passes through the policy (`policy` section):

- `deny` matches are **rejected outright** (root deletion, mkfs, shutdown, `curl|sh`, private keys/sudoers, `sudo`, touching the agent itself, …)
- `allow` matches are read-only/low-risk commands that **run automatically** (`ls`, `cat`, `git status`, …); commands are split on `&&`, `||`, `;`, `|`, newlines, and **every segment** must match an allow rule; a segment containing backticks, `$(`, `>`, `<`, or `&` is never auto-allowed
- everything else falls to `policy.default` (default `ask` = human approval)

`read_file` needs no approval but is bounded by `deny_paths` (private keys, credentials, the agent's own token/config are denied by default). `write_file` inside a machine's `roots` is auto-allowed, outside needs approval; `deny_paths` still applies first.

The built-in lists live in `internal/mcpsrv/policy.go` (`DefaultAllow`/`DefaultDeny`/`DefaultDenyPaths`); setting a key in yaml **replaces the whole list**, it doesn't append.

⚠️ Policy is a filter, **not a sandbox**: shell syntax can always route around naive splitting. The real boundary is the agent's OS user. `roots` uses **textual prefix matching** without resolving remote symlinks — a `~/work/link -> /etc` symlink lets `write_file ~/work/link/x` escape the roots check. Don't put such links inside roots.

### 9.5 Human approval

Two paths for approval-required actions:

1. **Popup**: MCP clients supporting elicitation get an "allow execution" prompt, with a "don't ask again for this command in this session" checkbox
2. **Local fallback**: without popup support, the pending request lands in `approvals_dir` (stdio mode also fires a desktop notification); a human runs `towstrap-mcp approve <id>` (stdio) or `towstrap-server mcp approve <id>` (embedded)

Requests time out and are denied after `ask_timeout` (default 5 minutes).

---

## 10. Installing the skill for LLM assistants

The repo ships a skill that teaches coding assistants how to use TowStrap safely (`skills/towstrap/SKILL.md`). Three ways to get it:

### Straight from the server (no towstrap-mcp needed)

```bash
mkdir -p ~/.claude/skills/towstrap && curl -fsSL https://server:8080/skill -o ~/.claude/skills/towstrap/SKILL.md
# other assistants: Cursor ~/.cursor/skills/, Codex/Grok share ~/.agents/skills/
# add -k to curl if the server uses a self-signed certificate
```

`GET /skill` needs no credentials (it's a public document); the tail of `mcp add` output includes these commands too.

### One-shot install via towstrap-mcp

```bash
towstrap-mcp connect                  # install into every detected harness
towstrap-mcp connect list             # what's supported, detected, installed
towstrap-mcp connect --path .claude/skills   # one specific dir (e.g. project-level)
towstrap-mcp connect uninstall        # uninstall (files you modified are kept unless --force)
towstrap-mcp connect --dry-run        # rehearsal, writes nothing
```

Supported: Claude Code, Codex, Grok Build, Cursor, Gemini CLI, OpenCode, GitHub Copilot CLI, Devin CLI (detected by their home dirs; Codex and Grok share `~/.agents/skills`, written once). An install writes `<skills-dir>/towstrap/SKILL.md` plus a `.towstrap-managed.json` manifest; a same-named skill you placed yourself is never overwritten without `--force`.

### Manual copy

Copy `skills/towstrap/` into any assistant's skills directory — same result.

### print-mcp: print per-client config snippets

```bash
towstrap-mcp connect print-mcp --url https://server:8080/mcp --token tsm-...
towstrap-mcp connect print-mcp --stdio [--config mcp.yaml]
```

Prints MCP config for Claude Code / Codex / Grok / Cursor / Gemini / OpenCode (writes nothing). The token is a credential — keep it out of chats and repos.

---

## 11. Monitoring

```bash
# Liveness: no auth
curl https://server:8080/health        # ok

# Who's online: two credential types
curl -H "X-Admin-Token: <admin_token>" https://server:8080/status   # admin sees everything
curl -H "X-Agent-Token: tsa-..."       https://server:8080/status   # a machine token sees only itself
```

`/status` returns:

```json
{"ok":true,"http":":8080","ssh":":2222","users":[{"user":"alice","machine":"alice+default","online":true}]}
```

The admin token lists every machine (`machine` is the full login name); a machine token sees only itself — ordinary users can't enumerate the fleet. With no machines online, `ok:false` and HTTP 503.

---

## 12. Audit logs

Both sides keep their own log in `<time> <event> k=v` format, rotating to `.1` at 16MB, mode 0600, with control characters scrubbed from values.

**Agent side** (default `/var/lib/towstrap/audit.log` or `~/.towstrap/audit.log`):

| Event | Meaning |
| --- | --- |
| `AGENT-START` | process start: version, server, shell, insecure/quiet, uid, audit path |
| `START` / `END` | each remote session: id, source `login@IP`, mode, command |
| `TOKEN-ROTATED` | a pushed new token was written to the token file |

**Server side** (default `/var/lib/towstrap/server-audit.log` or `~/.towstrap/server-audit.log`; `/dev/null` disables):

| Event | Meaning |
| --- | --- |
| `AUTH-OK` / `AUTH-FAIL` | SSH auth: user, ip, method (password/kbd-interactive/publickey), failure reason (locked/password/disabled/allow-ip/totp) |
| `AGENT-CONNECT` / `AGENT-DISCONNECT` | agent up/down: id, ip, version |
| `AGENT-REPLACE` | a same-named agent replaced the old connection |
| `AGENT-DENY` | agent rejected: reason=agent-allow (allowlist) / old-version |
| `AGENT-IPCHANGE` | agent's source IP changed (no allowlist) — a classic sign of a leaked token |
| `AGENT-REVOKE` | periodic check found a dead credential (rotated token / removed machine / disabled account); dropped on the spot |
| `SESSION-START` / `SESSION-END` | SSH/MCP sessions: user, from, id, mode (pty/exec/mcp), machine, cmd (truncated >512B); END carries the exit code |
| `SESSION-DENY` | session refused: reason=cmd-too-long/no-machine/ambiguous/offline/credential/open |
| `MGMT-DENY` | `@` command refused: reason=pubkey/locked/totp |
| `MACHINE-ADD` / `MACHINE-REMOVE` / `MACHINE-TOKEN` | SSH self-service: add/remove machine, show token |
| `MACHINE-ADD-ADMIN` / `MACHINE-TOKEN-ADMIN` | CLI `--admin` skipped owner confirmation |
| `MACHINE-TOKEN-REGEN-ADMIN` | CLI `--admin` emergency token rotation |
| `TOKEN-REFRESH` | rotation: one line per machine, with `agent:caller@IP` origin and result status |
| `TOKEN-REFRESH-DENY` | rotation refused: reason=content-type/token/agent-allow/locked/body/password/totp |
| `MCP-SESSION` | MCP client session: client, ip (deduped within 30s) |
| `MCP-AUTH-FAIL` | MCP auth failure: reason=allow-ip/token/client-allow-ip |
| `MCP-POLICY-DENY` | policy deny/deny_paths hit: client, machine, kind, detail |
| `MCP-ASK` / `MCP-APPROVED` / `MCP-DENIED` / `MCP-ASK-TIMEOUT` | approval flow: via=elicit/local, three outcomes |

---

## 13. Troubleshooting

| Symptom | Cause & fix |
| --- | --- |
| `machine not online (agent not connected)` | the agent isn't running or can't reach the server. Check agent logs; verify `--server` address/port and token file contents |
| `credential for this machine is no longer valid` | token was rotated, machine removed, or account disabled. Get the current token via `machine token` and update the agent's token file |
| SSH warns the host key changed | the server's `ssh_host_key` was replaced. Confirm whether the server was reinstalled; if yes, remove the stale `~/.ssh/known_hosts` line — if no, treat it as a MITM |
| repeated `Permission denied` | check whether the account is disabled (`user list`), whether your IP is on the allowlist, or whether you're rate-limited (wait out the lock — starts at 1 minute) |
| password login fails after TOTP enrollment | expected: TOTP-bound accounts must use keyboard-interactive (password + code); use a public key for automation |
| `mcp` won't start: `mcp on plaintext HTTP...` | `/mcp` on plaintext HTTP + non-loopback bind refuses to start. Set `tls: true`, or set `mcp.allow_plain_http: true` only if it's truly intranet/tunneled |
| MCP client gets 401 | wrong/deleted/disabled token (`mcp list`), or source not in the client's `--allow-ip` |
| `token refresh` says `no-file` | that machine's token didn't come from a file — switch to `--agent-token-file`, restart the agent, and future rotations will work remotely |
| `token refresh` says `offline`/`timeout` | target offline or didn't acknowledge; DB unchanged — retry |
| `token refresh` gets 429 | too many bad passwords/TOTP codes; wait out the lockout (starts at 1 minute, doubles up to 1 hour) |
| frequent `AGENT-REPLACE` | two agents with the same machine name keep displacing each other, or the token was copied elsewhere. Check for duplicate processes; rotate the token if you suspect a leak |
| connections exhausted | look for `connection limit reached` rejections; tune `max_conns`/`max_conns_per_ip` |

---

## 14. Upgrade notes

- **Automatic DB migration**: upgrading from the old one-token-per-account layout, `Open` moves each account's token, agent allowlist, and last source IP into a machine named `default` — tokens don't change, agents don't need touching; the login name becomes `account+default` (the bare account name still works for single-machine accounts)
- **`users_key` unset**: defaults to `users_db` minus `.db` plus `.key` (`/etc/towstrap/users.db` → `/etc/towstrap/users.key`); back up the DB and key together
- **SSH host key**: defaults to `ssh_host_key` next to `users_db`; carry it over when moving the DB or every client will warn about a changed host key
- Agent and server versions don't have to match; the server can retire old agents via `min_agent_version` (self-reported — not a security control)
