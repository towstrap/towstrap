<div align="center">

<img src="assets/logo.svg" alt="TowStrap" width="128" />

# TowStrap

[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8.svg)](https://go.dev/)
[![CI](https://github.com/towstrap/towstrap/actions/workflows/ci.yml/badge.svg)](https://github.com/towstrap/towstrap/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%C2%B7%20macOS%20%C2%B7%20Windows-lightgrey.svg)]()
[![MCP](https://img.shields.io/badge/MCP-ready-green.svg)]()
[![Release](https://img.shields.io/github/v/release/towstrap/towstrap)](https://github.com/towstrap/towstrap/releases)

**The tow strap between you (or your LLM) and machines behind NAT**

[中文](README.md) | English

</div>

---

## Overview

The machine you need is behind NAT or a firewall with no public IP. An agent on that machine opens an outbound WebSocket to your server; afterwards, **humans connect over SSH and LLMs over MCP**, both landing on that machine through the server — no sshd, no public IP, no router changes.

The one-sentence difference from ShellHub, Teleport, or RevoShell: **the same system serves both humans (SSH with password/TOTP/public key) and LLMs (MCP with three policy levels and human approval), and token rotation is initiated on the controlled machine itself by default** — a server admin who wants to re-credential someone else's machine remotely must pass `--admin` explicitly, and it is audited.

Three single binaries + SQLite — no Docker, no web UI, no external dependencies; all data stays in your infrastructure.

(The name comes from a tow strap: flat, tough, and made for pulling one vehicle with another.)

---

## Features

**Access**

- **Reverse connection, zero inbound**: the agent dials out over WebSocket — the controlled machine opens no ports and needs no public IP
- **Standard SSH client**: `ssh alice+office@server -p 7822` drops you into a shell — any SSH client works, desktop or phone (Termius etc.), nothing to install
- **exec mode**: `ssh host 'command'` returns separate stdout/stderr and the real exit code — ready for automation
- **Multiple machines per account**: each machine gets its own token; revoking one takes effect immediately without touching the others

**Relayable terminals (mirror)**

- **tmux-style persistent terminals, zero dependencies**: built into the agent, no tmux/screen needed — a mirror started at the machine is picked up from a phone or another computer via `ssh -t host mirror work`, with a shared multi-client view
- **Detach without killing**: `Ctrl-\` detaches and the job keeps running; new mirrors start in the directory you ran the command from; `mirror ls`/`mirror kill` manage them; idle mirrors are reaped (`mirror_idle`, default 72h, tunable)
- **Humans only**: mirrors live behind a local `0600` socket with a peer-uid check, deliberately not exposed over MCP — the AI can't reach your terminals

**For LLMs (MCP)**

- **Three tool families**: `run_command`/`read_file`/`write_file` plus a real-PTY terminal family (`terminal_open/write/read/resize/close/list`, session-scoped temporary terminals)
- **Three policy tiers + human approval**: configurable deny/allow/approval regex lists; an approval binds to machine + tool kind + command + cwd + stdin digest — change any input and it asks again
- **Two ways in**: server-embedded HTTP (`/mcp` + Bearer `tsm-` token) or local stdio (`towstrap-mcp`)
- **Shipped LLM skill**: fetch via `GET /skill`, or `towstrap-mcp connect` installs it into every detected coding assistant at once

**Accounts & authentication**

- **Self-service onboarding**: run `towstrap register` on the controlled machine — no account → sign up in place, have one → log in and attach the machine; the server gates it with `register`/`register_invite`
- **One machine, one account**: a machine fingerprint (motherboard-UUID hash, survives OS reinstalls) binds to exactly one account; re-registering offers recovery guidance
- **Password + TOTP + public key in any combination**; OAuth one-time SSH grants for sign-in (a temporary ticket can't reach the management surface)
- **Self-service management**: after `ssh` login, `@machine list/add/remove/token` manages your machines and `@totp` binds/unbinds the second factor (fresh TOTP check required); `towstrap totp` does the same right on the machine
- **Token rotation**: `towstrap token refresh` — the server pushes the new token, the agent writes it atomically, the old one is retired only after acknowledgement; a half-failed rotation falls back to the previous token and heals itself

**Security & visibility**

- **Brute-force defense**: rate limiting on account×IP and account dimensions with exponential-backoff lockouts — distributed spraying across IPs still accumulates
- **Minimal credential exposure**: tokens live in `0600` files; `TOWSTRAP_AGENT_TOKEN` never reaches child environments; the agent reports its token/config paths so the server adds them to the MCP deny list — the AI can't read your credentials
- **Audit on both sides**: server and agent each keep their own log — connections, executions, approvals, token rotations; approved operations carry an authorization ID you can trace
- **Visible on the controlled machine**: desktop notification + `wall` broadcast on session start/end — remote access is never silent

---

## ⚠️ Read This First (Security)

**Your responsibility**:

- **Commands run for real**: remote commands execute as the OS user running the agent — use a dedicated low-privilege user (running as root prints a warning, because every remote session would be a root shell)
- **MCP deny/allow/approval is a filter, not a sandbox**: shell syntax can route around naive command splitting — the real boundary is the agent's OS user
- **Tokens are credentials**: `tsa-` (agent) and `tsm-` (MCP client) tokens are keys to the door — keep files at `0600`, never put tokens in shell history, logs, repos, or chat
- **TLS is required in production**: over plaintext, tokens and passwords travel in the clear; plaintext HTTP on a non-loopback bind refuses to start by default (`allow_plain_http: true` is the explicit opt-out for trusted LANs/tunnels)
- **Do not put TowStrap behind a reverse proxy**: Nginx or a cloud load balancer rewrites the source IP to the proxy's own address — IP allowlists, rate limiting, and IP-change alerts silently stop working unless you know exactly what you are doing
- **Disclaimer**: this project is provided under the AGPL-3.0 license; the authors accept no liability for losses caused by its use

---

## Architecture

```
      human                     LLM client (Claude Code / Cursor / Codex…)
  ssh alice+office@S -p 7822    MCP https://S:7880/mcp  Bearer tsm-…
        │  password + TOTP        │  policy → approval prompt → run
        ▼                         ▼
   ┌───────────────── towstrap-server (S)───────────────────┐
   │  SSH :7822    HTTP :7880  /agent  /mcp  /token/refresh │
   │  accounts SQLite · audit log · rate limit · policy     │
   └───────────────┬────────────────────────────────┬───────┘
                   │ outbound WebSocket, tsa-…      │
        ┌──────────▼──────────┐          ┌──────────▼──────────┐
        │ towstrap            │          │ towstrap            │
        │ alice+office        │          │ alice+build         │
        │ local shell         │          │ local shell         │
        │ (low-priv user)     │          │                     │
        └─────────────────────┘          └─────────────────────┘
```

---

## Install

There is exactly one install path: **the sh script**. It downloads the right binary for your platform and verifies SHA256 (a failed check aborts the install; `--no-verify` is the explicit escape hatch).

### Controlled machine (agent)

```bash
# Official server (address is baked into the script)
curl -fsSL https://towstrap.vast-plan.com/install.sh | sh

# Self-hosted: the script connects back to whichever server served it
curl -fsSL http://S:7880/install.sh | sh -s -- --token tsa-…
```

Add `--systemd` to also install a system service; `--token tsa-…` supplies the credential directly (get one from your admin, or run `towstrap register` to self-sign-up first).

### Server

```bash
curl -fsSL https://raw.githubusercontent.com/towstrap/towstrap/main/scripts/install-server.sh | sudo sh
# On Linux as root it installs and starts a systemd unit (--no-systemd installs
# binary+config only, which is also the macOS path); binaries come from GitHub
# Releases, SHA256SUMS verified
```

Then run `sudo towstrap-server init` — the wizard configures the public URL, self-signup, and the first account in one pass.

On Windows the agent's interactive sessions use ConPTY (Windows 10 1809+ required) — see the [User Guide](docs/en/user-guide.md).

---

## Quick Start

On the official server (self-register, no admin needed):

```bash
# After installing on the controlled machine, onboard: it asks whether you
# have an account — no → sign up, yes → log in and attach this machine
towstrap register

# On your laptop
ssh -p 7822 alice@towstrap.vast-plan.com                            # land in that machine's shell
ssh -p 7822 alice@towstrap.vast-plan.com 'uname -a'                 # or run a command directly
ssh -t -p 7822 alice@towstrap.vast-plan.com 'mirror work'           # pick up the persistent terminal (Ctrl-\ detaches)
```

Self-hosting? `install-server.sh` + the `init` wizard gets you there in two steps; install the agent with `--token` and SSH in the same way.

For LLM use (optional): set `mcp.enabled: true` in `server.yaml`, restart, then issue an MCP token and paste the printed config into Claude Code / Cursor:

```bash
towstrap-server mcp add laptop --machine alice
```

Enable TLS in production (`--tls` or `tls: true` in server.yaml) — details in the [User Guide](docs/en/user-guide.md).

---

## Scenario: the AI assistant keeps working while you leave

Put the long-running TUI (an AI coding assistant, `vim`, `top`…) inside a mirror and walk away — the screen follows you, **in both directions**:

```bash
# Started at the machine, picked up on the phone:
mirror work                          # create a mirror named work, in the current directory
claude                               # start your AI coding assistant inside (any TUI works)
#   …dispatch the task, Ctrl-\ to detach — it keeps running; clock out
ssh -t -p 7822 alice@towstrap.vast-plan.com 'mirror work' # reattach on the road — same screen
```

```bash
# Started on the phone, picked up back at the desk (any ssh client, e.g. Termius):
ssh -t -p 7822 alice@towstrap.vast-plan.com 'mirror fix'  # create fix, dispatch, Ctrl-\ to detach
ssh -t -p 7822 alice@towstrap.vast-plan.com 'mirror fix'  # home at the desk — same command, same screen
```

Several devices can attach to the same mirror at once (shared view). To get "remind me when a mirror exists, optionally auto-attach" in everyday terminals: `mirror setup --write` adds a hook to your shell rc (reminder-only by default — put a name in `TOWSTRAP_MIRROR_AUTO=` inside the block to auto-attach it).

---

## Documentation

| | | |
| --- | --- | --- |
| 📘 User Guide | [docs/en/user-guide.md](docs/en/user-guide.md) | Install, accounts & machines, allowlists, TOTP, MCP, skill, token rotation, monitoring, troubleshooting |
| 🛠 Technical Manual | [docs/en/technical-manual.md](docs/en/technical-manual.md) | Architecture, wire protocol, auth & rate limiting, data model & crypto, token lifecycle, MCP policy & approval, audit events, config & CLI reference |
| 🌐 中文 | [README.md](README.md) · [用户手册](docs/zh/user-guide.md) · [技术手册](docs/zh/technical-manual.md) | 中文文档 |

---

## Tech Stack

| Component | Choice |
| --- | --- |
| Language | Go 1.25+ |
| SSH server | [gliderlabs/ssh](https://github.com/gliderlabs/ssh) + golang.org/x/crypto |
| WebSocket | [gorilla/websocket](https://github.com/gorilla/websocket) |
| Storage | SQLite ([modernc.org/sqlite](https://gitlab.com/cznic/sqlite), pure Go, no CGO) |
| MCP | [modelcontextprotocol/go-sdk](https://github.com/modelcontextprotocol/go-sdk) |
| PTY | [creack/pty](https://github.com/creack/pty) |
| Config | gopkg.in/yaml.v3 |

---

## Project Layout

```
├── cmd/
│   ├── towstrap-server/   # server + account/machine/MCP-client management + init wizard
│   ├── towstrap/          # controlled-machine agent (register/totp/token/mirror)
│   └── towstrap-mcp/      # stdio MCP entry + skill installer (connect)
├── internal/
│   ├── server/            # SSH/HTTP servers, Hub, auth rate limiting, token rotation, embedded MCP
│   ├── client/            # agent connection, session execution, on-machine presence, named mirrors
│   ├── accounts/          # SQLite store: users/machines/MCP clients/grants/fingerprints, crypto
│   ├── mcpsrv/            # MCP tools, policy engine, human approval, remote path resolution, SSH pool
│   ├── proto/             # WebSocket wire protocol
│   ├── harness/           # coding-assistant detection & skill install
│   ├── auditlog/          # two-sided audit log (rotation, control-char scrubbing)
│   ├── oidc/ + totp/      # OAuth grants, TOTP second factor
│   ├── machineid/         # machine fingerprint (motherboard UUID hash)
│   ├── monitor/ + notify/ # metrics monitoring, desktop notifications
│   ├── allow/ + auth/     # IP/host allowlists, password verification
│   ├── config/            # yaml config loading & merging
│   └── e2e/               # end-to-end tests (real server, real agent)
├── skills/towstrap/       # LLM skill shipped with the project (embedded)
├── scripts/               # install.sh / install-server.sh / install.ps1
├── examples/              # server.yaml / agent.yaml / mcp.yaml / systemd unit / nginx
├── docs/                  # Chinese & English user guides and technical manuals
└── assets/                # logo and other assets
```

Development: clone the repo and `make build` produces the three binaries under `bin/`; `make release` cross-compiles all platforms and generates SHA256SUMS (set `MINISIGN_KEY_FILE` to also sign with minisign).

---

## Star History

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=towstrap/towstrap&type=Date&theme=dark" />
  <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=towstrap/towstrap&type=Date" />
  <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=towstrap/towstrap&type=Date" />
</picture>

## License

[AGPL-3.0](LICENSE)
