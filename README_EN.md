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

## ⚠️ Read This First (Security)

**Defenses built into the system**:

- **Authentication + brute-force resistance**: password / TOTP 2FA / public key in any combination; rate limiting on both account×IP and account with exponential-backoff lockouts — distributed password spraying across IPs is covered; an agent reconnecting from a new IP writes an `AGENT-IPCHANGE` alert
- **Minimal credential exposure**: tokens live in `0600` files (the only kind the server can rotate remotely); `TOWSTRAP_AGENT_TOKEN` is stripped from child environments; the agent reports its token/config files so the server adds them to the MCP file-tool deny list — the AI can't read your credentials; passwords over non-loopback plaintext require explicit `--allow-plain`; `/mcp` refuses to start on plaintext HTTP bound to a non-loopback address
- **The boundary is the system user**: remote commands run as the agent's OS user — a dedicated low-privilege user is the real boundary (running as root logs a warning); the MCP deny list protects the agent itself: killing the process, stopping the service, or overwriting the binary is refused outright
- **The AI can't reach your terminals**: MCP terminals are session-scoped temporary PTYs and cannot attach to a `mirror`; the mirror socket is `0600` plus a peer-uid check (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS) — only the agent's own user can connect
- **Audited and visible**: session start/end pops a desktop notification + `wall` broadcast; both sides audit — connections, executions, approvals, token rotations, mirror kills; approved operations carry an authorization record (`MCP-AUTH-EXEC`) and unanswered prompts time out as denied; rotating another machine's token requires explicit `--admin` and is audited — normally only the machine itself can initiate
- **Your data stays in your infrastructure**: the account store is local SQLite on your server — self-hosted, no third-party cloud

**Your responsibility**:

- **Commands run for real**: remote commands execute as the OS user running the agent on the controlled machine. Run the agent under a dedicated low-privilege user — running it as root prints a warning, because every remote session would be a root shell.
- **MCP deny/allow/approval is a filter, not a sandbox**: shell syntax can route around naive command splitting. The real boundary is the agent's OS user.
- **Tokens are credentials**: `tsa-` (agent) and `tsm-` (MCP client) tokens are keys to the door. Keep token files at `0600`; never put tokens in shell history, logs, repos, or chat.
- **TLS is required in production**: over plaintext `ws://`/`http://`, tokens and passwords travel in the clear; `/mcp` refuses to start on plaintext HTTP bound to a non-loopback address.
- **Do not put TowStrap behind a reverse proxy**: Nginx or a cloud load balancer rewrites the source IP to the proxy's own address, which silently disables IP allowlists, rate limiting, and `AGENT-IPCHANGE` alerts — unless you know exactly what you are doing.
- **Disclaimer**: this project is provided under the AGPL-3.0 license; the authors accept no liability for losses caused by its use.

## Overview

TowStrap solves a common problem: the machine you need is behind NAT or a firewall with no public IP. An agent on that machine opens an outbound WebSocket to your server; afterwards, humans connect over SSH and LLMs over MCP, both landing on that machine through the server — **no sshd, no public IP, no router changes**.

The one-sentence difference from ShellHub, Teleport, or RevoShell: **the same system serves both humans (SSH with password/TOTP/public key) and LLMs (MCP with three policy levels and human approval), and token rotation is initiated on the controlled machine itself by default** — a server admin who wants to re-credential someone else's machine remotely must pass `--admin` explicitly, and it is audited.

(The name comes from a tow strap: flat, tough, and made for pulling one vehicle with another.)

## Features

- **Reverse connection, zero inbound**: the agent dials out over WebSocket — the controlled machine opens no ports and needs no public IP
- **Standard SSH client**: `ssh alice+office@server -p 7822` drops you into a shell; no client software to install
- **Layered authentication**: password + TOTP second factor + public key (for automation), with per-account and global IP allowlists
- **Brute-force defense**: rate limiting on both account×IP and account dimensions with exponential backoff lockout — distributed attacks rotating IPs are still caught
- **Multiple machines per account**: each machine gets its own token; revocation of one machine takes effect immediately without touching the others
- **Machine-initiated token rotation**: `towstrap token refresh` — the server pushes the new token over the live connection, the agent writes it atomically, and the old token is retired only after acknowledgement
- **Self-service for account owners**: after `ssh` login, `@machine list/add/remove/token` manages your machines and `@totp` binds/unbinds the second factor (fresh TOTP check required; public-key logins are rejected) — `towstrap totp` does the same right on the machine
- **exec mode**: `ssh host 'command'` returns separate stdout/stderr and the real exit code — ready for automation
- **Relayable terminals (named mirrors)**: tmux-style persistent terminals built into the agent, no tmux needed — a mirror started at the machine can be picked up from a phone or another computer via `ssh -t host mirror <name>`: shared multi-client view, `Ctrl-\` detaches without killing, new mirrors start in the directory you ran the command from, and idle mirrors are killed automatically (`mirror_idle`, default 72h, tunable or off). `mirror` is a symlink alias of the agent. This is a human feature, not exposed over MCP
- **MCP in two modes**: server-embedded HTTP (`/mcp`, Bearer token) or local stdio (`towstrap-mcp`) — file/command/terminal tools, three policy levels, approval prompts
- **A shipped LLM skill**: `GET /skill` serves it directly, or `towstrap-mcp connect` installs it into 8 coding assistants at once
- **Audit on both sides**: server and agent each keep their own log — who connected, what ran, when tokens rotated
- **Visible on the controlled machine**: desktop notification + `wall` broadcast on session start/end — remote access is never silent
- **Three single binaries + SQLite**: `go install` and go — no Docker, no web UI, no external dependencies

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

## Quick Start

On the official server (self-register, no admin needed):

```bash
# On the controlled machine, one command (the official server address is baked into the script)
curl -fsSL https://towstrap.vast-plan.com/install.sh | sh
# It downloads the right binary and verifies SHA256; add --systemd to install a service

# Then onboard: it asks whether you have an account — no → sign up,
# yes → log in and attach this machine (one account, many machines)
towstrap register
# One machine fingerprint binds to only one account. If the official server
# has register: off, sign-up is unavailable — install with --token tsa-…
# instead (ask an admin).

# On your laptop
ssh -p 7822 alice@towstrap.vast-plan.com                            # land in that machine's shell
ssh -p 7822 alice@towstrap.vast-plan.com 'uname -a'                 # or run a command directly
ssh -t -p 7822 alice@towstrap.vast-plan.com 'mirror work'           # pick up the machine's persistent terminal (Ctrl-\ detaches)
```

Or self-host everything (on your own server S) — one line installs the binary + config + systemd service:

```bash
curl -fsSL https://raw.githubusercontent.com/towstrap/towstrap/main/scripts/install-server.sh | sudo sh
# binary comes from GitHub Releases (SHA256SUMS verified); on Linux as root it
# installs and starts a systemd unit (--no-systemd installs binary+config only,
# which is also the macOS path)

sudo towstrap-server init         # post-install wizard: public URL / self-signup / first account
# No wizard? Edit server.yaml (register: true) or: towstrap-server user add alice → token

# Install the agent — the script connects back to whichever server served it
curl -fsSL http://S:7880/install.sh | sh -s -- --token tsa-…
# Manual way: towstrap --server ws://S:7880 --agent-token-file ~/.towstrap-token

ssh -p 7822 alice@S               # shell / mirror work for relay

# For LLM use (optional): set mcp.enabled: true in server.yaml, restart,
# then issue an MCP token and paste the printed config into Claude Code / Cursor
towstrap-server mcp add laptop --machine alice
```

Enable TLS in production (`--tls` or `tls: true` in server.yaml) — details in the [User Guide](docs/en/user-guide.md).

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

`mirror` is a symlink alias of `towstrap`; `mirror ls` lists, `mirror kill work` terminates; several devices can attach to the same mirror at once (shared view); mirrors idle past `mirror_idle` (default 72h) are reaped automatically. To get "remind me when a mirror exists, optionally auto-attach" in everyday terminals: `mirror setup --write` adds a hook to your shell rc (reminder-only by default — put a name in `TOWSTRAP_MIRROR_AUTO=` inside the block to auto-attach it).

## Deployment

### go install

```bash
go install github.com/towstrap/towstrap/cmd/towstrap-server@latest   # server + account management
go install github.com/towstrap/towstrap/cmd/towstrap@latest    # controlled machine
go install github.com/towstrap/towstrap/cmd/towstrap-mcp@latest      # MCP entry point (optional)
```

### Build from source

```bash
git clone https://github.com/towstrap/towstrap && cd towstrap
make build    # produces bin/towstrap-server, towstrap, towstrap-mcp
```

### Run the agent under systemd

`examples/towstrap.service` is a ready-made unit: dedicated low-privilege `User=towstrap`, `NoNewPrivileges`, auto-restart — the file's comments walk through the full setup.

### Binary releases

`make release` cross-compiles darwin/linux/windows × amd64/arm64 (18 artifacts) and generates `SHA256SUMS` (set `MINISIGN_KEY_FILE` to also sign with minisign). See [Releases](https://github.com/towstrap/towstrap/releases). On Windows the agent's interactive sessions use ConPTY (Windows 10 1809+ required) — see the user guide.

## For LLMs

TowStrap exposes the MCP tools `list_machines / run_command / read_file / write_file` plus the terminal family `terminal_open`/`terminal_write`/`terminal_read`/`terminal_resize`/`terminal_close`/`terminal_list` (a real PTY, session-scoped temporary terminals), reachable two ways:

- **Server-embedded HTTP**: set `mcp.enabled: true` in `server.yaml`, issue a `tsm-` token with `towstrap-server mcp add`, and point the client at the URL with a Bearer header — nothing to install
- **Local stdio**: run `towstrap-mcp` on the machine running the LLM; it SSHes to the server with a private key and lands on the agent

The companion LLM skill (which teaches the assistant safe usage) can be fetched three ways: `curl https://S:7880/skill`, `towstrap-mcp connect` to install into every detected assistant at once, or a manual copy of `skills/towstrap/`.

Authorization is layered: the agent's OS user is the real boundary, MCP policy (deny/allow/approval) is the filter, and approval prompts keep a human in the loop. See the [User Guide](docs/en/user-guide.md).

## Documentation

| | | |
| --- | --- | --- |
| 📘 User Guide | [docs/en/user-guide.md](docs/en/user-guide.md) | Install, accounts & machines, allowlists, TOTP, MCP, skill, token rotation, monitoring, troubleshooting |
| 🛠 Technical Manual | [docs/en/technical-manual.md](docs/en/technical-manual.md) | Architecture, wire protocol, auth & rate limiting, data model & crypto, token lifecycle, MCP policy & approval, audit events, config & CLI reference |
| 🌐 中文 | [README.md](README.md) · [用户手册](docs/zh/user-guide.md) · [技术手册](docs/zh/technical-manual.md) | 中文文档 |

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

## Project Layout

```
├── cmd/
│   ├── towstrap-server/   # server + account/machine/MCP-client management
│   ├── towstrap/    # controlled-machine agent (incl. token refresh, the mirror subcommand)
│   └── towstrap-mcp/      # stdio MCP entry + skill installer (connect)
├── internal/
│   ├── server/            # SSH/HTTP servers, Hub, auth rate limiting, token rotation, embedded MCP
│   ├── client/            # agent connection, session execution, on-machine presence (notify/audit), named mirrors
│   ├── accounts/          # SQLite store: users/machines/MCP clients, encryption, migration
│   ├── mcpsrv/            # MCP tools, policy engine, human approval, SSH pool
│   ├── proto/             # WebSocket wire protocol
│   ├── harness/           # coding-assistant detection & skill install
│   ├── auditlog/          # two-sided audit log (rotation, control-char scrubbing)
│   ├── config/            # yaml config loading
│   ├── allow/             # IP/host allowlists
│   ├── totp/              # TOTP second factor
│   └── e2e/               # end-to-end tests (real server, real agent)
├── skills/towstrap/       # LLM skill shipped with the project (embedded)
├── scripts/               # install.sh / install.ps1 one-line installers (served at /install.*)
├── examples/              # server.yaml / agent.yaml / mcp.yaml / systemd unit
├── docs/                  # Chinese & English user guides and technical manuals
└── assets/                # logo and other assets
```

## Star History

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=towstrap/towstrap&type=Date&theme=dark" />
  <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=towstrap/towstrap&type=Date" />
  <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=towstrap/towstrap&type=Date" />
</picture>

## License

[AGPL-3.0](LICENSE)
