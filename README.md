<div align="center">

<img src="assets/logo.svg" alt="TowStrap" width="128" />

# TowStrap

[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8.svg)](https://go.dev/)
[![CI](https://github.com/towstrap/towstrap/actions/workflows/ci.yml/badge.svg)](https://github.com/towstrap/towstrap/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%C2%B7%20macOS%20%C2%B7%20Windows-lightgrey.svg)]()
[![MCP](https://img.shields.io/badge/MCP-ready-green.svg)]()
[![Release](https://img.shields.io/github/v/release/towstrap/towstrap)](https://github.com/towstrap/towstrap/releases)

**连接用户（或 LLM）与 NAT 之后机器的反向接入系统**

中文 | [English](README_EN.md)

</div>

---

## 概述

TowStrap 用于访问位于 NAT/防火墙之后、无公网 IP 的机器。被控端 agent 通过 WebSocket 主动连接自建服务器；此后用户经 SSH、LLM 经 MCP，由服务器中转至目标机器执行。被控机无需运行 sshd、无需公网地址、无需修改网络设备配置。

同一系统服务两类使用者：人（SSH，密码/TOTP/公钥认证）与 LLM（MCP，策略过滤加人工批准）。token 换发默认仅允许被控机发起；管理员远程轮换他人机器凭据须显式指定 `--admin` 并计入审计。

交付形态为三个静态二进制与 SQLite 存储，无 Docker、无 Web 界面、无外部服务依赖，全部数据保存在自建设施内。

---

## 功能特性

**接入**

- 反向连接：agent 主动建立 WebSocket 出站连接，被控机无入站端口要求
- 标准 SSH：`ssh alice+office@服务器 -p 7822`，兼容任意 SSH 客户端
- exec 模式：`ssh 机器 '命令'` 返回分离的 stdout/stderr 与真实退出码
- 一账号多机器：每台机器独立 token，可单独吊销并即时生效

**接力终端（mirror）**

- 内置持久终端，不依赖 tmux/screen；多端可同时接入同一会话
- `Ctrl-\` 脱离且进程续跑；`mirror ls`/`mirror kill` 管理；`mirror_idle` 闲置自动回收（默认 72h）
- 仅限人工使用：本机 0600 socket 加对端 uid 校验，MCP 不提供此能力

**MCP（LLM 接入）**

- 工具集：`run_command`/`read_file`/`write_file` 及 PTY 终端族（`terminal_open`/`write`/`read`/`resize`/`close`/`list`，会话级临时终端）
- 策略：deny/allow/批准三级正则名单；批准绑定「机器+操作类型+命令+cwd+stdin 摘要」，参数变更须重新批准
- 接入方式：服务器内嵌 HTTP（`/mcp`，Bearer `tsm-` token）或本机 stdio（`towstrap-mcp`）
- 内置 LLM skill：`GET /skill` 获取，或 `towstrap-mcp connect` 批量安装至已检测的编码助手

**账号与认证**

- 自助注册：`towstrap register` 建号或登录挂接机器；服务端 `register`/`register_invite` 控制入口
- 机器指纹绑定：主板 UUID 哈希，一台机器仅可绑定一个账号
- 认证方式：密码 / TOTP 二因素 / 公钥任意组合；支持 OAuth 一次性 SSH 授权（临时凭据不可执行管理命令）
- 自助管理：SSH 登录后 `@machine list/add/remove/token`、`@totp`；本机 `towstrap totp`
- token 换发：`towstrap token refresh`，原子写入、确认后作废旧 token、失败自动回退

**安全与审计**

- 限速锁定：账号×IP 与账号双维度计数，指数退避
- 凭据保护：token 文件 0600；`TOWSTRAP_AGENT_TOKEN` 不进入子进程环境；agent 上报凭据路径自动加入 MCP 拒名单
- 双侧审计：服务器与 agent 分别记录连接/执行/批准/换发事件，批准操作携带授权编号
- 会话可见：会话开始/结束触发桌面通知与 `wall` 广播

---

## ⚠️ 安全须知

- 远程命令以 agent 系统用户身份真实执行，应以专用低权限用户运行 agent
- MCP 策略为过滤层而非沙箱，真实安全边界为系统用户权限
- `tsa-`/`tsm-` 均为凭据，须以 0600 权限保存，不得写入日志、仓库或公开渠道
- 生产部署须启用 TLS；明文且非回环监听默认拒绝启动（`allow_plain_http: true` 为显式例外）
- 不宜置于反向代理之后：来源 IP 被改写将使 IP 白名单、限速锁定、换 IP 告警失效
- 本项目按 AGPL-3.0 提供，作者不承担因使用造成的任何损失

---

## 架构

```
        人                          LLM 客户端（Claude Code / Cursor / Codex…）
  ssh alice+office@S -p 7822        MCP https://S:7880/mcp  Bearer tsm-…
        │  密码 + TOTP               │  策略 → 批准 → 执行
        ▼                            ▼
   ┌───────────────── towstrap-server（S）──────────────────┐
   │  SSH :7822    HTTP :7880  /agent  /mcp  /token/refresh │
   │  账号库 SQLite · 审计日志 · 限速锁定 · 策略与批准      │
   └───────────────┬────────────────────────────────┬───────┘
                   │ WebSocket 连出，token tsa-…    │
        ┌──────────▼──────────┐          ┌──────────▼──────────┐
        │ towstrap            │          │ towstrap            │
        │ alice+office        │          │ alice+build         │
        │ 本机 shell（低权限）  │          │ 本机 shell          │
        └─────────────────────┘          └─────────────────────┘
```

---

## 安装

安装统一使用 sh 脚本：按平台下载对应二进制并校验 SHA256，校验失败即中止（`--no-verify` 为显式跳过项）。

被控机（agent）：

```bash
curl -fsSL https://towstrap.vast-plan.com/install.sh | sh            # 官方服务器
curl -fsSL http://S:7880/install.sh | sh -s -- --token tsa-…        # 自建服务器
```

可选参数：`--systemd` 注册系统服务；`--token tsa-…` 直接提供凭据（亦可装后执行 `towstrap register` 自助建号）。

服务端：

```bash
curl -fsSL https://raw.githubusercontent.com/towstrap/towstrap/main/scripts/install-server.sh | sudo sh
```

Linux+root 下自动注册并启动 systemd 服务（`--no-systemd` 仅安装二进制与配置，亦适用于 macOS）。安装后执行 `sudo towstrap-server init` 完成初始化（对外地址、自助注册、首个账号）。

升级：`towstrap update` / `sudo towstrap-server update` 从官方 Release 下载新版，SHA256 校验后替换自身，已注册的 systemd 服务/计划任务自动重启生效（`--check` 只查不装，`--version vX.Y.Z` 指定版本）；也可重复执行安装脚本——二进制覆盖更新，配置与 token 保留。服务端下发的 `/install.sh` 默认安装与服务器同版本的 agent；管理员可在 `server.yaml` 设置 `min_agent_version` 拒绝过低版本接入。

Windows 交互会话使用 ConPTY（要求 Windows 10 1809+），详见[用户手册](docs/zh/user-guide.md)。

---

## 快速开始

```bash
# 被控机：安装后执行接入向导（建号或登录挂接）
towstrap register

# 客户端：
ssh -p 7822 alice@towstrap.vast-plan.com                            # 交互 shell
ssh -p 7822 alice@towstrap.vast-plan.com 'uname -a'                 # 单次执行
ssh -t -p 7822 alice@towstrap.vast-plan.com 'mirror work'           # 接入持久终端（Ctrl-\ 脱离）
```

MCP 接入：`server.yaml` 置 `mcp.enabled: true` 并重启，执行 `towstrap-server mcp add laptop --machine alice` 签发 `tsm-` token，按输出的配置接入客户端。

生产部署请启用 TLS（`--tls` 或 `tls: true`），详见[用户手册](docs/zh/user-guide.md)。

---

## 接力终端用法

```bash
mirror work        # 创建或接入名为 work 的持久终端
claude             # 在其中运行任意 TUI 程序
# Ctrl-\ 脱离，进程继续运行
```

其他设备执行 `ssh -t -p 7822 alice@S 'mirror work'` 即可接入同一终端。`mirror setup --write` 可向 shell rc 写入钩子（默认提醒，填 `TOWSTRAP_MIRROR_AUTO=` 启用自动接入）。

---

## 文档

| | | |
| --- | --- | --- |
| 📘 用户手册 | [docs/zh/user-guide.md](docs/zh/user-guide.md) | 安装、账号与机器、白名单、TOTP、MCP、skill、换 token、监控、排错 |
| 🛠 技术手册 | [docs/zh/technical-manual.md](docs/zh/technical-manual.md) | 架构、协议、认证与限速、数据模型与加密、token 生命周期、MCP 策略与批准、审计事件、配置与 CLI 参考 |
| 🌐 English | [README_EN.md](README_EN.md) · [User Guide](docs/en/user-guide.md) · [Technical Manual](docs/en/technical-manual.md) | English documentation |

---

## 技术栈

| 组件 | 选型 |
| --- | --- |
| 语言 | Go 1.25+ |
| SSH 服务端 | [gliderlabs/ssh](https://github.com/gliderlabs/ssh) + golang.org/x/crypto |
| WebSocket | [gorilla/websocket](https://github.com/gorilla/websocket) |
| 存储 | SQLite（[modernc.org/sqlite](https://gitlab.com/cznic/sqlite)，纯 Go，无 CGO） |
| MCP | [modelcontextprotocol/go-sdk](https://github.com/modelcontextprotocol/go-sdk) |
| PTY | [creack/pty](https://github.com/creack/pty) |
| 配置 | gopkg.in/yaml.v3 |

---

## 项目结构

```
├── cmd/
│   ├── towstrap-server/   # 服务器端 + 账号/机器/MCP 客户端管理 + init 向导
│   ├── towstrap/          # 被控机 agent（register/totp/token/mirror 子命令）
│   └── towstrap-mcp/      # stdio MCP 入口 + skill 安装器（connect）
├── internal/
│   ├── server/            # SSH/HTTP 服务、Hub、认证限速、token 换发、内嵌 MCP
│   ├── client/            # agent 连接、会话执行、被控端感知、镜像终端
│   ├── accounts/          # SQLite 账号库：用户/机器/MCP 客户端/授权/指纹、加密
│   ├── mcpsrv/            # MCP 工具、策略引擎、人工批准、远端路径解析、SSH 连接池
│   ├── proto/             # WebSocket 消息协议
│   ├── harness/           # 各家编码助手的检测与 skill 安装
│   ├── auditlog/          # 双侧审计日志（轮转、控制字符清洗）
│   ├── oidc/ + totp/      # OAuth 授权、TOTP 二因素
│   ├── machineid/         # 机器指纹（主板 UUID 哈希）
│   ├── monitor/ + notify/ # 指标监控、桌面通知
│   ├── allow/ + auth/     # IP/主机白名单、密码校验
│   ├── config/            # yaml 配置加载与合并
│   └── e2e/               # 端到端测试（起真服务器真 agent）
├── skills/towstrap/       # 随项目发布的 LLM skill（embed 进二进制）
├── scripts/               # install.sh / install-server.sh / install.ps1
├── examples/              # server.yaml / agent.yaml / mcp.yaml / systemd 单元 / nginx
├── docs/                  # 中英用户手册与技术手册
└── assets/                # logo 等资源
```

开发：`make build` 产出 `bin/` 下三个二进制；`make release` 交叉编译全平台产物并生成 SHA256SUMS（设 `MINISIGN_KEY_FILE` 顺带签名）。

---

## Star History

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=towstrap/towstrap&type=Date&theme=dark" />
  <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=towstrap/towstrap&type=Date" />
  <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=towstrap/towstrap&type=Date" />
</picture>

## 许可证

[AGPL-3.0](LICENSE)
