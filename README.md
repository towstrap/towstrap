<div align="center">

<img src="assets/logo.svg" alt="TowStrap" width="128" />

# TowStrap

[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8.svg)](https://go.dev/)
[![CI](https://github.com/towstrap/towstrap/actions/workflows/ci.yml/badge.svg)](https://github.com/towstrap/towstrap/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%C2%B7%20macOS%20%C2%B7%20Windows-lightgrey.svg)]()
[![MCP](https://img.shields.io/badge/MCP-ready-green.svg)]()
[![Release](https://img.shields.io/github/v/release/towstrap/towstrap)](https://github.com/towstrap/towstrap/releases)

**连接你（或你的 LLM）和 NAT 后面机器的那根拖车带**

中文 | [English](README_EN.md)

</div>

---

## 概述

要访问的机器躲在 NAT / 防火墙后面、没有公网 IP？被控机上的 agent 主动 WebSocket 连到你自己的服务器，之后**人走 SSH、LLM 走 MCP**，都经服务器落到那台机器上执行——不开 sshd、不要公网 IP、不改路由器。

和 ShellHub、Teleport、RevoShell 这类方案的一句差别：**同一套系统既给人（SSH + 密码/TOTP/公钥）也给 LLM（MCP + 三档策略 + 人工批准），而且换 token 默认只能在被控机器上发起**——服务器管理员要隔空换别人机器的凭据，必须显式 `--admin` 并留下审计。

三个单二进制 + SQLite，无 Docker、无网页、无外部依赖；所有数据留在你自己的设施上。

（名字来自拖车带 tow strap：扁、结实、两车之间拖拽用。）

---

## 功能特性

**接入**

- **反向连接，零入站**：agent 主动连出 WebSocket，被控机不开任何端口
- **标准 SSH 客户端**：`ssh alice+office@服务器 -p 7822` 直接进 shell——桌面、手机（Termius 等）任何 SSH 客户端都行，不用装客户端
- **exec 执行模式**：`ssh 机器 '命令'` 拿回分开的 stdout/stderr 和真实退出码，脚本可直接消费
- **一个账号多台机器**：每台机器独立 token，互不影响，单个撤权立即生效

**接力终端（mirror）**

- **tmux 式常驻终端，零依赖**：agent 内置，不装 tmux/screen——机器前开的镜像，换手机/别的电脑 `ssh -t 机器 mirror work` 接着操作，画面多端同屏
- **脱离不杀进程**：`Ctrl-\` 脱离后续跑；新建落在你敲命令的目录；`mirror ls`/`mirror kill` 管理；闲置自动终结（`mirror_idle` 默认 72h 可调）
- **只给人用**：镜像走本机 0600 socket + 对端 uid 核对，MCP 刻意不开放——AI 碰不到人的终端

**给 LLM 用（MCP）**

- **三类工具**：`run_command`/`read_file`/`write_file` + 真 PTY 终端族（`terminal_open/write/read/resize/close/list`，会话级临时终端）
- **三档策略 + 人工批准**：deny/allow/批准名单正则可配；批准后按「机器+操作类型+命令+cwd+stdin 摘要」绑定，换个参数就得重批
- **两条接入路**：服务器内嵌 HTTP（`/mcp` + Bearer `tsm-` token）或本机 stdio（`towstrap-mcp`）
- **随项目发布 LLM skill**：`GET /skill` 直接拉，或 `towstrap-mcp connect` 一键装进检测到的编码助手

**账号与认证**

- **自助注册向导**：被控机跑 `towstrap register`，没账号就地建号、有账号登录加机器；服务器用 `register`/`register_invite` 控制入口
- **一机一账号**：机器指纹（主板 UUID 哈希，重装系统不变）只允许绑一个账号，重复注册提示找回
- **密码 + TOTP + 公钥任选组合**；OAuth 一次性 SSH 授权登录（临时票进不了管理面）
- **自助管理**：`ssh` 登录后 `@machine list/add/remove/token` 管名下机器、`@totp` 绑/解绑二因素（要 TOTP 再验）；机器上也可 `towstrap totp`
- **token 换发**：`towstrap token refresh`——服务器下推、agent 原子写文件、确认后才作废旧 token，连接不断；半途失败自动回退旧 token 自愈

**安全与可感知**

- **防爆破**：账号×IP 与账号双维度限速、指数退避锁定；换 IP 分布式爆破也累计
- **凭据最小暴露**：token 推荐 0600 文件；`TOWSTRAP_AGENT_TOKEN` 不进子进程环境；agent 上报 token/配置路径给服务器，自动进 MCP 拒名单——AI 读不到你的凭据
- **双侧审计**：服务器和 agent 各记各的日志，连接/执行/批准/换 token 全部可查；批准操作带授权编号可串查
- **被控机可感知**：会话开始/结束桌面通知 + `wall` 广播，远程访问不偷偷摸摸

---

## ⚠️ 使用前必读（安全须知）

**你要注意的**：

- **命令是真实执行的**：远程命令以被控机上 agent 进程的系统用户身份运行——请给 agent 配专用低权限用户（以 root 运行会打告警，那意味着每个远程会话都是 root shell）
- **MCP 的 deny/allow/批准是过滤层，不是沙箱**：shell 语法绕得过朴素切段，真正的安全边界是 agent 的系统用户权限
- **token 是凭据**：`tsa-`（agent）和 `tsm-`（MCP 客户端）泄漏等于开门——0600 权限保存，别写进 shell 历史、日志、仓库或聊天窗口
- **生产环境必须开 TLS**：明文下 token 和密码裸传；明文 + 非回环监听时服务器默认拒绝启动（内网/隧道部署需 `allow_plain_http: true` 显式确认）
- **不要放反向代理后面**：Nginx、云负载均衡会把来源 IP 变成代理地址，IP 白名单、限速锁定、换 IP 告警全部失效——除非你清楚后果
- **免责**：本项目按 AGPL-3.0 协议提供，作者不承担因使用本项目造成的任何损失

---

## 架构

```
        人                          LLM 客户端（Claude Code / Cursor / Codex…）
  ssh alice+office@S -p 7822        MCP https://S:7880/mcp  Bearer tsm-…
        │  密码 + TOTP               │  策略 → 弹窗批准 → 执行
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

安装只有一条路：**sh 脚本**。它会按平台下载对应二进制、校验 SHA256（校验不过直接不装，`--no-verify` 可显式跳过）。

### 被控机（agent）

```bash
# 官方服务器（地址已内置在脚本里）
curl -fsSL https://towstrap.vast-plan.com/install.sh | sh

# 自建服务器：脚本从哪台服务器拉的就默认连回哪台
curl -fsSL http://S:7880/install.sh | sh -s -- --token tsa-…
```

加 `--systemd` 顺带装成系统服务；`--token tsa-…` 直接带凭据（向管理员要，或先跑 `towstrap register` 自助建号）。

### 服务端

```bash
curl -fsSL https://raw.githubusercontent.com/towstrap/towstrap/main/scripts/install-server.sh | sudo sh
# Linux+root 自动装并启动 systemd 服务（--no-systemd 只装二进制+配置，
# macOS 也走这条）；二进制从 GitHub Releases 下，SHA256SUMS 校验
```

装完跑 `sudo towstrap-server init` 初始化向导：对外地址、自助注册开关、第一个账号，一次配完。

Windows 上 agent 的交互会话走 ConPTY（需 Windows 10 1809+），详见[用户手册](docs/zh/user-guide.md)。

---

## 快速开始

用官方服务器（自助注册，不用找管理员）：

```bash
# 被控机装好（见上）后接入：先问有没有账号——没有就建号，有就登录挂机
towstrap register

# 你的电脑上
ssh -p 7822 alice@towstrap.vast-plan.com                            # 进那台机器的 shell
ssh -p 7822 alice@towstrap.vast-plan.com 'uname -a'                 # 或直接执行命令
ssh -t -p 7822 alice@towstrap.vast-plan.com 'mirror work'           # 接力常驻终端（Ctrl-\ 脱离）
```

自建服务器的话，`install-server.sh` + `init` 向导两步就绪；agent 用 `--token` 装好后同样走 SSH 进机器。

给 LLM 用（可选）：`server.yaml` 里 `mcp.enabled: true` 后重启，再签发 MCP token，把打印的配置贴进 Claude Code / Cursor：

```bash
towstrap-server mcp add laptop --machine alice
```

生产上请开 TLS（`--tls` 或 server.yaml 里 `tls: true`），细节见[用户手册](docs/zh/user-guide.md)。

---

## 场景：AI 助手跑着，人先走

把要跑半天的 TUI 程序（AI 编码助手、`vim`、`top`……）放进镜像，人就可以离开——画面跟着你走，**两个方向都行**：

```bash
# 机器前开的，手机上接：
mirror work                          # 建一个名叫 work 的镜像，落在当前目录
claude                               # 在里面起 AI 编码助手（任何 TUI 程序都行）
#   …派完活，Ctrl-\ 脱离——助手继续跑，锁屏下班
ssh -t -p 7822 alice@towstrap.vast-plan.com 'mirror work' # 路上用手机接回同一个画面
```

```bash
# 手机上开的，回家电脑前接：
ssh -t -p 7822 alice@towstrap.vast-plan.com 'mirror fix'  # 新建 fix、派活、Ctrl-\ 脱离
ssh -t -p 7822 alice@towstrap.vast-plan.com 'mirror fix'  # 到家后接回——同一条命令、同一个现场
```

多台设备可以同时接入同一镜像（画面同步）。想让日常终端「有镜子时提醒、可选自动接入」：`mirror setup --write` 往 shell rc 写一段钩子（默认只提醒，把段里 `TOWSTRAP_MIRROR_AUTO=` 填上名字才自动接）。

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

开发：克隆仓库后 `make build` 产出 `bin/` 下三个二进制，`make release` 交叉编译全平台产物并生成 SHA256SUMS（设 `MINISIGN_KEY_FILE` 顺带签名）。

---

## Star History

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=towstrap/towstrap&type=Date&theme=dark" />
  <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=towstrap/towstrap&type=Date" />
  <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=towstrap/towstrap&type=Date" />
</picture>

## 许可证

[AGPL-3.0](LICENSE)
