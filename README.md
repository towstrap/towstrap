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

## ⚠️ 使用前必读（安全须知）

**系统内置的防线**：

- **认证 + 防爆破**：密码 / TOTP 二因素 / 公钥任选组合；账号×IP 与账号双维度限速、指数退避锁定，换 IP 分布式爆破也挡得住；agent 换 IP 重连写 `AGENT-IPCHANGE` 告警
- **凭据最小暴露**：token 推荐放 0600 文件（只有文件来源的 token 服务器才能远程换发）；`TOWSTRAP_AGENT_TOKEN` 不进子进程环境；agent 主动上报 token 文件和配置文件路径，服务器把它们加进 MCP 文件工具的拒名单——AI 读不到你的凭据；密码走非回环明文必须 `--allow-plain` 显式确认；`/mcp` 在明文 HTTP + 非回环监听时拒绝启动
- **边界是系统用户权限**：远程命令以 agent 的系统用户身份执行——配专用低权限用户就是真边界（以 root 运行会打告警）；MCP 拒名单连 agent 自己都动不了：杀进程、停服务、覆盖二进制一律直接拒绝
- **AI 碰不到人的终端**：MCP 终端是会话级临时 PTY，接入不了 `mirror` 镜像；镜像 socket 0600 + 对端 uid 核对（Linux `SO_PEERCRED`、macOS `LOCAL_PEERCRED`），只有 agent 同一个用户能连
- **全程留痕、人可感知**：会话开始/结束桌面通知 + `wall` 广播；服务器和 agent 双侧审计——连接、执行、批准、换 token、终结镜像全部留档；批准过的操作带授权编号（`MCP-AUTH-EXEC`），超时未批视为拒绝；隔空换别人机器的 token 必须显式 `--admin` 并写审计，平时只能在被控机上发起
- **数据不出你的设施**：账号库是你服务器上的本地 SQLite，自托管、无第三方云

**你要注意的**：

- **命令是真实执行的**：远程命令以被控机上 agent 进程的系统用户身份运行。请给 agent 配一个专用低权限用户（以 root 运行会打告警——那意味着每个远程会话都是 root shell）。
- **MCP 的 deny/allow/批准只是过滤层，不是沙箱**：shell 语法绕得过朴素切段，真正的安全边界是 agent 的系统用户权限。
- **token 是凭据**：`tsa-`（agent）和 `tsm-`（MCP 客户端）泄漏等于开门。token 文件用 0600 权限，别写进 shell 历史、日志、仓库或聊天窗口。
- **生产环境必须开 TLS**：明文 `ws://`/`http://` 下 token 和密码会裸传；`/mcp` 在明文 HTTP + 非回环监听时直接拒绝启动。
- **不要放在反向代理后面**：Nginx、云负载均衡会把来源 IP 变成代理自己的地址，IP 白名单、限速锁定、`AGENT-IPCHANGE` 换 IP 告警全部失效——除非你清楚后果并做了对应处理。
- **免责**：本项目按 AGPL-3.0 协议提供，作者不承担因使用本项目造成的任何损失。

## 概述

TowStrap 解决一个常见问题：要访问的机器躲在 NAT / 防火墙后面，没有公网 IP。被控机上的 agent 主动 WebSocket 连到你自己的服务器，之后人走 SSH、LLM 走 MCP，都经服务器落到那台机器上执行——**不开 sshd、不要公网 IP、不改路由器**。

和 ShellHub、Teleport、RevoShell 这类方案的一句差别：**同一套系统既给人（SSH + 密码/TOTP/公钥）也给 LLM（MCP + 三档策略 + 人工批准），而且换 token 默认只能在被控机器上发起**——服务器管理员要隔空换别人机器的凭据，必须显式 `--admin` 并留下审计。

（名字来自拖车带 tow strap：扁、结实、两车之间拖拽用。）

## 特性

- **反向连接，零入站**：agent 主动连出 WebSocket，被控机不开任何端口、不要公网 IP
- **标准 SSH 客户端**：`ssh alice+office@服务器 -p 7822` 直接进 shell，无需装客户端
- **多重认证**：密码 + TOTP 二因素 + 公钥（给自动化），账号级和全局 IP 白名单
- **防爆破**：账号×IP 与账号双维度限速、指数退避锁定，换 IP 分布式爆破也挡得住
- **一个账号多台机器**：每台机器独立 token，互不影响，单个撤权立即生效
- **本机发起的 token 换发**：`towstrap token refresh`，服务器下推、agent 原子写文件、确认后才作废旧 token——连接不断
- **账号本人自助**：`ssh` 登录后 `@machine list/add/remove/token` 管理名下机器（要 TOTP 再验，公钥不行）
- **exec 执行模式**：`ssh 机器 '命令'` 拿回分开的 stdout/stderr 和真实退出码，自动化可直接用
- **可接力终端（镜像终端）**：agent 内置 tmux 式常驻终端，不依赖 tmux——机器前开的镜像，换手机/别的电脑 `ssh -t 机器 mirror 名字` 接着操作：多端同屏、`Ctrl-\` 脱离不杀进程、新建落在你敲命令的目录、闲置自动终结（`mirror_idle` 默认 72h，可调可关）；`mirror` 是 agent 的软链别名。这是给人用的功能，MCP 不开放
- **MCP 双模式**：服务器内嵌 HTTP（`/mcp`，Bearer token）或本机 stdio（`towstrap-mcp`），文件/命令/终端三类工具、三档策略、弹窗批准
- **随项目发布的 LLM skill**：`GET /skill` 直接拉取，或 `towstrap-mcp connect` 一键装进 8 家编码助手
- **双侧审计**：服务器和 agent 各记各的日志，谁连过、跑过什么、换过 token 全部可查
- **被控机可感知**：会话开始/结束弹桌面通知 + `wall` 广播，远程访问不偷偷摸摸
- **三个单二进制 + SQLite**：`go install` 即用，无 Docker、无网页、无外部依赖

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

## 快速开始

用官方服务器（向管理员要到账号和 agent token 后，两条命令）：

```bash
# 被控机上一条命令装好（官方服务器地址已内置在脚本里）
curl -fsSL https://towstrap.vast-plan.com/install.sh | sh -s -- --token tsa-…
# 它会下载对应平台的二进制、校验 SHA256、写 token 文件和最小配置；
# 加 --systemd 顺带装成服务。手动方式：下载 towstrap 后直接
#   towstrap --agent-token-file ~/.towstrap-token   （--server 默认就是官方）

# 你的电脑上
ssh -p 7822 alice@towstrap.vast-plan.com                            # 进那台机器的 shell
ssh -p 7822 alice@towstrap.vast-plan.com 'uname -a'                 # 或直接执行命令
ssh -t -p 7822 alice@towstrap.vast-plan.com 'mirror work'           # 接力机器上的常驻终端（Ctrl-\ 脱离）
```

或者自己跑一套（自建服务器 S 上）：

```bash
go install github.com/towstrap/towstrap/cmd/towstrap-server@latest
towstrap-server user add alice    # 建号；打印随机密码和第一台机器的 agent token
towstrap-server &                 # SSH :7822，HTTP :7880

# 被控机装 agent——脚本从哪台服务器拉就默认连回哪台
curl -fsSL http://S:7880/install.sh | sh -s -- --token tsa-…
# 手动方式：towstrap --server ws://S:7880 --agent-token-file ~/.towstrap-token

ssh -p 7822 alice@S               # 进机器 shell / mirror work 接力

# 给 LLM 用（可选）：server.yaml 里 mcp.enabled: true 后重启，
# 再签发 MCP token，把打印出来的配置贴进 Claude Code / Cursor
towstrap-server mcp add laptop --machine alice
```

生产上请开 TLS（`--tls` 或 server.yaml 里 `tls: true`），细节见[用户手册](docs/zh/user-guide.md)。

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
# 手机上开的，回家电脑前接（Termius 之类任何 ssh 客户端都行）：
ssh -t -p 7822 alice@towstrap.vast-plan.com 'mirror fix'  # 新建 fix、派活、Ctrl-\ 脱离
ssh -t -p 7822 alice@towstrap.vast-plan.com 'mirror fix'  # 到家后接回——同一条命令、同一个现场
```

`mirror` 是 `towstrap` 的软链别名；`mirror ls` 看清单、`mirror kill work` 终结；多台设备可以同时接入同一镜像（画面同步）；闲置超过 `mirror_idle`（默认 72h）自动回收。想让日常终端「有镜子时提醒、可选自动接入」：`mirror setup --write` 往 shell rc 写一段钩子（默认只提醒，把段里 `TOWSTRAP_MIRROR_AUTO=` 填上名字才自动接）。

## 部署方式

### go install

```bash
go install github.com/towstrap/towstrap/cmd/towstrap-server@latest   # 服务器端 + 账号管理
go install github.com/towstrap/towstrap/cmd/towstrap@latest    # 被控机
go install github.com/towstrap/towstrap/cmd/towstrap-mcp@latest      # MCP 入口（可选）
```

### 从源码构建

```bash
git clone https://github.com/towstrap/towstrap && cd towstrap
make build    # 产出 bin/towstrap-server、towstrap、towstrap-mcp
```

### systemd 运行 agent

`examples/towstrap.service` 是现成的 systemd 单元：专用低权限用户 `User=towstrap`、`NoNewPrivileges`、自动重启都配好了，文件里有完整的安装步骤注释。

### 二进制发布

`make release` 交叉编译 darwin/linux/windows × amd64/arm64 共 18 个产物并生成 `SHA256SUMS`（设 `MINISIGN_KEY_FILE` 会顺带 minisign 签名）。打好的包见 [Releases](https://github.com/towstrap/towstrap/releases)。Windows 上 agent 的交互会话走 ConPTY（需 Windows 10 1809+），详见用户手册。

## 给 LLM 用

TowStrap 给 LLM 提供 MCP 工具 `list_machines / run_command / read_file / write_file` 和终端族 `terminal_open`/`terminal_write`/`terminal_read`/`terminal_resize`/`terminal_close`/`terminal_list`（真 PTY，会话级临时终端），两条接入路任选：

- **服务器内嵌 HTTP**：`server.yaml` 开 `mcp.enabled: true`，`towstrap-server mcp add` 签发 `tsm-` token，客户端填 URL + Bearer 即可——不装任何东西
- **本机 stdio**：在跑 LLM 的机器上跑 `towstrap-mcp`，经 SSH 私钥登录服务器再落到 agent

配套的 LLM skill（教助手安全用法）三条路任选：`curl https://S:7880/skill`、`towstrap-mcp connect` 一键装进全部检测到的助手、手工拷贝 `skills/towstrap/`。

授权是三层：agent 的系统用户权限是边界，MCP 策略（deny/allow/批准）是过滤，批准弹窗让人兜底。详见[用户手册「MCP」章](docs/zh/user-guide.md)。

## 文档

| | | |
| --- | --- | --- |
| 📘 用户手册 | [docs/zh/user-guide.md](docs/zh/user-guide.md) | 安装、账号与机器、白名单、TOTP、MCP、skill、换 token、监控、排错 |
| 🛠 技术手册 | [docs/zh/technical-manual.md](docs/zh/technical-manual.md) | 架构、协议、认证与限速、数据模型与加密、token 生命周期、MCP 策略与批准、审计事件、配置与 CLI 参考 |
| 🌐 English | [README_EN.md](README_EN.md) · [User Guide](docs/en/user-guide.md) · [Technical Manual](docs/en/technical-manual.md) | English documentation |

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

## 项目结构

```
├── cmd/
│   ├── towstrap-server/   # 服务器端 + 账号/机器/MCP 客户端管理
│   ├── towstrap/    # 被控机 agent（含 token refresh、mirror 子命令）
│   └── towstrap-mcp/      # stdio MCP 入口 + skill 安装器（connect）
├── internal/
│   ├── server/            # SSH/HTTP 服务、Hub、认证限速、token 换发、内嵌 MCP
│   ├── client/            # agent 连接、会话执行、被控端感知（通知/审计）、镜像终端
│   ├── accounts/          # SQLite 账号库：用户/机器/MCP 客户端、加密、迁移
│   ├── mcpsrv/            # MCP 工具、策略引擎、人工批准、SSH 连接池
│   ├── proto/             # WebSocket 消息协议
│   ├── harness/           # 各家编码助手的检测与 skill 安装
│   ├── auditlog/          # 双侧审计日志（轮转、控制字符清洗）
│   ├── config/            # yaml 配置加载
│   ├── allow/             # IP/主机白名单
│   ├── totp/              # TOTP 二因素
│   └── e2e/               # 端到端测试（起真服务器真 agent）
├── skills/towstrap/       # 随项目发布的 LLM skill（embed 进二进制）
├── scripts/               # install.sh / install.ps1 一键安装（服务器 /install.* 下发）
├── examples/              # server.yaml / agent.yaml / mcp.yaml / systemd 单元
├── docs/                  # 中英用户手册与技术手册
└── assets/                # logo 等资源
```

## Star History

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=towstrap/towstrap&type=Date&theme=dark" />
  <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=towstrap/towstrap&type=Date" />
  <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=towstrap/towstrap&type=Date" />
</picture>

## 许可证

[AGPL-3.0](LICENSE)
