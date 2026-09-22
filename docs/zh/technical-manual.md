# TowStrap 技术手册

[首页](../../README.md) · [用户手册](user-guide.md) · [English](../../docs/en/technical-manual.md)

本手册面向需要理解内部机制、对接、审计或二次开发的人。所有描述对照当前代码（`internal/`、`cmd/`），文末列有已知限制。

## 目录

1. [总体架构与数据流](#1-总体架构与数据流)
2. [WebSocket 协议](#2-websocket-协议)
3. [认证与限速](#3-认证与限速)
4. [数据模型与加密](#4-数据模型与加密)
5. [账号与机器：Hub](#5-账号与机器hub)
6. [token 生命周期](#6-token-生命周期)
7. [SSH 会话处理](#7-ssh-会话处理)
8. [MCP 层](#8-mcp-层)
9. [skill 与 harness](#9-skill-与-harness)
10. [配置参考](#10-配置参考)
11. [CLI 参考](#11-cli-参考)
12. [HTTP 端点参考](#12-http-端点参考)
13. [审计事件参考](#13-审计事件参考)
14. [安全模型与已知限制](#14-安全模型与已知限制)
15. [构建、测试与发布](#15-构建测试与发布)

---

## 1. 总体架构与数据流

三个进程：

- **towstrap-server**（`cmd/towstrap-server`，`internal/server`）：一个进程两个端口——SSH 口（gliderlabs/ssh）面向人，HTTP 口面向 agent（`/agent` 的 WebSocket）、监控（`/health` `/status`）、MCP（`/mcp`）、token 换发（`/token/refresh`）、公开 skill（`/skill`）和一键安装脚本（`/install.sh`、`/install.ps1`）。`Hub` 是核心：机器 ID → 已连接 agent 的映射，所有会话都经它建立。账号库是 SQLite（`internal/accounts`）。
- **towstrap-agent**（`cmd/towstrap-agent`，`internal/client`）：被控机上的常驻进程。主动 WebSocket 连出到 `/agent`，收 `open` 消息起本地进程（PTY 或 exec），双向搬运数据；处理 `token` 消息做远程换发；本地写审计、弹通知。
- **towstrap-mcp**（`cmd/towstrap-mcp`）：stdio MCP server。内部起 `mcpsrv.Server`，执行后端是 SSH 连接池（`Pool`）——它自己当 SSH 客户端登到服务器，走和普通 `ssh` 客户端一样的路。

```
SSH 会话:  ssh 客户端 ──SSH──> server(:2222) ──WS open/data──> agent ──> 本地 shell/进程
exec:      同上，pty=false，stdout/stderr 分两条流
MCP 调用:  LLM ──MCP──> towstrap-mcp(stdio, SSH 到 S) 或 /mcp(HTTP Bearer)
                        └── 都落到 server.Hub ──WS──> agent ──> shell -c
```

数据流细节：

- **SSH 交互**：`handleSSH` 解析登录名选机器 → `Hub.OpenShell` 发 `open`（带窗口尺寸/pty/命令/from）→ agent 起进程回 `ok` → `Hub.pipe` 双向搬运 `data`（32KB 分片），`resize` 透传窗口变化，stdin 关进发 `eof`，子进程退出 agent 回 `close`（带退出码）。
- **exec**：同一条路，`pty=false`；agent 侧 `shell -c` 起进程，stdout/stderr 用 `s` 字段分流，stdin 管道喂数据。
- **MCP**：内嵌模式下 `mcpRunner.Run` 直接调 `Hub.OpenShell`（pty=false）；stdio 模式 `Pool.Run` 建一条真实 SSH exec 会话，同样落到 `handleSSH` → `Hub` → agent。两者出口都是 agent 上的 `shell -c`。

## 2. WebSocket 协议

agent ↔ server 走一条 WebSocket（`/agent`），消息是单行 JSON 文本帧。消息类型定义在 `internal/proto/proto.go`：

| `t` | 方向 | 字段 | 语义 |
| --- | --- | --- | --- |
| `hello` | agent→server | `name`(agent ID)、`ver`(自报版本) | 连接后第一条；不是 hello 就回 `err` 断开 |
| `open` | server→agent | `id`、`cols`、`rows`、`pty`、`cmd`、`from` | 开会话；`cmd` 空 = 交互 shell，`pty` 决定走 PTY 还是 exec |
| `data` | 双向 | `id`、`d`(base64)、`s` | 数据分片；`s` 空 = stdout/PTY 流，`"e"` = stderr（仅 agent→server 用） |
| `eof` | server→agent | `id` | 客户端关了 stdin；exec 会话传给子进程，PTY 忽略 |
| `resize` | server→agent | `id`、`cols`、`rows` | PTY 窗口变化 |
| `close` | 双向 | `id`、`code` | 会话结束；agent→server 带子进程退出码，server→agent 表示杀会话 |
| `ok` | 双向 | `id` | 对 `open`/`token` 的确认 |
| `err` | 双向 | `id`、`err` | 失败应答（开会话失败、token 写不进文件等） |
| `token` | server→agent | `id`、`d`(新 token 明文) | 换发下推；agent 原子写文件后回 `ok`，失败回 `err` |

会话 ID：会话用 `s<N>`，token 换发请求用 `t<N>`（同一序号空间，前缀区分）。

限制与心跳（两侧一致）：

| 参数 | 值 | 作用 |
| --- | --- | --- |
| `MaxMessageBytes` | 256 KiB | 单条消息上限（读侧 `SetReadLimit`） |
| `MaxCommandBytes` | 64 KiB | `open.cmd` 上限，服务器在进 WebSocket 前先拦 |
| 数据分片 | 32 KiB | `data` 负载切片大小（base64 后约 44KB） |
| `PingPeriod` | 30 s | 双侧各发 WS ping |
| `PongWait` | 90 s | 这么久没收到任何消息（含 pong）就断 |
| `WriteWait` | 10 s | 单条写超时（同机会话共用写锁，卡住一个等于卡全部） |

## 3. 认证与限速

### SSH 认证路径（`internal/server/ssh.go`）

gliderlabs/ssh 按客户端尝试顺序调三个 handler：

1. **password**（`sshAuthOK`）：账号绑了 TOTP → 烧一次 bcrypt（`BurnPassword`，消时间侧信道）后直接拒，密码认证统一走 keyboard-interactive。否则 `verifyPassword`：全局白名单 → 锁定检查 → bcrypt 验密码 → 账号存在且未停用 → 账号白名单。全过后 `guard.pass` 清零并记 `AUTH-OK method=password`。
2. **keyboard-interactive**（`handleKbdInteractive`）：先问密码（同一个 `verifyPassword`，记 `method=kbd-interactive`），账号绑了 TOTP 再问验证码；验证码错计入限速（`reason=totp`）。整个流程（含验证码）通过才清零——「密码对就清零」会让攻击者拿泄露密码重置限速。
3. **publickey**（`handlePublicKey`）：全局白名单 → 公钥匹配（`VerifySSHKey`）→ 账号存在且未停用 → 账号白名单。**不进限速器**（客户端会连着试几把钥匙），也不要求 TOTP——公钥是给自动化的第二种凭据。成功记 `AUTH-OK method=publickey fp=SHA256:...`，并在会话 context 里标记 `publickey`（@ 管理命令和空闲重验都读它）。

时间侧信道处理：不存在的账号、停用账号、`BurnPassword` 路径都做同等耗时的 bcrypt 比较，按响应时间枚举用户名不可行。

### authGuard（`internal/server/authguard.go`）

内存中的双维度失败计数：

| 维度 | 键 | 阈值 | 窗口 |
| --- | --- | --- | --- |
| 账号×IP | `user\|ip` | 5 次失败 | 15 分钟滑动窗口 |
| 账号汇总 | `user` | 50 次失败 | 15 分钟 |

- 达到阈值锁定 **1 分钟**，之后每多失败一次锁定时长翻倍（移位上限 6 步 → 封顶 **1 小时**）
- 认证整体成功（含 TOTP）调 `pass()` 同时清两个维度的计数
- 表容量各 65536 条，满了先清过期再淘汰最旧——乱喷用户名的分布式爆破撑不大失败表
- **状态在内存，重启清零**
- 同一套 guard 也罩着 `/token/refresh` 的密码+TOTP 校验和 `@machine` 的 TOTP 重验

`/token/refresh` 锁定中再试返回 429；SSH 侧锁定表现为拒绝（`AUTH-FAIL reason=locked`）。

### 空闲重验（`idle_verify`，默认 30m）

绑了 TOTP 的账号 + PTY 会话 + 非公钥登录：输入流被 `idleGate` 包住，距上次输入超过阈值后下一笔输入先触发 TOTP 重验（SSH 通道内提示，3 次机会，全错断开）。输出活动不算使用；exec 会话和公钥登录不罩（往脚本 stdin 塞验证码提示会毁掉自动化）。

## 4. 数据模型与加密

### SQLite schema（`internal/accounts/accounts.go`）

```sql
CREATE TABLE IF NOT EXISTS users (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	username        TEXT    NOT NULL UNIQUE,
	password_hash   TEXT    NOT NULL,
	contact         TEXT    NOT NULL DEFAULT '',
	totp_secret_enc BLOB,
	totp_last_step  INTEGER NOT NULL DEFAULT 0,
	allow_ips       TEXT    NOT NULL DEFAULT '',   -- JSON 数组
	ssh_pubkeys     TEXT    NOT NULL DEFAULT '',   -- JSON 数组
	disabled        INTEGER NOT NULL DEFAULT 0,
	created_at      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS machines (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	username        TEXT    NOT NULL,
	name            TEXT    NOT NULL,
	token_enc       BLOB    NOT NULL UNIQUE,       -- AES-GCM（确定性）
	agent_allow_ips TEXT    NOT NULL DEFAULT '',   -- JSON 数组
	agent_last_ip   TEXT    NOT NULL DEFAULT '',
	created_at      TEXT    NOT NULL,
	UNIQUE(username, name)
);
CREATE INDEX IF NOT EXISTS idx_machines_token ON machines(token_enc);

CREATE TABLE IF NOT EXISTS mcp_clients (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT    NOT NULL UNIQUE,
	token_enc  BLOB    NOT NULL UNIQUE,            -- AES-GCM（seal "mcptoken"）
	machines   TEXT    NOT NULL DEFAULT '',        -- JSON 数组；["*"] = 全部
	allow_ips  TEXT    NOT NULL DEFAULT '',        -- JSON 数组
	disabled   INTEGER NOT NULL DEFAULT 0,
	created_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mcp_token ON mcp_clients(token_enc);
```

打开参数：`journal_mode=WAL`、`busy_timeout=5000`、单连接（SQLite 写是库级串行的，避免本进程内抢锁）。文件权限收紧到 0600。

### 加密（`internal/accounts/crypto.go`）

- **密钥文件** `users.key`：64 字节 = 32B AES-256 密钥 + 32B HMAC 密钥；首次自动生成（0600）；默认路径由 `users_db` 推出（去掉 `.db` 加 `.key`）。**库和 key 必须一起备份**，key 丢了所有 token 解不开。
- **AES-256-GCM 确定性加密**：nonce 由 `HMAC(macKey, purpose‖plaintext)` 派生前 12 字节——同一明文同一密文，因此可以按密文建唯一索引、按密文等值查询（`MachineByToken`、`MCPClientByToken` 都是这么查的）；不同明文 nonce 不同，不会出现 GCM nonce 复用。`purpose`（`"token"`/`"mcptoken"`/`"totp"`）绑定字段用途，密文挪到别的用途解密失败。
- **代价**：确定性加密会泄露「两个 token 是否相同」这类等值关系——对随机高熵 token 可接受，换来可索引。
- **密码**：bcrypt（DefaultCost），哈希自带随机盐，库里永无明文。
- **TOTP**：秘钥 AES-GCM 存 `totp_secret_enc`；`totp_last_step` 记已用过的最大时间片，同一码 30 秒窗口内不可重放（RFC 6238，6 位，30 秒片）。
- **用户名明文**：注册查重、登录查询都按它来（`UNIQUE`）。

### 老库迁移

`Open` 幂等做两件事：`ensureColumn` 给老表补 `ssh_pubkeys` 列；`migrateMachines` 检测 `users` 表有没有 `token_enc` 列——有就把每个账号的 `token_enc/agent_allow_ips/agent_last_ip` 搬进 `machines` 表（名字 `default`，同 key 同 seal 上下文的 BLOB 直接搬，不用解密），再建新 `users` 表去掉这些列（SQLite 删列的标准做法：建新表→搬数据→删旧表→改名）。

## 5. 账号与机器：Hub

- 机器 ID = `账号+机器名`（`SplitMachineID` 拆 `+`；`+` 不是合法名字字符，不会歧义）
- `Hub.Attach`：同名（同账号同机器名）再连**顶掉旧连接**（旧连接关掉、其会话全摘）记 `AGENT-REPLACE`；同账号不同机器名共存
- `agentConn` 记住接入时用的 token；**开会话前复核**（`agentCredentialValid`：token 仍映射到这台机器）+ **每 30 秒巡检**（`revokeLoop`→`PruneInvalid`，失效当场断开记 `AGENT-REVOKE`）——撤权（regen/remove/disable）对已连接的 agent 也立刻生效，不依赖下一次登录尝试
- `remove`（SSH @machine）和 `--disable` 后立即触发巡检，不等 30 秒
- 并发会话上限 `max_sessions`（默认 16/机）

## 6. token 生命周期

```
签发:  user add / machine add / @machine add → accounts.NewAgentToken() (tsa-)
       明文只在命令输出出现一次；库里是 encToken 后的密文
存储:  machines.token_enc（AES-GCM 确定性，UNIQUE + 索引）
查找:  X-Agent-Token → MachineByToken(token_enc 等值查询) → 机器 + 账号未停用检查
换发（两阶段）:
  ①  agent 机器上 towstrap-agent token refresh
       → POST /token/refresh（X-Agent-Token + JSON{password, totp, machines|all}）
  ②  服务器：验 token → 调用方 agent 白名单 → 锁定检查 → 验密码 → 验 TOTP
       → 对每台目标机器：Hub.RotateToken 下推 "token" 消息（10s 等 ack）
  ③  agent：writeTokenFile（同目录临时文件 0600 → write → sync → rename）
       → 成功回 ok 并就地换当前 token；失败回 err
  ④  服务器收到 ok → SetMachineToken 落库 → agentConn.setToken 更新记忆
       （不更新的话下次巡检会把这条连接当旧凭据踢掉）
```

- **没 ack 不换库**：`offline`（不在线）、`no-file`（token 不从文件读）、`timeout`（10 秒无应答）、`not-found`（机器不存在）、`error`
- **不一致告警**：agent 已写新 token 但落库失败 → `slog.Error("TOKEN 换发不一致…")` + status=`error`，需人工处理
- **重连重读**：agent 每轮重连前重读 token 文件（手动改文件也生效）
- **应急通道**：CLI `machine token --regen --admin` 直接落库换（记 `MACHINE-TOKEN-REGEN-ADMIN`），在线 agent 最多 30 秒内被巡检踢掉
- `/token/refresh` 细节：必须 POST + `Content-Type: application/json` + `X-Agent-Token`；请求体 ≤64KB；密码错记 `guard.fail`；全过 `guard.pass`；响应 `{"results":[{machine,status,detail}]}`

## 7. SSH 会话处理

- **选机器**：登录名带 `+机器名` 指名；不带时账号恰有一台机器落它，多台报错列出名单（含在线状态），零台报错。机器不存在/不在线/凭据失效都有明确报错 + `SESSION-DENY`（reason=no-machine/ambiguous/offline/credential）
- **`@` 前缀**是管理命令，进 `handleMgmt` 不发给 agent：公钥登录拒（reason=pubkey），TOTP 账号要新验证码（3 次机会，错计入限速），目前只有 `@machine list/add/remove/token/help`
- **PTY vs exec**：`sess.Pty()` 判定；PTY 走伪终端（unix 用 `creack/pty`，Windows 用 `x/sys/windows` 直写的 ConPTY——两条管道 + `CreatePseudoConsole` + `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`，窗口尺寸透传 + `resize`），exec 走 `shell -c` + 三根管道（stdout/stderr 分流用 `s="e"` 标记）
- **stdin/EOF**：客户端关 stdin → 服务器发 `eof` → exec 会话把它传给子进程（`cat` 靠 EOF 收尾）；PTY 会话忽略（Ctrl-D 本来就是数据流里的字符）
- **退出码**：agent 侧 `exitCode()`：正常退出取 ExitCode；信号杀取 128+信号；进程没起来等错误取 255。服务器侧 `session.code` 默认 255，收到 agent 的 `close.code` 才覆盖——agent 掉线不会被记成 0。MCP 侧 `run_command` 超时被 SIGKILL 时 `timed_out=true` 且 `exit_code=-1`
- **命令长度**：`open.cmd` 上限 64KB，超长 `SESSION-DENY reason=cmd-too-long`
- **环境**：子进程环境剥掉 `TOWSTRAP_AGENT_TOKEN`，补 `TERM=xterm-256color`
- **空闲重验**：见 §3

## 8. MCP 层

### 结构（`internal/mcpsrv`）

- `Server` = 配置 + 编译好的 `Policy` + `Runner` 后端；`Runner` 接口两种实现：stdio 模式 `Pool`（懒建 SSH 连接池，按机器复用，连接层错误自动重拨重试一次），内嵌模式 `mcpRunner`（直接走 Hub，等价无密码 exec）
- 内嵌模式每个请求新建 `mcpsrv.Server`（`getServer` 回调），机器集合按该请求的客户端凭据现算——改授权不用重启
- `Implementation.Name = "towstrap-mcp"`；`initialize` 响应带 `Instructions`（给 LLM 的使用须知 + 机器列表 + 策略概况）

### 四个工具（`tools.go`）

| 工具 | 入参 | 出参 | 策略 |
| --- | --- | --- | --- |
| `list_machines` | — | `machines[]`：name/description/roots/connected | 无 |
| `run_command` | `machine`、`command`、`cwd?`、`stdin?`、`timeout_seconds?` | `exit_code`、`stdout`、`stderr`、`timed_out`、`*_truncated`、`duration_ms`、`approval` | deny→拒；全段 allow→放行；否则批准 |
| `read_file` | `machine`、`path` | `content`、`bytes` | deny_paths 拦；≤max_file；含 NUL 拒（二进制） |
| `write_file` | `machine`、`path`、`content` | `bytes_written` | deny_paths 拦；≤max_file；在 roots 内放行否则批准 |

实现细节：`run_command` 带 `cwd` 时包成 `cd -- 'cwd' && (命令)`（shellQuote 单引号包裹）；`read_file` 实际是 `head -c max+1`；`write_file` 是 `cat > 'path'` + stdin；输出超限保留头尾各半加省略标记（`CapWriter`）；`timeout_seconds` 超 `max_timeout` 会被夹到上限并注明。工具错误走 `IsError` + 文字（不变成协议级错误，LLM 能看到原因）。

### 策略引擎（`policy.go`）

`Policy.Command` 流程：

1. 整串命令先过全部 deny 正则（防切段藏雷）
2. 按 `&&`、`||`、`;`、`|`、`换行` 朴素切段；**每段**再过 deny
3. 段里出现 `` ` ``、`$(`、`>`、`<`、`&` → 标记不安全（命令替换/重定向/后台都可能藏第二动作）
4. 安全且每段都命中 allow → `Run`；否则落 `policy.default`

`deny` 优先于一切。内置名单（写配置里同名项就**整份替换**）：

- `DefaultAllow`：`ls/pwd/cat/head/tail/wc/grep/rg/find/stat/file/echo/which/whoami/id/uname/df/du/ps/date/tree`；裸 `env`；`git status|diff|log|show|remote|rev-parse|ls-files|blame`、`git branch` 只读形态；`go build|test|vet|fmt|list|mod tidy|doc|version`；`npm/pnpm/yarn test|run test|run lint|run build|ls`；`cargo/make test|build|check|fmt`；`python/python3/node --version`；`gofmt`
- `DefaultDeny`：`rm -r /`、`rm ~`、`mkfs`、`dd of=/dev/`、`shutdown/reboot/halt/poweroff`、`curl|sh`、`wget|sh`、`find -exec/-delete`、`rg --pre`、`> /dev/sd`、`chmod 777 /`、`.ssh/id_*`、`.ssh/authorized_keys`、`/etc/shadow`、`/etc/sudoers`、`sudo`、`su`、`towstrap-agent`（不许动 agent 自身）
- `DefaultDenyPaths`：`.ssh/`、`.gnupg/`、`/etc/shadow`、`/etc/sudoers`、`.aws/credentials`、`towstrap/token`、`towstrap/agent.yaml`

### 路径策略

- `deny_paths`：正则对**原始路径和 `path.Clean` 后的路径**各匹配一遍
- `roots`（write_file 放行目录）：**文本前缀匹配**，只接受绝对路径或 `~/` 开头（相对路径一律算不在——远端家目录无从知晓）；`~` 不展开
- **已知限制**：不解析远端符号链接——roots 里的 `link -> /etc` 会让 `link/x` 逃过前缀匹配。roots 目录内别放指向外面的符号链接

### 人工批准（`approval.go`）

两层机制：

1. **elicitation（弹窗）**：客户端 `initialize` 声明了 elicitation 能力 → handler 返回带 `InputRequests` 的 `CallToolResult`（go-sdk 的 MRTR/SEP-2322 模式，新旧协议都兼容，SDK 完成往返后把 handler 再调一次、答复在 `InputResponses["approval"]`）。schema 两个字段：`approve`（bool，必填）和 `remember`（bool，「本次会话内相同命令不再询问」）
2. **本地文件回退**：不支持弹窗 → `approvals_dir` 里落 `<id>.json`（`{id,machine,kind,detail,cwd,created,pid}`，0600），stdio 模式同时弹桌面通知；用户跑 `approve <id>` 写 `<id>.approved`、deny 写 `<id>.denied`，服务侧每 500ms 轮询直到 `ask_timeout`

`remember` 按**客户端会话**记（`machine + detail` 为键，会话结束清理）。超时/用户取消 → `Timeout`；批准环节不可用 → `Unavailable`。进出批准环节记 `MCP-ASK`（via=elicit/local）和结果事件 `MCP-APPROVED`/`MCP-DENIED`/`MCP-ASK-TIMEOUT`。

### 内嵌模式鉴权顺序（`internal/server/mcp.go`）

`/mcp` 挂 `RequireBearerToken`，`mcpBearer` 顺序：服务器全局 `allow_ips` → `mcp_clients` 查 token（`MCPClientByToken`：token 有效且未停用）→ 客户端自己的 `allow_ips`。任何一步不过记 `MCP-AUTH-FAIL`（reason=allow-ip/token/client-allow-ip）回 401；明文 token 不进请求上下文。新会话（无 `Mcp-Session-Id` 头）记 `MCP-SESSION`（30 秒去重）。Streamable HTTP 会话超时 30 分钟。

执行走 `mcpRunner.Run`：机器必须在客户端授权集合里（`machines` 四种写法展开：`'*'`→全部、`'alice'`/`'alice+*'`→该账号全部且未停用、`'alice+office'`→指定一台）、机器在线、接入凭据复核；审计 `SESSION-START mode=mcp from=mcp:客户端名@IP`。

## 9. skill 与 harness

- **源**：`skills/towstrap/SKILL.md`，`skills/embed.go` 用 `//go:embed` 编进 `towstrap-mcp` 和 `towstrap-server`（`/skill` 端点服务的就是这份）
- **harness 表**（`internal/harness/harness.go`，按家目录检测）：

| Harness | 检测 | 安装到 |
| --- | --- | --- |
| Claude Code | `~/.claude` | `~/.claude/skills` |
| Codex | `~/.codex` | `~/.agents/skills`（共享目录，避免重复） |
| Grok Build | `~/.grok` | `~/.agents/skills`（同上） |
| Cursor | `~/.cursor` | `~/.cursor/skills` |
| Gemini CLI | `~/.gemini` | `~/.gemini/skills` |
| OpenCode | `~/.config/opencode` | `~/.config/opencode/skills` |
| GitHub Copilot CLI | `~/.copilot` | `~/.copilot/skills` |
| Devin CLI | `~/.config/devin` | `~/.config/devin/skills` |

- **manifest**：`<skills目录>/towstrap/.towstrap-managed.json` 记 `{version, sha256, installed_at}`。有 manifest → 按版本升级（用户改过的内容被覆盖时提示）；无 manifest → 视为用户自建同名 skill，跳过（`--force` 才覆盖）。卸载时 sha 不一致（用户改过）跳过，`--force` 才删。写入走临时文件 + rename
- **print-mcp**：为各家生成配置片段（纯函数）。字段来源：Claude Code `{"type":"http",url,headers}` + `claude mcp add` 命令；Codex `config.toml` 的 `url` + `http_headers`（来源 developers.openai.com/codex/config-reference）；Grok `url` + `headers` 内联表（本机 grok 文档）；Cursor `url`/`headers` 或 `command`/`args`；Gemini `httpUrl` + `headers`（`url` 是 SSE 传输，不能用错）；OpenCode `{"type":"remote",url,headers}` / `{"type":"local","command":[…]}`

## 10. 配置参考

### server.yaml（`internal/config`）

| 键 | 类型 | 默认 | 说明 / 对应旗标 |
| --- | --- | --- | --- |
| `http` | string | `:8080` | HTTP 监听地址 / `--http` |
| `ssh` | string | `:2222` | SSH 监听地址 / `--ssh` |
| `host_key` | string | users_db 同目录 `ssh_host_key` | SSH 主机密钥 / `--host-key` |
| `users_db` | string | `/etc/towstrap/users.db` | 账号库 / `--users-db` |
| `users_key` | string | `users_db` 去 `.db` + `.key` | 加密密钥 / `--users-key` |
| `admin_token` | string | 空 | `/status` 管理口令 / `--admin-token` |
| `public_url` | string | 空 | 对外 wss:// 地址，生成安装命令用 / `--public-url` |
| `tls` | bool | `false` | HTTPS/WSS / `--tls` |
| `cert` / `key` | string | 空 | 证书 / `--cert` `--key`；空则自签到 `./tls_cert.pem` `./tls_key.pem` |
| `allow_ips` | []string | 空 | 全局白名单 / `--allow-ip`（可重复） |
| `idle_verify` | duration | `30m` | TOTP 空闲重验阈值，`0` 关 / `--idle-verify` |
| `min_agent_version` | string | 空 | agent 版本下限 / `--min-agent-version` |
| `audit_log` | string | 见下 | 审计路径 / `--audit-log`；`/dev/null` 关 |
| `max_sessions` | int | `16` | 每机并发会话 / `--max-sessions` |
| `max_conns` | int | `4096` | 每口并发连接总上限 / `--max-conns` |
| `max_conns_per_ip` | int | `64` | SSH 每 IP 并发 / `--max-conns-per-ip` |
| `ssh_idle_timeout` | duration | `0` | SSH 空闲超时 / `--ssh-idle-timeout` |
| `ssh_max_timeout` | duration | `24h` | SSH 连接绝对寿命 / `--ssh-max-timeout` |
| `mcp.enabled` | bool | `false` | 内嵌 MCP 开关（无旗标） |
| `mcp.path` | string | `/mcp` | 挂载路径 |
| `mcp.allow_plain_http` | bool | `false` | 明文+非回环放行开关 |
| `mcp.approvals_dir` | string | 审计日志目录旁 `approvals/` | 待批文件目录 |
| `mcp.machines.<id>.description` / `.roots` | string / []string | — | MCP 侧元数据；键是完整机器 ID |
| `mcp.policy` / `mcp.limits` | — | 内置默认 | 与 mcp.yaml 同格式 |

审计默认路径：root `/var/lib/towstrap/server-audit.log`，其他用户 `~/.towstrap/server-audit.log`。

### agent.yaml

| 键 | 类型 | 默认 | 说明 / 旗标 |
| --- | --- | --- | --- |
| `agent.server` | string | 必填 | `ws(s)://`（也认 `http(s)://`）/ `--server` |
| `agent.agent_token` | string | — | 直写 token / `--agent-token`（会进 ps） |
| `agent.agent_token_file` | string | — | 0600 文件（推荐，支持远程换发）/ `--agent-token-file` |
| `agent.shell` | string | `$SHELL` → `/bin/bash` | 远程会话用的 shell / `--shell` |
| `agent.insecure` | bool | `false` | 跳过 TLS 校验 / `--insecure` |
| `agent.quiet` | bool | `false` | 关通知（审计仍写）/ `--quiet` |
| `agent.audit_log` | string | root `/var/lib/towstrap/audit.log`，其他 `~/.towstrap/audit.log` | / `--audit-log` |

token 也认环境变量 `TOWSTRAP_AGENT_TOKEN`。token 来源优先级（`resolveAgentToken`）：`--agent-token` > `--agent-token-file` > 环境变量 > yaml `agent_token` > yaml `agent_token_file`；其余项是旗标 > yaml > 默认。

### mcp.yaml（stdio，`internal/mcpsrv/config.go`）

| 键 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `server` | string | 必填 | 服务器 SSH 入口 `host:port` |
| `key` | string | 必填 | 无口令私钥路径 |
| `known_hosts` | string | — | 主机密钥校验（与 host_key 二选一） |
| `host_key` | string | — | 钉死 SHA256 指纹，设了不看 known_hosts |
| `machines.<登录名>.description` | string | — | 给 LLM 看的说明 |
| `machines.<登录名>.roots` | []string | — | write_file 自动放行目录 |
| `policy.default` | string | `ask` | `run`/`ask`/`deny` |
| `policy.allow` / `deny` / `deny_paths` | []正则 | 内置名单 | 写了就整份替换 |
| `policy.ask_timeout` | duration | `5m` | 批准等待上限 |
| `limits.timeout` | duration | `120s` | run_command 默认超时 |
| `limits.max_timeout` | duration | `1h` | timeout_seconds 上限 |
| `limits.max_output` | int | `65536` | stdout/stderr 各自上限（≥1024） |
| `limits.max_file` | int | `1048576` | read/write 文件上限 |
| `approvals_dir` | string | `~/.config/towstrap/approvals` | 待批文件目录 |

校验：`timeout ≤ max_timeout`；`max_output ≥ 1024`；stdio 模式 `server`/`key`/`machines` 必填。默认配置路径 `~/.config/towstrap/mcp.yaml`。

## 11. CLI 参考

### towstrap-server

```
towstrap-server [旗标]                                   跑服务器
towstrap-server user add|list|set|remove|token|totp     账号管理
towstrap-server machine add|list|set|remove|token       机器管理
towstrap-server mcp add|list|set|remove|token|pending|approve|deny
towstrap-server version                                  版本
```

通用选项（管理子命令共用）：`--config server.yaml`（读 users_db/users_key/public_url/audit_log/mcp 小节）、`--users-db`、`--users-key`、`--server-url`、部分命令有 `--audit-log`、`--admin`。

- `user add 名字 [--password] [--contact] [--allow-ip]... [--agent-allow-ip]... [--ssh-key]... [--ssh-key-file]`：不给 `--password` 生成 16 位随机密码只显示一次；自动带 `default` 机器
- `user set`：`--password` `--name` `--contact`/`--clear-contact` `--allow-ip`/`--clear-allow` `--agent-allow-ip`/`--clear-agent-allow` `--ssh-key`/`--ssh-key-file`/`--remove-ssh-key`/`--clear-ssh-keys` `--disable`/`--enable`
- `user token 名字 [--regen] [--admin]`：仅单机账号；本人确认；`--regen` 必须 `--admin`
- `user totp 名字 [--remove]`：绑定（打印 otpauth URI + 秘钥，输码确认）/解绑
- `machine add 账号 机器名 [--agent-allow-ip]... [--admin]`：本人确认
- `machine list [账号]` / `machine set 账号 机器名 [--agent-allow-ip]... [--clear-agent-allow]` / `machine remove 账号 机器名` / `machine token 账号 机器名 [--regen] [--admin]`
- `mcp add 名字 --machine 授权... [--allow-ip]...`：签发 tsm- token + 打印客户端配置 + skill 安装命令；`--machine` 四写法 `*`/`alice`/`alice+*`/`alice+office`
- `mcp list` / `mcp set 名字 [--machine]... [--allow-ip]... [--clear-allow] [--disable|--enable]` / `mcp remove` / `mcp token [--regen]`
- `mcp pending` / `mcp approve <id>|--all` / `mcp deny <id>|--all`：`--approvals-dir` > yaml `mcp.approvals_dir` > 审计目录旁 `approvals/`

### towstrap-agent

```
towstrap-agent [旗标]                                    常驻运行
towstrap-agent token refresh [--machine 机器名]... [--all] [--allow-plain]
```

旗标：`--config --server --agent-token --agent-token-file --shell --insecure --audit-log --quiet`。`refresh` 交互问密码 + TOTP；退出码 0 全 ok / 1 部分失败 / 2 参数或鉴权错。

### towstrap-mcp

```
towstrap-mcp [--config mcp.yaml]              跑 stdio MCP server
towstrap-mcp pending|approve <id>|--all|deny <id>|--all   批准兜底
towstrap-mcp connect [list|uninstall|print-mcp] [--path] [--force] [--dry-run]
                [--url URL --token tsm-...] | [--stdio]
```

## 12. HTTP 端点参考

| 路径 | 方法 | 鉴权 | 说明 |
| --- | --- | --- | --- |
| `/health` | GET | 无 | 进程活着，`200 ok` |
| `/status` | GET | `X-Admin-Token`（全量）或 `X-Agent-Token`（只看自己） | `{"ok","http","ssh","users":[{user,machine,online,disabled?}]}`；无在线机器时 503 |
| `/agent` | GET(Upgrade) | `X-Agent-Token` | WebSocket 接入点；401 无效 token，403 agent 白名单拒绝 |
| `/mcp` | POST 等 | `Authorization: Bearer tsm-…` | Streamable HTTP MCP；401 记 `MCP-AUTH-FAIL`；明文+非回环拒启动 |
| `/token/refresh` | POST | `X-Agent-Token` + JSON 密码/TOTP | 见 §6；`{"results":[…]}`；401/403/429 记 `TOKEN-REFRESH-DENY` |
| `/skill` | GET/HEAD | 无（公开文档） | `text/markdown; charset=utf-8`，`Cache-Control: public, max-age=3600`；其他方法 405 |
| `/install.sh` | GET/HEAD | 无（公开文档） | unix 一键安装脚本；`__TOWSTRAP_DEFAULT_SERVER__` 换成 `public_url`（没配则按请求 Host + TLS 推导），`Cache-Control: no-cache` |
| `/install.ps1` | GET/HEAD | 无（公开文档） | Windows PowerShell 版，同上 |

HTTP 口固定参数：`ReadHeaderTimeout 10s`、`IdleTimeout 2m`、`MaxHeaderBytes 16KB`；TLS 最低 1.2。

## 13. 审计事件参考

格式 `<RFC3339时间> <事件> k=v`；`cmd` 超 512 字节截断；值中控制字符被清洗。

**服务器侧**（`server-audit.log`）：

| 事件 | 关键字段 | 触发 |
| --- | --- | --- |
| `AUTH-OK` | user ip method(password/kbd-interactive/publickey) [totp=true] [fp] | SSH 认证成功 |
| `AUTH-FAIL` | user ip method reason(locked/password/disabled/allow-ip/totp) | 认证失败 |
| `AGENT-CONNECT` | id ip version | agent 接入 |
| `AGENT-REPLACE` | id ip | 同名顶替 |
| `AGENT-DISCONNECT` | id ip | 连接断开 |
| `AGENT-REVOKE` | id | 巡检发现凭据失效，当场断开 |
| `AGENT-DENY` | id ip reason(agent-allow/old-version) [ver min] | 接入被拒 |
| `AGENT-IPCHANGE` | id old new | 来源 IP 变了（无白名单时） |
| `SESSION-START` | user from id mode(pty/exec/mcp) machine cmd | 会话建立 |
| `SESSION-END` | user from id code | 会话结束（退出码） |
| `SESSION-DENY` | user from reason | 会话被拒 |
| `MGMT-DENY` | user from reason(pubkey/locked/totp) | `@` 命令被拒 |
| `MACHINE-ADD` `MACHINE-REMOVE` `MACHINE-TOKEN` | user machine from | SSH 自助管理 |
| `MACHINE-ADD-ADMIN` `MACHINE-TOKEN-ADMIN` `MACHINE-TOKEN-REGEN-ADMIN` | user machine | CLI `--admin` 跳过本人确认（由 CLI 进程写） |
| `TOKEN-REFRESH` | user machine from(agent:调用者@ip) status | 每台一条换发结果 |
| `TOKEN-REFRESH-DENY` | [user] ip reason | 换发被拒 |
| `MCP-SESSION` | client ip | MCP 新会话（30s 去重） |
| `MCP-AUTH-FAIL` | ip reason | Bearer 校验失败 |
| `MCP-POLICY-DENY` | client ip machine kind detail reason | 策略拒绝 |
| `MCP-ASK` | client ip machine kind detail via(elicit/local) | 进入批准 |
| `MCP-APPROVED` `MCP-DENIED` `MCP-ASK-TIMEOUT` | client ip machine kind detail | 批准结果 |

**agent 侧**（`audit.log`）：

| 事件 | 字段 | 触发 |
| --- | --- | --- |
| `AGENT-START` | version id server shell insecure quiet uid audit | 进程启动 |
| `START` | id from mode(pty/exec) cmd | 会话开始（from 格式校验不过会脱敏为「未知来源」） |
| `END` | id from | 会话结束 |
| `TOKEN-ROTATED` | id | 下推的新 token 写入文件 |

## 14. 安全模型与已知限制

### 信任边界

| 边界 | 说明 |
| --- | --- |
| agent 系统用户 | **真正的边界**：远程命令以 agent 进程的用户身份执行。专用低权限用户是必选项，不是建议 |
| 服务器 | 持有 users.db + users.key 的人等于持有全部凭据的解密能力（token 可解密回显）；文件 0600 只是兜底 |
| MCP 策略 | 过滤层，不是沙箱：朴素切段绕得过完整 shell 语义 |
| 来源 IP | 白名单/限速/IPCHANGE 都按 TCP 来源 IP 判断——反向代理会毁掉全部三层 |

### 已知限制

- **反向代理**：见 README 安全须知；需要前置就用四层透传（保留源 IP）或云防火墙
- **root 运行**：只打告警不阻止（`warnIfRoot`，审计 `uid=`）
- **roots 符号链接**：前缀匹配不解析远端链接，逃逸见 §8
- **明文**：`/mcp` 有拒启动保护；agent 普通连接 ws:// 不拦（内网场景），但 `token refresh` 的密码走非回环明文要 `--allow-plain` 显式确认
- **公钥登录不进限速器**：客户端试多把钥匙计失败会误锁；同时公钥不可猜测。代价：公钥探测不设限（也不记每次失败审计）
- **agent 版本自报**：`min_agent_version` 是运维门槛不是安全控制
- **限速状态在内存**：重启清零
- **确定性加密泄露等值关系**：见 §4
- **`@machine` 管理只认密码类登录**：公钥自动化不能管机器（设计取舍）
- **没有 scp/sftp**：文件传输走 cat/heredoc 或 MCP 文件工具

## 15. 构建、测试与发布

- **Make 目标**：`build`（三个二进制到 `bin/`）、`test`（`go vet` + `go test ./...`）、`release`（交叉编译 darwin/linux/windows × amd64/arm64 → `dist/` + `SHA256SUMS`，设 `MINISIGN_KEY_FILE` 顺带 minisign 签名）、`clean`
- **版本注入**：`-ldflags "-X github.com/towstrap/towstrap/internal/version.Version=$(cat VERSION)"`；`version` 命令和 `hello` 消息的 `ver` 都用它
- **测试结构**：各 `internal/*` 包单测 + `internal/e2e` 端到端——e2e 起**真实的服务器进程内实例 + 真实 agent 连接**，覆盖 SSH 密码/TOTP/公钥登录、爆破锁定、exec、多机、token 换发、MCP HTTP/stdio、@machine、撤权等
- **依赖**：全部静态 Go（modernc sqlite 无 CGO），三个二进制零依赖
- **CI/发布**：`.github/workflows/ci.yml` 在 main 推送和 PR 上跑 `vet + test + build`；`.github/workflows/release.yml` 在 `v*` 标签触发，先跑测试再 `make release`（版本号取标签去掉 `v`），仓库 Secrets 里放了 `MINISIGN_KEY`（未加密私钥的 base64）就自动签名，最后 `gh release create` 把 `dist/` 全部挂到 Release
