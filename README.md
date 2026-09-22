# ws2ssh

机器上的 agent 主动用 WebSocket 连出到服务器，外人 SSH 连服务器，进到 agent 那台机器的命令行。被访问的机器**不用开 sshd**、不用有公网 IP。

当前版本 **0.2.0**。全部配置都在命令行完成，不需要网页。

```
外人 ssh 用户名@服务器
        │ 密码是建号时自己设的
        ▼
   服务器（按账号验密码）
        │  WebSocket /agent（token 也是按账号发的）
        ▼
   机器（本机 shell）
```

账号（人）和机器（agent）是分开的两层：**一个账号可以挂多台机器**，每台机器有自己独立的 **agent token**（`w2s-...`，建号时自动生成第一台）。外人用账号的 **SSH 用户名/密码**登录，登录名写 `账号+机器名` 指定落到哪台（如 `alice+office`）；账号只有一台机器时写账号名就行。

## 快速开始

```bash
make build   # 或：go build -o bin/ws2ssh-server ./cmd/ws2ssh-server && go build -o bin/ws2ssh-agent ./cmd/ws2ssh-agent
```

**1. 服务器上建号**（自定义用户名、密码，可设这台机器的 IP 白名单）：

```bash
./ws2ssh-server user add office --password 自己设的密码 --allow-ip 1.2.3.4
```

建号会自动带出一台名为 `default` 的机器，输出它的 agent token 和安装命令：

```
默认机器: office+default
agent token: w2s-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
在那台机器上执行 agent 安装命令：
  ws2ssh-agent --server wss://<服务器地址> --agent-token w2s-xxxx...
```

（把 `public_url: wss://你的域名:443` 写进 server.yaml，或加 `--server-url`，就会生成完整命令。）

**2. 在要被访问的机器上跑 agent**（不用开 sshd）：

```bash
ws2ssh-agent --server wss://你的服务器:443 --agent-token w2s-xxxx...
```

断线后自动重连：2 秒起步、指数退避到 30 秒封顶、带随机抖动（服务器重启时几千台机器不会同一毫秒全冲回来）；连接稳定运行超过一分钟就重置回 2 秒。agent 是远程访问的入口，默认开着重端感知（见下节）：有人连入会弹通知、广播终端，并写审计日志。

**3. 外人连接**（用户名和密码就是建号时设置的）：

```bash
ssh office@你的服务器IP -p 2222
```

机器没上线会提示 agent 未连接。**同一个账号下可以再挂机器**（每台机器独立 token）：

```bash
./ws2ssh-server machine add office build   # 再拿一个 w2s-... token（会问 office 的密码做本人确认）
```

一个账号有多台机器后，`ssh office@...` 会报错并列出机器名单和在线状态，要指名：`ssh office+default@...` 或 `ssh office+build@...`。同一台机器（同名）的 agent 再连会顶掉旧连接，不同机器名互不干扰。

**服务器本身**（配置文件是主入口，旗标只做临时覆盖）：

```bash
cp examples/server.yaml server.yaml   # 按需改：地址、TLS、白名单、限额、审计……
                                       # 每个键的含义都在示例文件的注释里
./ws2ssh-server --config server.yaml

# 临时覆盖某一项（不改文件）：
./ws2ssh-server --config server.yaml --max-conns 100
```

SSH 主机密钥默认放在和 `users.db` 同目录的 `ssh_host_key`（即 `/etc/ws2ssh/ssh_host_key`），第一次启动自动生成；文件存在但读不了或解析失败会直接报错退出，**不会**静默换一把新钥匙——主机密钥一变，所有人的 ssh 客户端都会告警。

启动时会回显一行**生效配置**（`http=... ssh=... tls=... max_sessions=... audit_log=...`，秘密只显示设没设）——排查「yaml 到底生效没」看这行就行。

agent 同理支持 `--config agent.yaml`（见 `examples/agent.yaml`，包括从 0600 文件读 token）。`user add` 生成的安装命令用的是旗标，装好后换成配置文件更省心。

## 账号管理（都在服务器上的 ws2ssh-server 命令操作）

| 命令 | 作用 |
| --- | --- |
| `ws2ssh-server user add 名字 [--password 密码] [--contact 联系方式] [--allow-ip 地址]... [--agent-allow-ip 地址]... [--ssh-key 公钥]... [--ssh-key-file 文件]` | 建号，自动带一台 `default` 机器并打印它的 token 和安装命令 |
| `ws2ssh-server user list` | 列出账号、名下机器、白名单、TOTP 状态、公钥数、联系方式 |
| `ws2ssh-server user set 名字 [--password 密码] [--name 新名] [--contact 联系方式] [--allow-ip 地址]... [--agent-allow-ip 地址]... [--ssh-key 公钥]... [--ssh-key-file 文件] [--remove-ssh-key 公钥或SHA256指纹]... [--clear-ssh-keys] [--clear-allow] [--disable\|--enable]` | 改密码 / 改名 / 改备注 / 改白名单 / 增删公钥 / 停启用（`--agent-allow-ip` 只作用于唯一那台机器，多台时用 `machine set`） |
| `ws2ssh-server user remove 名字` | 删号，名下机器的 token 全部作废 |
| `ws2ssh-server user token 名字 [--regen] [--admin]` | 查看 token（仅当账号只有一台机器；多台时用 `machine token`）。要本人确认；`--regen` 是应急通道，必须加 `--admin` |
| `ws2ssh-server machine add 账号 机器名 [--agent-allow-ip 地址]... [--admin]` | 在账号下加一台机器，打印它的独立 token 和安装命令。要本人确认 |
| `ws2ssh-server machine list [账号]` | 列机器（账号、机器名、登录名、agent 白名单、token） |
| `ws2ssh-server machine set 账号 机器名 [--agent-allow-ip 地址]... [--clear-agent-allow]` | 改这一台机器的 agent 来源白名单 |
| `ws2ssh-server machine remove 账号 机器名` | 删一台机器，token 立刻作废 |
| `ws2ssh-server machine token 账号 机器名 [--regen] [--admin]` | 查看这一台机器的 token。要本人确认；`--regen` 是应急通道，必须加 `--admin` |
| `ws2ssh-server user totp 名字 [--remove]` | 绑定 / 解绑 TOTP 二因素 |

不写 `--password` 会生成 16 位强随机密码，**只显示一次**（库里只有 bcrypt 哈希，丢了只能重设）。密码至少 10 位。改名后 agent 不用动（它靠 token 认，不靠名字）。服务器每次校验都直连账号库，改完立即生效，不用重启。

### 账号本人确认（CLI）和 SSH 自助管理

会签发或暴露机器 token 的 CLI 命令——`machine add`、`machine token`（含不带 `--regen` 的查看）、`user token`——默认要**账号本人确认**：先问这个账号的 SSH 密码，绑了 TOTP 再问验证码；确认失败直接退出。这样「能碰服务器上的命令行」不等于「能给任何账号发 token」。管理员要绕过加 `--admin`：会打一条警告，并往服务器审计日志写 `MACHINE-ADD-ADMIN` / `MACHINE-TOKEN-ADMIN`（审计文件按 `--audit-log` 旗标 > yaml `audit_log` > 默认位置找）。

账号本人也可以**直接用 SSH 自助管理**名下机器——`@` 开头的命令保留给服务器自己执行，不会发给 agent：

```bash
ssh office@服务器 -p 2222 '@machine list'                  # 列名下机器：ID、在线/离线、agent白名单（不显示 token）
ssh office@服务器 -p 2222 '@machine add build'             # 加机器，直接打印新 token 和安装命令
ssh office@服务器 -p 2222 '@machine add build --agent-allow-ip 10.0.0.5'
ssh office@服务器 -p 2222 '@machine remove build'          # 删机器，在线 agent 立刻断开
ssh office@服务器 -p 2222 '@machine token build'           # 看这台的 token（换 token 在 agent 机器上跑，见下节）
ssh office@服务器 -p 2222 '@machine help'                  # 用法说明
```

- **只能密码登录跑**：公钥登录是给自动化用的，跑 `@` 命令会被拒（记 `MGMT-DENY reason=pubkey`）。
- **绑了 TOTP 的账号要再输一个新的验证码**——登录时用过的那个不能重放；连错 3 次断开，错一次记一条 `MGMT-DENY reason=totp` 并计入登录限速。没绑 TOTP 的账号密码登录就是本人，不再多问。
- 登录名带后缀也行：`ssh office+default@... '@machine list'` 按账号部分处理。

### 换 token（在 agent 机器上跑）

换一台机器的 token **在被控机本地发起**，不是在服务器上：

```bash
# 在 office 的一台 agent 机器上执行：
ws2ssh-agent token refresh                # 只换本机（会问账号密码；绑了 TOTP 再问验证码）
ws2ssh-agent token refresh --machine build        # 换同账号下的 build（它得在线）
ws2ssh-agent token refresh --all                  # 换账号下全部机器
```

- **鉴权是双重的**：本机的 agent token（证明你在一台已登记机器上）+ 账号密码 + TOTP（证明是账号主人）。
- **下推 + 确认（ack）**：服务器把新 token 经目标机器**现有的 WebSocket 连接**发过去，agent 原子写进自己的 token 文件（同目录临时文件 → rename，权限 0600）后回执；**收到回执服务器才把库里的旧 token 作废**。写不了文件、超时、机器离线都不换——机器不会因为这步掉线，连接也不用重连。
- **前提**：目标机器的 token 是从文件读的（`--agent-token-file` 或配置 `agent_token_file`）。命令行 `--agent-token` 或环境变量给的 token 没法远程换（结果会报 `no-file`）。agent 每次重连还会重读一遍 token 文件，手动改过文件的也生效。
- 服务器地址是明文 `ws://` 且不在本机回环时，要先确认是内网再加 `--allow-plain`——密码不能裸奔。
- **应急**：机器离线/丢了没法走这条通道时，服务器 CLI 的 `machine token 账号 机器名 --regen --admin`（或单机 `user token --regen --admin`）兜底换——打警告并记 `MACHINE-TOKEN-REGEN-ADMIN` 审计。

账号存在 **SQLite 数据库**里（默认 `/etc/ws2ssh/users.db`，纯 Go 驱动，不需要装任何东西）：

- **密码**：bcrypt 哈希存储——bcrypt 每次哈希自带 128 位随机盐（哈希串里的 `$2a$10$<盐>` 那段），改密码换新盐，库里永远没有明文，也无法还原。
- **用户名**：明文存放，建了 UNIQUE 索引——注册时重名直接报「账号已存在」，SSH 登录也按它查询。
- **token**：每台机器一个，存在 `machines` 表里，AES-256-GCM 加密存储（确定性加密，同一明文同一密文，才能按密文建唯一索引和查询）。密钥在单独的 `users.key` 文件里（权限 0600，首次自动生成）。
- **备份**：`users.db` 和 `users.key` 要一起备份；key 丢了 token 解不开，agent 全部失联，只能挨个换 token。
- **老库自动迁移**：从旧版本（一个账号一个 token）升级时，`Open` 会把每个账号原有的 token、agent 白名单和最近来源 IP 搬到一台名为 `default` 的机器上——升级后原账号变成 `账号+default`，老 token 不变，agent 不用动。

## 白名单

两层，先过全局再过账号自己的：

```yaml
server:
  allow_ips: [10.0.0.0/8]   # 全局：谁能连 SSH
```

```bash
ws2ssh-server user add office --allow-ip 1.2.3.4 --allow-ip 10.0.0.0/8   # 只有这些来源能 ssh office
ws2ssh-server user set office --clear-allow                               # 清空 = 不限来源
```

条目可以是 IP、网段、`IP:端口`、主机名、`*.domain` 或 `*`。不写就全放行。

### agent 连接的来源限制

`--allow-ip` 管的是「谁能 SSH 登录」，`--agent-allow-ip` 管的是「被控机器从哪连出来」——两个独立配置，别混：

```bash
ws2ssh-server user add office --agent-allow-ip 203.0.113.0/24 ...   # 落到 default 机器上
ws2ssh-server user set office --agent-allow-ip 10.0.0.5             # 单机时照旧；多台报错
ws2ssh-server machine set office build --agent-allow-ip 10.0.0.5    # 多台时按台设置
ws2ssh-server machine set office build --clear-agent-allow          # 清空 = 不限来源
```

- 设了 `agent_allow_ips` 就**硬校验**：连接来源不在名单里直接 403，记 `AGENT-DENY`。机器出口 IP 稳定（公司专线、云上固定出口）时建议设上——token 被偷也用不了。
- 不设（默认）不限——机器会换网络（DHCP、笔记本换 WiFi、NAT 出口轮换），强制锁死首个 IP 会误伤。此时服务器记下每次连接的来源，**换了地方连会记 `AGENT-IPCHANGE` 审计事件并打告警日志**：这是 token 泄露的典型信号，配合 30 秒一轮的凭据复核（换 token 立即踢下线）足够定位。

## 审计日志（agent 侧 + 服务器侧）

两端各有自己的审计日志，格式都是 `<时间> <事件> k=v`，16MB 自动轮转成 `.1`（旧档被覆盖），文件权限 0600，值里的控制字符写入时清掉：

- **agent 侧**（默认 root: `/var/lib/ws2ssh/audit.log`，普通用户 `~/.ws2ssh/audit.log`，`--audit-log` 可改）：`AGENT-START`（每次进程启动：版本、连哪台服务器、shell、insecure/quiet 等参数）、`START`/`END`（每个远程会话，含来源 `登录账号@IP`）。机器主人能查「这台机器被谁连过、agent 被配成了什么样」。
- **服务器侧**（默认 root: `/var/lib/ws2ssh/server-audit.log`，`--audit-log` / `audit_log` 可改，写 `/dev/null` 可关）：`AUTH-OK` / `AUTH-FAIL`（含 user、来源 IP、method、失败原因 locked/password/disabled/totp）、`AGENT-CONNECT` / `AGENT-REPLACE` / `AGENT-DISCONNECT` / `AGENT-REVOKE`、`SESSION-START` / `SESSION-END` / `SESSION-DENY`；机器管理：`MGMT-DENY`（@ 命令被拒，reason=pubkey/locked/totp）、`MACHINE-ADD` / `MACHINE-REMOVE` / `MACHINE-TOKEN`（SSH 自助管理）、`MACHINE-ADD-ADMIN` / `MACHINE-TOKEN-ADMIN`（CLI `--admin` 跳过本人确认）、`MACHINE-TOKEN-REGEN-ADMIN`（CLI `--admin` 应急换 token）；token 换发：`TOKEN-REFRESH`（每台一条，含发起机器和结果 status）、`TOKEN-REFRESH-DENY`（拒绝原因 token/agent-allow/locked/password/totp）。agent 侧本地审计记 `TOKEN-ROTATED`（服务器下推的新 token 写进文件时）。出了安全事件，服务器上就能回溯「谁在什么时候试了什么密码、哪些机器上下线过、谁加删了机器、谁换过 token」。

云防火墙（安全组）和白名单是两层：包先过安全组，再进 ws2ssh。

## TOTP 二因素

给账号绑定 TOTP 验证器（Google Authenticator / 1Password / Aegis 等），SSH 登录就要「密码 + 6 位码」两道因素——密码被钓鱼或泄露也进不来。按账号 opt-in，没绑的账号行为不变：

```bash
ws2ssh-server user totp office        # 打印 otpauth:// URI 和手动录入秘钥，输一次码确认绑定
ws2ssh-server user totp office --remove
```

绑了之后：`ssh office@服务器 -p 2222` 先问密码，再问 6 位码（走 SSH keyboard-interactive，标准客户端都支持，不用装东西）；纯密码路径直接拒绝。同一个码 30 秒有效期内只能用一次（防重放），绑定时的那个码不能用来登录。验证码错误同样计入防爆破限速——纯密码通道不会碰这个计数，所以拿泄露的密码反复尝试也无法重置限速。

**空闲重验**：绑了 TOTP 的账号，SSH 会话挂机超过 `--idle-verify`（默认 30m，`0` 关闭）后再敲键，会先要求输入一个**新的**验证码，输对才继续（3 次机会）。挂机期间程序自己的输出不算使用。

**注意**：绑了 TOTP 的账号没法再用 `sshpass` 这类纯密码自动化——要么别给它绑，要么改用 expect 之类的交互应答。绑了公钥的账号用公钥登录时不走 TOTP，公钥是给自动化用的。

## 联系方式备注

`--contact`（建号或 `user set` 时）给账号挂负责人/联系方式，只做追溯、不参与认证，`user list` 里能看到：

```bash
ws2ssh-server user add office --contact ops@example.com ...
ws2ssh-server user set office --contact "值班：张三"
```

## wss / HTTPS

服务器加 `--tls` 就能让 agent 走 `wss://`，不用在前面加 Nginx/Caddy：

```bash
# 用正式证书（推荐，例如 Let's Encrypt 签发的）
./ws2ssh-server --tls --cert cert.pem --key key.pem --http :443 ...

# 没有证书：自动生成一张自签证书（存到 ./tls_cert.pem、./tls_key.pem，下次复用）
./ws2ssh-server --tls --http :443 ...
```

自签证书 agent 校验不过，要加 `--insecure` 跳过校验（等于不验证服务器身份，只适合内网或临时用）。正式对外请用受信证书，agent 不要开 `--insecure`。

**不要把 ws2ssh 放在 Nginx / 云负载均衡这类反向代理后面。** 服务器是按 TCP 连接的来源 IP 做判断的，经过代理后所有连接的来源都变成代理自己的地址：IP 白名单、`--agent-allow-ip`、每 IP 连接数、防爆破限速、`AGENT-IPCHANGE` 告警全部失效。需要 HTTPS 直接用 `--tls`，需要挡在前面的话用四层透传（保留来源 IP 的 TCP 转发）或云防火墙。

## 给 LLM / 自动化工具用

`ssh -p 2222 office@服务器 '命令'` 会在那台机器上执行命令，stdout、stderr 和退出码原样带回——Claude Code、Codex、Devin 这类自带终端的助手不用任何适配就能把它当普通 ssh 主机用。`ssh -T`（无 PTY 的非交互 shell）、管道喂 stdin 都支持；文件传输暂时用 `cat`/heredoc，`scp`/`sftp` 还没做。

**给自动化单独建账号**，绑公钥：

```bash
ws2ssh-server user add bot --ssh-key "$(cat ~/.ssh/id_ed25519.pub)" --allow-ip 跑LLM的机器IP
# 或给已有账号补：ws2ssh-server user set bot --ssh-key-file ~/.ssh/id_ed25519.pub
```

私钥放在跑 LLM 的机器上。公钥登录不要求 TOTP，也不进防爆破限速器（客户端会连着试好几把钥匙，计失败会误锁）；配 `--allow-ip` 把账号锁到那台机器。

**安全姿势**：被控机上的 agent 用低权限用户跑——LLM 能碰的就是那个用户能碰的。服务器审计 `SESSION-START` 记 `mode=exec cmd=…`（超过 512 字节截断）、`SESSION-END` 记 `code=` 退出码，agent 侧 `START` 同样记 `cmd`。桌面/终端通知同一来源 10 分钟内最多弹一对（审计每条都记，只是不刷屏）。单条命令上限 64KB。

**自己写 LLM 应用**：直接用任意 SSH 库调——Go 的 `golang.org/x/crypto/ssh`、Python 的 paramiko 都行，认证就是公钥。要 MCP 封装的话看下一节。

## MCP：给自己写的 LLM 应用 / 支持 MCP 的客户端

LLM 应用通过 MCP 拿到四个工具在被控机上干活：`list_machines`（看有哪些机器）、`run_command`（跑命令，返回分开的 stdout/stderr/exit_code）、`read_file`、`write_file`。接入方式有两种，工具行为完全一致，区别只在 MCP server 跑在哪：

| | stdio（`ws2ssh-mcp`） | 服务器内嵌 HTTP（`/mcp`） |
| --- | --- | --- |
| MCP server 跑在 | 跑 LLM 应用的那台机器 B | ws2ssh 服务器 S 上 |
| B 上要装的东西 | `ws2ssh-mcp` 二进制 + SSH 私钥 | 不用装，填 URL + Bearer token |
| 执行通道 | B 经 SSH 登录 S，再落到 agent | S 内部直连 agent（Hub），不走 SSH 回环 |
| 能碰哪些机器 | mcp.yaml 里写死 | 每个客户端 token 各自的 `--machine` 列表 |
| 人工批准兜底 | `ws2ssh-mcp approve`（在 B 上跑） | `ws2ssh-server mcp approve`（在 S 上跑） |
| 适用 | 自己本机用 | 给别人/多台客户端用 |

### 方式一：stdio（ws2ssh-mcp）

**安装与配置**：`make build` 产出 `bin/ws2ssh-mcp`（发布包里是 `ws2ssh-mcp-<os>-<arch>`）。配置写在 `~/.config/ws2ssh/mcp.yaml`（`--config` 可换路径，`examples/mcp.yaml` 有全量注释模板）：服务器 SSH 入口、无口令私钥、known_hosts 或钉死的 `host_key` 指纹、机器列表（键就是 ws2ssh 账号名）、策略和限额。

Claude Code 的 `mcpServers` 写法（`command` 要给绝对路径）：

```json
{
  "mcpServers": {
    "ws2ssh": {
      "command": "/usr/local/bin/ws2ssh-mcp",
      "args": ["--config", "/Users/you/.config/ws2ssh/mcp.yaml"]
    }
  }
}
```

**批准环节分三层**：被控机上 agent 的系统用户权限是第一层（真正的边界）；`policy` 名单是第二层——`deny` 直接拒、`allow` 只读命令直接放行、其余进第三层人工批准。批准有两条路：客户端支持确认弹窗（elicitation）就弹「允许执行」；不支持就把待批请求落到 `approvals_dir`，人去终端跑：

```bash
ws2ssh-mcp pending          # 看谁在等
ws2ssh-mcp approve <id>     # 批准；--all 全批
ws2ssh-mcp deny <id>        # 拒绝；--all 全拒
```

弹窗里勾「本次会话内相同命令不再询问」后，同一条命令同一个 MCP 会话里不再问。等到 `ask_timeout` 没人理就超时拒绝。

### 方式二：服务器内嵌 HTTP（/mcp）

`server.yaml` 里加 `mcp:` 小节打开（完整注释见 `examples/server.yaml`）：

```yaml
mcp:
  enabled: true
  # path: /mcp                 # 默认 /mcp，和 /agent 同一端口同一套 TLS
  # approvals_dir: ...         # 批准文件目录，默认在审计日志旁边的 approvals/
  # allow_plain_http: false    # 明文 HTTP + 非回环监听时拒绝启动；确认只在内网/隧道里用才开
  # machines:                  # 可选：给 MCP 客户端看的机器说明、write_file 放行目录
  #   bot: { description: "办公机", roots: ["~/work"] }
  # policy / limits 与 mcp.yaml 同格式
```

然后在服务器上给每个客户端签发 token：

```bash
ws2ssh-server mcp add laptop --machine bot            # bot 账号名下的全部机器
ws2ssh-server mcp add builder --machine alice+build   # 只给 alice+build 这一台
ws2ssh-server mcp add all-machines --machine '*'      # '*' = 全部机器（'alice+*' = alice 名下全部）
ws2ssh-server mcp list / set / remove / token         # 查看、改、删、换 token
ws2ssh-server mcp set laptop --disable                # 临时停用
```

客户端（Claude Code 等）只填 URL 和 token：

```json
{
  "mcpServers": {
    "ws2ssh": {
      "type": "http",
      "url": "https://服务器:8080/mcp",
      "headers": { "Authorization": "Bearer w2m-..." }
    }
  }
}
```

内嵌模式下建议客户端支持批准弹窗（elicitation）；不支持时待批请求落在服务器的 `approvals_dir`，管理员在服务器上跑 `ws2ssh-server mcp pending / approve / deny` 兜底。机器范围收窄到 `machines=["other"]` 的客户端只能看到自己那几台。审计上：认证失败记 `MCP-AUTH-FAIL`，批准流转记 `MCP-ASK`/`MCP-APPROVED`/`MCP-DENIED`/`MCP-ASK-TIMEOUT`/`MCP-POLICY-DENY`，命令会话记 `SESSION-START mode=mcp from=mcp:客户端名@IP`。

**提醒**：策略名单只是方便过滤，**不是安全边界**——shell 语法总能绕过朴素切段，别把它当沙箱；真正兜底的是 agent 跑在哪个系统用户下。内置 allow/deny 名单在 `internal/mcpsrv/policy.go` 的 `DefaultAllow`/`DefaultDeny`/`DefaultDenyPaths`，yaml 里写了对应项就整份替换。另外 roots 只按文本前缀匹配路径、不解析远端符号链接：`~/work/link -> /etc` 这种指向外面的链接会让 `write_file ~/work/link/x` 逃过 roots 检查——roots 目录里别放这类符号链接。

## 给 LLM 编码助手装 skill

仓库自带一份教编码助手「怎么安全地用 ws2ssh」的 skill（源文件在 `skills/ws2ssh/SKILL.md`）：什么时候用 MCP 工具、什么时候走 ssh、策略拒绝时不要去绕、哪些是禁区。`ws2ssh-mcp connect` 把它装进本机检测到的各家助手：

```bash
ws2ssh-mcp connect                    # 装到本机检测到的所有 harness
ws2ssh-mcp connect list               # 看支持哪些、检测到哪些、装没装
ws2ssh-mcp connect --path .claude/skills    # 只装到指定目录（比如项目级）
ws2ssh-mcp connect uninstall          # 卸载（用户改过的内容默认不删，--force 才删）
```

支持：Claude Code、Codex、Grok Build、Cursor、Gemini CLI、OpenCode、GitHub Copilot CLI、Devin CLI（检测各自的家目录；Codex 和 Grok 共用 `~/.agents/skills`，只写一份）。安装是写入 `<skills目录>/ws2ssh/SKILL.md` 加一份 `.ws2ssh-managed.json` 清单；你自己放的同名 skill 不会被误盖（要 `--force`）。所有写操作都能先 `--dry-run` 演练。不想用命令也行——把 `skills/ws2ssh/` 整个目录拷进任何一家认识的 skills 目录效果一样。

配套的还有 `connect print-mcp`：打印各家客户端接 ws2ssh MCP 要写的配置片段（不写文件）：

```bash
ws2ssh-mcp connect print-mcp --url https://服务器:8080/mcp --token w2m-...
ws2ssh-mcp connect print-mcp --stdio [--config mcp.yaml]
```

## 监控

看谁在线：`GET /status`，请求头带 `X-Admin-Token`（server.yaml 的 `admin_token`）或任一有效 `X-Agent-Token`：

```bash
curl -H "X-Agent-Token: w2s-xxxx" https://服务器:443/status
# {"ok":true,"http":":8080","ssh":":2222","users":[{"user":"office","machine":"office+default","online":true}]}
```

`/health` 不需要口令，只表示进程活着。`/status` 按凭据分级：管理口令看全量（每台机器一行，`machine` 是完整登录名），机器 token 只看得到自己那一台（普通用户没法枚举整个机群）。

## 资源与连接限制

默认值都开箱可用，需要时用旗标或 yaml 调（`0` = 不限）：

| 旗标 / yaml | 默认 | 作用 |
| --- | --- | --- |
| `--max-sessions` / `max_sessions` | 16 | 每台机器（每账号）并发 SSH 会话上限——防一个账号在被控机上 fork 出一堆 shell |
| `--max-conns` / `max_conns` | 4096 | SSH/HTTP 各自的并发连接总上限，超了直接拒（fail-closed，防连接洪水耗尽 fd） |
| `--max-conns-per-ip` / `max_conns_per_ip` | 64 | SSH 每来源 IP 的并发连接上限；只对 SSH 生效（HTTP 端口上多台 agent 常共用一个 NAT 出口 IP，卡了会误伤） |
| `--ssh-idle-timeout` / `ssh_idle_timeout` | 0（关） | SSH 空闲超时。能治未认证连接挂死，但也会断开空闲的交互会话——挂了 TOTP 空闲重验的会话要保留挂机，默认别开 |
| `--ssh-max-timeout` / `ssh_max_timeout` | 24h | SSH 连接绝对寿命 |

HTTP 口另有 10 秒请求头超时（防 Slowloris）和 2 分钟空闲超时；`/agent` 的长连接不受影响。WebSocket 两侧都有单条消息上限（256KB）、10 秒写超时和 30 秒 ping 心跳，对端死了或卡住都会被断开，不会永久挂着会话。

## 被控端感知（远程访问，本机可见）

ws2ssh 本质是远程控制：agent 装好后，持有账号密码的人随时能进这台机器。所以 agent **默认让机器的主人能感知到**，而不是悄悄运行：

- **会话通知**：远程会话开始（「alice@1.2.3.4 正在通过 wss://… 远程连入本机」）和全部结束时，各弹一次系统通知（macOS 通知中心 / Linux `notify-send`），同时用 `wall` 广播到所有登录着的终端——headless 服务器上桌面通知到不了，终端广播总能看到。多个并发会话不刷屏，只在头一个开始和最后一个结束时各说一次。
- **审计日志**：agent 每次启动记一条 `AGENT-START`（时间、版本、连哪台服务器、shell、insecure/quiet 等参数）；每个远程会话的开始/结束各记一条（会话 id、来源 `登录账号@IP`）。默认位置 root 是 `/var/lib/ws2ssh/audit.log`，普通用户是 `~/.ws2ssh/audit.log`，`--audit-log` 可改。机器主人随时能查「这台机器被谁连过、agent 是怎么配的」。
- 通知发不出去（没桌面、权限没批）不影响会话；审计日志才是保底。

**别用 root 跑 agent**：远程会话拿到的是 agent 进程那个用户的 shell——agent 以 root 跑，每个连进来的人直接是 root。agent 启动时发现自己是 root 会打一条警告，`AGENT-START` 审计里也记 `uid=`。建议建一个专用低权限用户，`examples/ws2ssh-agent.service` 是现成的 systemd 单元（`User=ws2ssh`、`NoNewPrivileges` 等都配好了）。

想安静是显式动作，不是默认：`--quiet`（或 agent.yaml 的 `quiet: true`）只关通知，**审计日志照写**。

```bash
ws2ssh-agent ... --quiet                    # 关通知，审计仍写
ws2ssh-agent ... --audit-log /var/log/w2s.log  # 换审计路径
```

## 注意

- **配置怎么给**：长久配置写 `server.yaml` / `agent.yaml`（`examples/` 里有全量注释模板，`--config` 加载，命令行旗标显式给过的项覆盖文件）；秘密（agent token）优先用 `--agent-token-file`（0600 文件）或环境变量 `WS2SSH_AGENT_TOKEN`，别把 token 写进配置文件。
- 对外请开 `--tls`；明文 `ws://` 只适合本机或内网试跑。
- **防爆破**：SSH 密码认证按「账号|来源 IP」限速——连续 5 次失败锁定 1 分钟，之后每多失败一次时长翻倍（封顶 1 小时）；锁定只影响这一个账号从这个 IP 的登录，攻击者刷失败锁不了别人。另外按账号汇总一道更宽松的门（15 分钟内 50 次失败锁 1 分钟起、同样翻倍）：换着 IP 打同一个账号也会被锁——代价是有人能故意刷失败让某个账号暂时登不上，但他本来也进不来。成功登录即清零；重启服务器清零。乱喷用户名的分布式爆破也撑不大失败表（65536 条上限，先清过期再淘汰最旧）。**不存在/停用账号的登录尝试也做一次同等耗时的 bcrypt 比较**——按响应时间枚举用户名不可行。
- **token 别走命令行**：`--agent-token w2s-...` 会出现在 `ps` 里。用 `--agent-token-file 路径`（文件权限 0600）或环境变量 `WS2SSH_AGENT_TOKEN`，配置文件 `agent_token` 也行。agent 给远程会话起 shell 时会把 `WS2SSH_AGENT_TOKEN` 从环境里去掉，SSH 进来的人 `env` 看不到它。
- agent 建议用权限较小的账号跑，不要用 root。
- 谁拿到某台机器的 token，就能把机器挂到那个 `账号+机器名` 下；token 泄露就用 `machine token 账号 机器名 --regen` 换掉——**对已经连着的旧 agent 立刻生效**（它再接会话会被拒，服务器最多 30 秒内把它踢下线），不用重启服务器。只影响那一台，同账号其他机器照跑。
- SSH 登录名 = `账号+机器名`；账号只有一台机器时写账号名也行（自动落到那台）。

## 发布与安装校验

发布产物是**三个独立的二进制**（制品最小化：装在被控机上的 agent 不含 SQLite 账号库、SSH 服务端这些服务器侧代码）：

- `ws2ssh-server-<os>-<arch>` — 服务器端 + 账号管理（`user` 子命令）
- `ws2ssh-agent-<os>-<arch>` — 被控机上的 agent
- `ws2ssh-mcp-<os>-<arch>` — MCP 入口，装在跑 LLM 应用的机器上（见「MCP」节）

`make release` 交叉编译全平台并生成 `SHA256SUMS`；设 `MINISIGN_KEY_FILE` 环境变量会顺带 minisign 签名。**安装时先校验再执行**：

```bash
shasum -a 256 -c SHA256SUMS --ignore-missing   # 只校验你下载的那两个
minisign -Vm ws2ssh-agent-darwin-arm64          # 有签名文件时
```

只从官方 release 取二进制，不要 `curl | sh` 来路不明的 agent。另：agent 上报的版本号（`--min-agent-version` 门槛、审计里的 `version=`）是**自报的**，只用于机群版本淘汰和运维可见性，不是安全依据——服务器对 agent 的所有输入始终按不可信处理。
