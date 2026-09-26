# TowStrap 用户手册

[首页](../../README.md) · [技术手册](technical-manual.md) · [English](../../docs/en/user-guide.md)

TowStrap 让 NAT/防火墙后面的机器可以被安全访问：被控机上的 agent 主动 WebSocket 连到服务器，人用 SSH、LLM 用 MCP，都经服务器落到那台机器。本手册按使用顺序讲：安装 → 服务器 → 被控机 → 账号 → 登录 → 命令 → MCP → 监控排错。

> ⚠️ 开始之前请先看 [README 的安全须知](../../README.md)：agent 请用低权限专用用户跑，token 是凭据，生产开 TLS，别放反向代理后面。

## 目录

1. [安装](#1-安装)
2. [服务器](#2-服务器)
3. [被控机 agent](#3-被控机-agent)
4. [账号与机器](#4-账号与机器)
5. [登录与认证](#5-登录与认证)
6. [执行命令与自动化](#6-执行命令与自动化)
7. [账号本人自助管理（@machine）](#7-账号本人自助管理machine)
8. [换 token](#8-换-token)
9. [MCP：给 LLM 用](#9-mcp给-llm-用)
10. [给 LLM 助手装 skill](#10-给-llm-助手装-skill)
11. [监控](#11-监控)
12. [审计日志](#12-审计日志)
13. [排错](#13-排错)
14. [升级说明](#14-升级说明)

---

## 1. 安装

三个二进制各管一件事：

| 二进制 | 装在哪 | 干什么 |
| --- | --- | --- |
| `towstrap-server` | 有公网 IP 的服务器 | SSH/HTTP 入口 + 账号/机器/MCP 凭据管理 |
| `towstrap` | 要被访问的每台机器 | 主动连服务器，执行远程会话 |
| `towstrap-mcp` | 跑 LLM 应用的机器（可选） | stdio MCP 入口 + skill 安装器 |

### go install（推荐）

```bash
go install github.com/towstrap/towstrap/cmd/towstrap-server@latest
go install github.com/towstrap/towstrap/cmd/towstrap@latest
go install github.com/towstrap/towstrap/cmd/towstrap-mcp@latest
```

### 从源码构建

```bash
git clone https://github.com/towstrap/towstrap && cd towstrap
make build    # 产出 bin/towstrap-server、towstrap、towstrap-mcp
```

### 预编译二进制

见 [Releases](https://github.com/towstrap/towstrap/releases)，文件名形如 `towstrap-linux-arm64`（被控端改名前的旧版本叫 `towstrap-agent-linux-arm64`）。`make release` 同时产出 `SHA256SUMS` 和（有签名密钥时的）minisign 签名，**安装前请先校验**：

```bash
shasum -a 256 -c SHA256SUMS --ignore-missing
minisign -Vm towstrap-linux-amd64   # 有签名文件时
```

### 一键安装脚本（服务端）

服务端也有一行装法——下二进制、校验 `SHA256SUMS`、写最小 `server.yaml`（0600）、Linux+root 自动装并启动 systemd 服务（`--no-systemd` 只装文件，macOS 同理）：

```bash
curl -fsSL https://raw.githubusercontent.com/towstrap/towstrap/main/scripts/install-server.sh | sudo sh
# --version vX.Y.Z 钉版本，--confdir/--prefix 换位置，--check 干跑看解析结果
# （官方域名 /install-server.sh 挂的是同一份字节——但装第一台服务器时
# 还没有自己的服务器，GitHub raw 才是正道）
```

已有 `server.yaml` 不会被覆盖（升级重装安全）；单元文件样例见 `examples/towstrap-server.service`。

装完跑**初始化向导**把三件事一次配掉（对外地址、自助注册、第一个账号），之后改配置也能反复跑：

```bash
sudo towstrap-server init
# 对外地址 → 写 server.yaml 的 public_url（下发安装命令/落地页用它）
# 自助注册 → register: true（+可选邀请码）；不开则引导用 user add 建号
# 第一个账号 → 内联建号，打印 SSH 登录名和这台机器的 agent token
# 写完若 towstrap-server 的 systemd 服务在跑会自动重启生效
```

向导用 Node 级改写回写 yaml：注释、无关字段原样保留，同值重跑不重复写。脚本模式下全部走旗标（`--yes` + `--public-url`/`--register`/`--register-invite`/`--account`/`--password-stdin`/`--no-restart`），`--register-invite ""` 显式清掉邀请码。

### 一键安装脚本（agent 推荐）

服务器直接吐安装脚本——从哪台服务器下载，就默认连回哪台，不用手填地址：

```bash
# Linux / macOS
curl -fsSL https://towstrap.vast-plan.com/install.sh | sh -s -- --token tsa-…

# Windows（PowerShell）
powershell -Command "& { $(irm https://towstrap.vast-plan.com/install.ps1) } -Token tsa-…"
```

脚本做的事：按系统架构从 GitHub Releases 下载 `towstrap`、校验 `SHA256SUMS`、装到 `/usr/local/bin`（不可写则 `~/.local/bin`）、写 0600 的 token 文件和 `agent.yaml`（root 进 `/etc/towstrap`，普通用户进 `~/.config/towstrap`）。**从服务器下发的脚本默认装和这台服务器同版本的 agent**（`--version vX.Y.Z` 可覆盖）、并把服务器 `agent_defaults:` 里的预设工作配置（`shell`、`mirror_idle`、`mcp_policy` 等）一并写进 `agent.yaml`；GitHub 直拉的脚本默认 latest、不带预设。装完结尾会打印这台机器的 SSH 登录地址（主机取自 `--server`，端口是服务器配置的 SSH 口）。加 `--systemd` 会顺带装服务：root 跑建 `towstrap` 专用用户 + 系统单元并启动，普通用户写 `~/.config/systemd/user` 单元。

也可以从 GitHub 直接拉脚本（默认指向官方服务器；自建才加 `--server wss://…`）：

```bash
curl -fsSL https://raw.githubusercontent.com/towstrap/towstrap/main/scripts/install.sh | sh -s -- --token tsa-…
```

`machine add` / `user add` / `@machine add` 打印的接入指引里就带这条一键命令。自签证书时 curl 加 `-k`。

支持 Linux、macOS 和 Windows（amd64/arm64）。Windows 上 agent 默认用 `cmd.exe` 跑命令（配 `shell` 可换 `powershell`/`pwsh`/git-bash 的 `bash`，按 shell 名自动选 `/c` 或 `-Command`）；交互式会话走 **ConPTY**（Windows 10 1809 / Server 2019 及以上），`ssh -t`、vim、top 都能用。服务器端在 Windows 上能跑但属小众用法，默认路径（`/etc/towstrap` 等）是 Unix 风格，请用命令行旗标或配置文件显式指定。

---

## 2. 服务器

### 启动

```bash
# 最小启动：SSH 监听 :7822，HTTP 监听 :7880，账号库 /etc/towstrap/users.db
towstrap-server

# 用配置文件（推荐；examples/server.yaml 是全量注释模板）
towstrap-server --config server.yaml
```

账号库默认在 `/etc/towstrap/users.db`——需要 root。普通用户跑的话给每条 `towstrap-server` 命令都加 `--users-db`：

```bash
towstrap-server --users-db ~/.towstrap/users.db user add alice
towstrap-server --users-db ~/.towstrap/users.db &
```

启动时会打一行**生效配置**（`http=... ssh=... tls=... max_sessions=...` 等，秘密只显示设没设），排查「yaml 生效没」看这行。

### server.yaml 全字段

优先级：**命令行显式给的旗标 > yaml > 内置默认**（旗标和 yaml 同名，把 `-` 换成 `_`）。

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `http` | `:7880` | HTTP 口：`/health`、`/agent`、`/status`、`/mcp`、`/token/refresh`、`/skill` |
| `ssh` | `:7822` | SSH 入口 |
| `host_key` | 与 users_db 同目录的 `ssh_host_key` | SSH 主机密钥；不存在才生成，读不了/解析失败直接报错退出（不会静默换钥） |
| `users_db` | `/etc/towstrap/users.db` | 账号 SQLite 库 |
| `users_key` | `users_db` 去掉 `.db` + `.key` | token 加密密钥文件（0600，自动生成；**务必备份**，丢了所有 token 解不开） |
| `admin_token` | 空 | 查 `/status` 全量的管理口令；不设就只能用 agent token 查自己那台 |
| `public_url` | 空 | 对外 wss:// 地址，写进 `user add`/`machine add` 生成的安装命令 |
| `tls` | `false` | HTTP 口走 HTTPS/WSS |
| `cert` / `key` | 空 | 证书路径；`tls: true` 且没给时自动生成自签证书（`./tls_cert.pem`/`./tls_key.pem`） |
| `allow_ips` | 空（不限） | 全局来源白名单：谁能连 SSH（也作用于 `/mcp`） |
| `idle_verify` | `30m` | 绑了 TOTP 的账号，SSH 会话挂机超过这么久后下一次敲键要重验验证码；`0` 关闭 |
| `min_agent_version` | 空（不限） | agent 自报版本低于它就拒绝接入（机群版本淘汰用；版本可伪造，不是安全控制） |
| `audit_log` | root: `/var/lib/towstrap/server-audit.log`；普通用户: `~/.towstrap/server-audit.log` | 服务器审计日志；写 `/dev/null` 关闭 |
| `max_sessions` | `16` | 每台机器并发 SSH 会话上限（`0` 不限） |
| `max_conns` | `4096` | SSH/HTTP 各自的并发连接总上限（`0` 不限） |
| `max_conns_per_ip` | `64` | SSH 每来源 IP 并发上限（只管 SSH；`0` 不限） |
| `ssh_idle_timeout` | `0`（关） | SSH 空闲超时；能治未认证连接挂死，但会断开空闲的交互会话，慎开 |
| `ssh_max_timeout` | `24h` | SSH 连接绝对寿命（`0` 不限） |
| `agent_defaults` | 空 | 管理员预设的 agent 工作配置：服务器下发的 `install.sh`/`install.ps1` 会把这些写进装好的 `agent.yaml`（只影响新装）。字段名同 agent.yaml；`server`/`agent_token*` 身份字段写了会被忽略（地址由脚本生成、token 一机一份） |
| `register` | `false` | 开 `POST /register` 自助建号：被控机 `towstrap register` 交互建账号+拿 token。同指纹一账号、每 IP 每小时限 8 个、全程审计（只走 yaml，没旗标）。已有账号加机器的 `POST /register/machine` 不受此开关管 |
| `register_invite` | 空 | 注册邀请码；设了注册时要带 `--invite`。空 = 不验 |
| `mcp` | 关 | 内嵌 MCP 小节，见 [9.2](#92-方式二服务器内嵌-httpmcp) |

对应的命令行旗标：`--config --http --ssh --host-key --users-db --users-key --admin-token --public-url --tls --cert --key --allow-ip --idle-verify --min-agent-version --audit-log --max-sessions --max-conns --max-conns-per-ip --ssh-idle-timeout --ssh-max-timeout`（`--allow-ip` 可重复）。

### TLS

```bash
# 用正式证书（推荐，比如 Let's Encrypt）
towstrap-server --tls --cert cert.pem --key key.pem --http :443

# 没有证书：自动生成自签证书到 ./tls_cert.pem、./tls_key.pem（下次复用）
towstrap-server --tls --http :443
```

自签证书下 agent 要加 `--insecure` 才能连（等于不验证服务器身份，只适合内网/临时）。正式对外请用受信证书。

TLS 开不开只影响 HTTP 口（agent 的 WebSocket、`/mcp`、`/status` 等）；SSH 口自带加密，与此无关。

### 反向代理部署

推荐形态：`http` 绑回环 `127.0.0.1:7880`，nginx 443 终结 TLS 后按路径反代（完整示例 `examples/nginx.conf`；`/agent` 是 WebSocket，Upgrade/Connection 头与读写超时必须按示例配置）。SSH `:7822` 是裸 TCP，不走 nginx，直接放行端口。

挂反代后服务端看到的来源全部是回环地址：`agent_allow_ips`、登录限速等按 IP 的控制在 HTTP 面上失效（SSH 直连不受影响），`X-Forwarded-For` 可被客户端伪造、不用于判定。

**反代跑在 Docker 容器里（Nginx Proxy Manager 等面板）**：容器内的 `127.0.0.1` 是容器自身，转发到它必然 502。处理方式：

1. `server.yaml` 的 `http` 改绑 docker0 网桥地址（默认 `172.17.0.1`，`ip addr show docker0` 确认）或本机内网 IP；
2. 非回环监听需显式确认明文：`allow_plain_http: true`（明文只存在于宿主机内部通道，对外仍是反代的 HTTPS）；
3. 反代目标填该地址（不是 `127.0.0.1`），并确认面板开了 WebSocket 转发；
4. 防火墙对公网收掉该端口，只留容器与本机可达。

**配置写法提醒**：`http`/`ssh`/`allow_plain_http` 等键必须缩进在 `server:` 小节内；顶层扁平写法与 `server:` 小节混用时，顶层键不生效。排查实际生效值看启动日志的「生效配置」行，或 `timeout 2 towstrap-server --config <路径>`。

### 审计日志与资源限制

审计日志位置见上表；文件超 16MB 自动轮转成 `.1`（旧档被覆盖），权限 0600。连接与会话限额：`max_sessions`、`max_conns`、`max_conns_per_ip`、`ssh_idle_timeout`、`ssh_max_timeout`，HTTP 口另有固定的 10 秒请求头超时（防 Slowloris）和 2 分钟空闲超时，`/agent` 长连接不受影响。

---

## 3. 被控机 agent

### 跑起来

```bash
# token 从文件读（推荐——只有这种来源才支持远程换 token）
echo 'tsa-…' > ~/.towstrap-token && chmod 600 ~/.towstrap-token
towstrap --server wss://towstrap.vast-plan.com --agent-token-file ~/.towstrap-token
```

`--server` 接受 `ws://`、`wss://`（也认 `http://`/`https://`，自动换算）。断线自动重连：2 秒起步、指数退避封顶 30 秒、带随机抖动；连接稳定超过 1 分钟后退避重置。

### 自助接入（`towstrap register`）

agent 装完不需要管理员给 token——它是首次接入入口，交互模式先问你有没有账号：

```bash
towstrap register                    # 先问"已有账号？"，按回答走分支
towstrap register --login            # 跳过提问：登录已有账号，这台机器挂到名下
towstrap register --account alice --machine work --server wss://S:7880
echo '密码' | towstrap register --account alice --password-stdin   # 脚本化
```

两条分支：

- **没有账号** → 自助建号（服务器需开 `register: true`）：设密码（两次确认）、建账号+机器、拿 token
- **已有账号** → 登录加机（不受 `register:` 开关管，和 SSH 的 `@machine add` 等价）：账号+密码验证后把机器挂到名下；同名机器视为重装换新 token（旧的作废）

做的事：上报机器指纹（原始 ID 在本机内做 SHA256 哈希后才上传，硬件 ID 不出本机）→ 拿回 token 写进配置目录的 `agent-token`（0600）并生成最小 `agent.yaml` → 打印 SSH 登录命令 → **交互模式还会问要不要顺手绑 TOTP**（终端出二维码、验证器扫完输码确认才生效；`--skip-totp` 或脚本模式跳过，事后再绑用 `towstrap totp`），接下来直接 `towstrap` 跑即可。

约束：**一台机器的指纹只许绑一个账号**——指纹已被别的账号占用会提示既有账号名（那账号的密码走 `--login`，或管理员 `user del` 释放指纹）。服务器设了 `register_invite` 时建号要带 `--invite 码`；每来源 IP 每小时限 8 次；服务器没开 `register:` 时建号走 `user add` + `--token` 的传统流程（已有账号加机器不受影响）。

指纹的边界要说清：原始硬件 ID 只在机器内参与 SHA256（带来源标签），服务器存的是哈希——**脱敏是到位的**；优先取主板固件级 ID（macOS `IOPlatformUUID`+序列号、Linux `product_uuid`、Windows SMBIOS UUID——重装系统不变），取不到才回落 OS 级 `machine-id`/`MachineGuid`。但"一机一号"仍是**防误刷护栏、不是反欺诈**——有 root 或改了客户端的人照样能发自报指纹；VM 克隆则方向相反（撞指纹被误拒）。

### token 的四种给法（按推荐排序）

| 来源 | 写法 | 能否远程换 token |
| --- | --- | --- |
| 文件（推荐） | `--agent-token-file 路径` 或 yaml `agent_token_file`（文件 0600） | ✅ `token refresh` 会原子重写它 |
| 配置文件 | yaml `agent_token` | ❌ |
| 环境变量 | `TOWSTRAP_AGENT_TOKEN` | ❌ |
| 命令行 | `--agent-token tsa-...`（会出现在 `ps` 里，别用） | ❌ |

agent 给远程会话起 shell 时会把 `TOWSTRAP_AGENT_TOKEN` 从子进程环境里剥掉，SSH 进来的人 `env` 看不到它。

### agent.yaml 全字段

```yaml
agent:
  server: wss://towstrap.vast-plan.com  # 必填；没开 TLS 写 ws://
  agent_token_file: /path/to/token  # 推荐：0600 文件，支持远程换发
  # agent_token: tsa-...            # 直写 token（不能远程换发）
  # shell: /bin/bash                # 不写用 $SHELL，都没有用 /bin/bash
  # insecure: true                  # 服务器自签证书时才开
  # quiet: true                     # 关桌面通知/wall（审计仍写）
  # audit_log: /path/audit.log      # 默认 /var/lib/towstrap/audit.log（root）或 ~/.towstrap/audit.log
```

旗标：`--config --server --agent-token --agent-token-file --shell --insecure --audit-log --quiet`。

### systemd

`examples/towstrap.service` 是现成单元，注释里有完整步骤。要点：

```bash
sudo useradd -r -m -s /bin/bash towstrap
sudo mkdir -p /etc/towstrap && sudo cp agent.yaml /etc/towstrap/
sudo chown towstrap:towstrap /etc/towstrap/agent.yaml /path/to/token_file
sudo chmod 600 /path/to/token_file     # token 文件要能让 towstrap 用户读写（refresh 会重写它）
sudo cp towstrap.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now towstrap
```

注意单元里是 `ProtectSystem=true` 而不是 `full`：full 会把 `/etc` 挂成只读，token 换发时 agent 重写不了 token 文件。

### 被控端感知

agent 默认让机器主人能感知到远程访问：

- **通知**：活跃会话数 0→1 和 1→0 时各弹一次桌面通知（macOS 通知中心 / Linux `notify-send`）+ `wall` 广播到所有登录终端；同一来源 10 分钟内最多弹一次（审计照记，只是不刷屏）
- **审计**：每次启动记 `AGENT-START`（版本、连哪台服务器、shell、insecure/quiet、uid），每个会话记 `START`/`END`（来源 `登录账号@IP`、命令、结束）
- `--quiet` / `quiet: true` 只关通知，审计照写；通知发不出去不影响会话
- 以 root 跑会打警告：`agent 正以 root 运行：远程登录者将拿到 root shell`

### 镜像终端（可接力终端）

agent 内置一个类似 tmux 的「带名常驻终端」功能，不用装 tmux：镜像进程的伪终端由 agent 持有，接入方断开只是「脱离」，进程继续跑——在机器前开着 `pi`、`vim`、`top`，换手机或另一台电脑上来还能接回同一个画面。

```bash
# 在被控机上（本机终端、或直接 sshd 上去、或 towstrap SSH 进去都行）
mirror                            # 列出本机所有镜像终端
mirror work                          # 接入 work；不存在就以登录 shell 新建
mirror work vim a.go                 # 不存在就以该命令新建
mirror kill work                     # 终结 work（杀掉里面的进程）
```

`mirror` 是 `towstrap` 的软链别名（busybox 式，install.sh 装好就有）；没有软链的机器上写全称 `towstrap mirror …`，完全一样。

新建出的镜像，shell 落在你敲命令时所在的目录（`mirror ls` 的「目录」列能看到）；接入已存在的镜像不改变它里面的目录——接力的是原工作现场，不是你这次接入的目录。

- 接入后按 **`Ctrl-\`** 脱离——只断开你的接入，镜像里的进程继续跑；同名再 `mirror` 就接回去
- 想让工作「默认就在镜像里」（离开机器后随时远程接力）：`mirror setup --write` 往 shell 启动文件（`~/.zshrc`/`~/.bashrc`）写一段钩子——**默认只提醒不接入**：新终端里有活镜像时提示一行；把段里 `TOWSTRAP_MIRROR_AUTO=` 后面填上镜像名（或 `mirror setup work --write` 预填）才会自动接入它。`mirror setup` 不加 `--write` 只打印片段自己贴；临时跳过 `export TOWSTRAP_NO_MIRROR=1`，彻底去掉删掉 `# >>> towstrap mirror >>>` 那段即可
- `mirror ls -q` 是存在性探针：有活镜像退出 0，没有退出 1，不打印——rc 钩子和脚本用它判断「有没有可接的」
- 多个接入方可以同时看同一个镜像（画面同步），谁敲键都进同一个终端；尺寸以最后接入/调整的一方为准
- 套在 SSH 里接力：`ssh -t 机器 mirror work`（`ssh -t` 经 towstrap 服务器也行）——接力是给人用的功能：本机终端、普通 sshd、towstrap SSH 三种门进来，最后都是跑本机 `mirror` 命令
- MCP 不参与：`terminal_open` 开的是会话级临时终端，接入不了镜像终端——AI 没有「接管人正在用的终端」的入口
- 实现位置：`~/.towstrap/mirror.sock`（root 装法 `/var/lib/towstrap/mirror.sock`），0600，只有 agent 的系统用户能连——和「能在本机给这个用户开 shell」等价
- 闲置终结：镜像超过 **72 小时**没有任何输入/输出会被自动杀掉（接着但没动静也算；审计写 `MIRROR-KILL via=idle`）。阈值用 `mirror_idle` 配置或 `--mirror-idle` 旗标改，写 `0`/`off` 关掉
- 边界：镜像只活在 agent 进程里——agent 重启镜像就没了（tmux 也一样）；Windows 上暂没有 `mirror` 命令，Windows 机器上没有镜像终端

---

## 4. 账号与机器

### 概念

- 登录名 = `账号+机器名`（如 `alice+office`）。账号只有一台机器时写账号名也行，自动落到它
- 建号自动带一台名为 `default` 的机器；一个账号下的机器数不限，每台独立 token
- 机器名和账号名只能用字母、数字、点、下划线、短横线（1–64 字符），`+` 是分隔符不能进名字
- 同名机器的 agent 再连会顶掉旧连接；同账号不同机器名互不干扰
- 改名（`user set --name`）后 agent 不用动——它靠 token 认，不靠名字

### user 子命令

都在服务器上跑，操作账号库；通用选项 `--config`（读 yaml 里的 users_db/users_key/public_url）、`--users-db`、`--users-key`、`--server-url`。

| 命令 | 作用 |
| --- | --- |
| `user add 名字 [--password 密码] [--contact 联系方式] [--allow-ip 地址]... [--agent-allow-ip 地址]... [--ssh-key 公钥]... [--ssh-key-file 文件]` | 建号，自动带 `default` 机器并打印它的 token 和安装命令 |
| `user list` | 列账号：状态、TOTP、公钥数、联系方式、白名单、机器 |
| `user set 名字 [--password] [--name 新名] [--contact] [--clear-contact] [--allow-ip]... [--clear-allow] [--agent-allow-ip]... [--clear-agent-allow] [--ssh-key]... [--ssh-key-file] [--remove-ssh-key 公钥或SHA256指纹]... [--clear-ssh-keys] [--disable\|--enable]` | 改密码/改名/备注/白名单/公钥/停启用 |
| `user remove 名字` | 删号，名下机器的 token 全部作废 |
| `user token 名字 [--regen] [--admin]` | 看 token（仅当账号只有一台机器）。要本人确认；`--regen` 应急换法必须 `--admin` |
| `user totp 名字 [--remove]` | 绑定/解绑 TOTP |

要点：

- 不给 `--password` 会生成 **16 位随机密码，只显示一次**（库里只有 bcrypt 哈希）；密码至少 10 位
- `user set --agent-allow-ip` 只作用于账号唯一那台机器，多台时用 `machine set`
- `--disable` 停用后 SSH 和 agent 都进不来，已连接的 agent 最多 30 秒内被踢下线
- 白名单条目：IP、网段、`IP:端口`、主机名、`*.domain`、`*`；不写 = 不限

### machine 子命令

| 命令 | 作用 |
| --- | --- |
| `machine add 账号 机器名 [--agent-allow-ip 地址]... [--admin]` | 加机器并打印它的 token（只显示一次）。要本人确认 |
| `machine list [账号]` | 列机器（不给账号列全部）：登录名、agent 白名单、token、创建时间 |
| `machine set 账号 机器名 [--agent-allow-ip]... [--clear-agent-allow]` | 改这台机器的 agent 来源白名单 |
| `machine remove 账号 机器名` | 删机器，token 作废，在线 agent 立刻断开 |
| `machine token 账号 机器名 [--regen] [--admin]` | 看这台的 token。要本人确认；`--regen` 应急必须 `--admin` |

### 账号本人确认 与 --admin

`machine add`、`machine token`、`user token` 会签发或暴露 token，默认**先问这个账号的 SSH 密码**（绑了 TOTP 再问验证码）——「能碰服务器命令行」不等于「能给任何账号发 token」。加 `--admin` 跳过，但会打警告并往服务器审计日志写 `MACHINE-ADD-ADMIN` / `MACHINE-TOKEN-ADMIN` / `MACHINE-TOKEN-REGEN-ADMIN`。

---

## 5. 登录与认证

### 密码登录

```bash
ssh -p 7822 alice@服务器          # 单机账号
ssh -p 7822 alice+office@服务器   # 多机账号必须指名
```

多机账号不带后缀登录会报错并列出机器名单（含在线状态）。

### TOTP 二因素

```bash
towstrap-server user totp alice          # 终端里显示二维码（扫不了时用 otpauth:// URI 或手动录入秘钥），输一次码确认绑定
towstrap-server user totp alice --remove # 解绑，退回纯密码
```

绑了之后：

- `ssh alice@...` 先问密码再问 6 位码（走 keyboard-interactive，标准客户端都支持）；纯密码通道对绑了 TOTP 的账号**直接拒绝**
- 同一个码在其时间片内只能用一次（防重放）；验证码错误计入防爆破限速
- **空闲重验**：PTY 会话挂机超过 `idle_verify`（默认 30 分钟，`0` 关闭）后下一次敲键要先输一个新验证码（3 次机会）；程序自己的输出不算使用。只罩密码类登录的交互会话——公钥登录和 exec 不受影响
- 绑了 TOTP 就没法用 `sshpass` 这类纯密码自动化；自动化请改用公钥

### 公钥登录（给自动化）

```bash
towstrap-server user add bot --ssh-key "$(cat ~/.ssh/id_ed25519.pub)" --allow-ip 跑自动化的机器IP
towstrap-server user set bot --ssh-key-file ~/.ssh/towstrap_bot.pub   # 补登
```

公钥登录不要求 TOTP、不进限速器（客户端会连着试几把钥匙，计失败会误锁）。自动化账号建议同时配 `--allow-ip` 锁来源。公钥登录**不能**跑 `@machine` 管理命令。

### 限速与锁定

密码类认证按两个维度限速（具体数字见[技术手册](technical-manual.md)）：

- `账号|来源IP`：15 分钟窗口内连续 5 次失败锁 1 分钟，之后每多失败一次锁定时长翻倍，封顶 1 小时——只影响这个账号从这个 IP
- `账号`（全部来源合计）：15 分钟内 50 次失败同样锁 1 分钟起翻倍——换着 IP 打同一账号也会被锁
- 登录成功即清零；服务器重启清零；锁定中再试会计入失败

### 白名单（两类）

| 层 | 控制什么 | 在哪设 |
| --- | --- | --- |
| 全局 `allow_ips` | 谁能连 SSH 口（和 `/mcp`） | server.yaml / `--allow-ip` |
| 账号 `allow_ips` | 谁能 ssh 登这个账号 | `user add/set --allow-ip` |
| 账号 `agent_allow_ips` | 这台机器的 agent 能从哪连出来 | `user add/set --agent-allow-ip`（单机）、`machine add/set --agent-allow-ip`（多机） |

- 账号白名单是**硬校验**：不在名单里直接拒（SSH 记 `AUTH-FAIL reason=allow-ip`，agent 记 `AGENT-DENY`）
- agent 白名单不设时不限来源，但**换了来源 IP 会记 `AGENT-IPCHANGE` 审计并打告警**——token 被偷换个环境用第一时间可见；机器出口 IP 稳定时建议设上
- 条目写法同全局：IP、网段、`IP:端口`、主机名、`*.domain`、`*`

云防火墙（安全组）和这些白名单是两层：包先过安全组再进 towstrap。

---

## 6. 执行命令与自动化

```bash
ssh -p 7822 alice@towstrap.vast-plan.com 'uname -a'                 # 执行命令，stdout/stderr 分开，退出码原样带回
ssh -p 7822 -T alice@towstrap.vast-plan.com                         # 无 PTY 的非交互 shell
echo hello | ssh -p 7822 alice@towstrap.vast-plan.com 'cat'         # stdin 管道，EOF 会传给子进程
```

- 退出码约定：子进程退出码原样返回；被信号杀按 shell 惯例 128+信号号；命令没起来/连接中断返回非 0（255），agent 侧起命令失败的原因会打到 stderr（`agent: ...` 前缀）
- 单条命令上限 64KB；每条命令都是新起的 shell，`cd`、环境变量不会带到下一条
- **没有 scp/sftp**：传文件用 `cat`/heredoc（`ssh alice@towstrap.vast-plan.com 'cat > f' < f`）或 MCP 的 `read_file`/`write_file`
- 自带终端的 AI 助手（Claude Code、Codex 等）不用任何适配就能把它当普通 ssh 主机用；自己写程序调的话用任意 SSH 库 + 公钥认证即可
- 每个远程会话拿到的都是 **agent 进程那个系统用户**的 shell

---

## 7. 账号本人自助管理（@machine / @totp）

`@` 开头的命令由服务器自己执行，不发给 agent。账号本人 SSH 登录后直接管名下机器和自己的二因素：

```bash
ssh alice@towstrap.vast-plan.com -p 7822 '@machine list'                 # 列机器：ID、在线/离线、agent 白名单（不显示 token）
ssh alice@towstrap.vast-plan.com -p 7822 '@machine add build'            # 加机器，直接打印新 token 和安装命令
ssh alice@towstrap.vast-plan.com -p 7822 '@machine add build --agent-allow-ip 10.0.0.5'
ssh alice@towstrap.vast-plan.com -p 7822 '@machine remove build'         # 删机器，在线 agent 立刻断开
ssh alice@towstrap.vast-plan.com -p 7822 '@machine token build'          # 看这台的 token
ssh alice@towstrap.vast-plan.com -p 7822 '@machine help'                 # 用法说明
ssh -t alice@towstrap.vast-plan.com -p 7822 '@totp'                      # 自助绑/换绑 TOTP（出二维码输码确认）
ssh alice@towstrap.vast-plan.com -p 7822 '@totp remove'                  # 解绑 TOTP
```

TOTP 也可以直接在被管的机器上管——SSH 进机器后在 shell 里敲 `towstrap totp`（绑/换绑）或 `towstrap totp remove`（解绑）。效果和 `@totp` 完全一样，鉴权是本机 agent token + 账号密码（已绑的换绑/解绑还要当前动态码），对已经登进机器的人来说少记一种写法；`@totp` 留给手边没这台机器的场合（比如机器不在身边、从别的设备上收）。

限制：

- **只能密码类登录**跑：公钥登录会被拒（`MGMT-DENY reason=pubkey`）——公钥是给自动化的，不能管机器
- **绑了 TOTP 的账号要再输一个新验证码**（登录时用过的那个不能重放）；连错 3 次断开，每次错记 `MGMT-DENY reason=totp` 并计入登录限速
- 登录名带 `+机器名` 也行，按账号部分处理
- 换 token 不在这里——在 agent 机器上跑 `towstrap token refresh`（见下节）

---

## 8. 换 token

### 正常换法：在被控机上发起

```bash
# 在 alice 的某台 agent 机器上执行：
towstrap token refresh                  # 只换本机
towstrap token refresh --machine build  # 换同账号的 build（它得在线）
towstrap token refresh --all            # 换账号下全部机器
```

会问**账号密码**（绑了 TOTP 再问验证码）——鉴权是双重的：本机 agent token 证明「你在一台已登记机器上」，密码+TOTP 证明「你是账号主人」。

流程是**下推 + 确认**：服务器把新 token 经目标机器现有 WebSocket 发过去，agent 原子写进自己的 token 文件（同目录临时文件 → rename，0600）后回执；**收到回执才把库里的旧 token 作废**。连接不断、agent 不重启。

前提与注意：

- 目标机器的 token 必须是**从文件读的**（`--agent-token-file` / `agent_token_file`），否则报 `no-file`
- 目标机器要**在线**，否则报 `offline`
- 服务器是明文 `ws://` 且不在本机回环时，要确认是内网再加 `--allow-plain`（密码不能裸传）
- agent 每次重连会重读 token 文件，手动改过文件也生效

### 每台机器的结果状态

| status | 含义 |
| --- | --- |
| `ok` | 新 token 已写进该机器的 token 文件 |
| `offline` | agent 不在线，没换 |
| `no-file` | 该机器 token 不是从文件读的，没法远程换 |
| `timeout` | agent 没在时限内确认（10 秒），库里没换 |
| `not-found` | 机器不存在 |
| `error` | 其他错误；特别注意「agent 已写入新 token 但服务器更新数据库失败」这种不一致，需人工处理 |

进程退出码：全 ok 为 0，部分失败为 1，参数/鉴权错误为 2。

### 应急换法（机器离线/丢失）

```bash
towstrap-server machine token alice build --regen --admin   # 打警告 + 记 MACHINE-TOKEN-REGEN-ADMIN
```

旧 token 立刻作废；之后把新 token 写进那台机器的 token 文件（agent 重连时会重读）或重启时传给 `--agent-token`。

---

## 9. MCP：给 LLM 用

LLM 通过 MCP 拿这些工具在被控机上干活：`list_machines`（有哪些机器）、`run_command`（跑命令，返回分开的 stdout/stderr/exit_code）、`read_file`、`write_file`，以及一组真实终端工具 `terminal_open`/`terminal_write`/`terminal_read`/`terminal_resize`/`terminal_close`/`terminal_list`（开 PTY 跑 pi、vim、top 这类要终端的交互程序）。

`terminal_open` 开的是**会话级临时终端**：挂在当前 MCP 会话下，`terminal_close` 或会话结束即终止，`terminal_list` 只列本会话的终端。它接不了镜像终端（见 §3「镜像终端」）——可接力终端是给人用的功能，入口只有被控机上的 `towstrap mirror` 命令（本机终端或 SSH 上去跑）。

`run_command` 默认每条命令都是新起的 shell（cd、export 不保留）；带 `session` 参数（如 `session: "work"`）则进**常驻 shell**——同名会话共享一个远端 shell 进程，cd、环境变量、`source` 激活的环境、后台任务跨命令保留，跟本地终端一样。边界：不支持 `stdin`；`cwd` 只在建会话时生效；命令超时或会话终结会杀掉**整个进程组**——shell 正在跑的前台命令和 `&` 后台任务一起清掉（想在会话结束后留一个守护进程，用 `setsid` 起，比如 `setsid npm run dev >/tmp/dev.log 2>&1 &`；Windows 下只杀主进程）；`exit`/`exec` 终结会话后同名命令自动起新 shell（返回 `session_restarted` 提示）；要终端的交互程序跑不了。空闲会话按 `session_idle`（默认 30m）回收，每个 MCP 客户端最多 `max_sessions`（默认 8）个。

两种接入方式工具行为一致，区别只在 MCP server 跑在哪：

| | stdio（`towstrap-mcp`） | 服务器内嵌 HTTP（`/mcp`） |
| --- | --- | --- |
| MCP server 跑在 | 跑 LLM 的那台机器 B | 服务器 S 上 |
| B 上要装的 | `towstrap-mcp` + 无口令 SSH 私钥 | 不装，填 URL + Bearer token |
| 执行通道 | B 经 SSH 登 S 再落到 agent | S 内部直连 agent，不走 SSH 回环 |
| 能碰哪些机器 | mcp.yaml 里写死 | 每个客户端 token 各自的 `--machine` 列表 |
| 批准兜底 | `towstrap-mcp pending/approve/deny`（在 B） | `towstrap-server mcp pending/approve/deny`（在 S） |
| 适用 | 自己本机用 | 给别人/多个客户端用 |

### 9.1 方式一：stdio（towstrap-mcp）

配置默认读 `~/.config/towstrap/mcp.yaml`（`--config` 可换；`examples/mcp.yaml` 是全量注释模板）：

```yaml
server: towstrap.vast-plan.com:7822   # towstrap 服务器的 SSH 入口
key: ~/.ssh/towstrap_bot            # 无口令私钥（MCP 没地方输 passphrase）
known_hosts: ~/.ssh/known_hosts     # 或改成 host_key: SHA256:... 钉死指纹（二选一，必填其一）
machines:
  office:                            # 键 = SSH 登录名（账号 或 账号+机器名）
    description: 开发机，代码在 ~/work/app
    roots: [~/work]                  # write_file 落到这些目录自动放行
policy:
  default: ask                       # run|ask|deny，默认 ask
  ask_timeout: 5m
limits:
  timeout: 120s                      # run_command 默认超时
  max_timeout: 1h                    # timeout_seconds 参数上限
  max_output: 65536                  # stdout/stderr 各自返回上限，超了保留头尾
  max_file: 1048576                  # read_file/write_file 文件大小上限
  session_idle: 30m                  # 常驻 shell 空闲多久回收
  max_sessions: 8                    # 每个 MCP 客户端会话最多几个常驻 shell
approvals_dir: ~/.config/towstrap/approvals   # ask_via: local 的待批请求落这
```

先在服务器上把公钥登记给账号：`towstrap-server user set office --ssh-key-file ~/.ssh/towstrap_bot.pub`。known_hosts 里没有记录时，先 `ssh-keyscan -p 7822 服务器 >> ~/.ssh/known_hosts`，或在 yaml 写 `host_key: SHA256:...`。

Claude Code 的 `mcpServers` 写法（`command` 给绝对路径）：

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

### 9.2 方式二：服务器内嵌 HTTP（/mcp）

`server.yaml` 里加 `mcp:` 小节打开（默认关）：

```yaml
mcp:
  enabled: true
  # path: /mcp                 # 挂载路径，默认 /mcp
  # allow_plain_http: false    # 明文 HTTP + 非回环监听时拒绝启动；确认内网/隧道才开
  # approvals_dir: /var/lib/towstrap/approvals   # 默认在审计日志目录旁的 approvals/
  # machines:                  # 可选：给 MCP 客户端看的说明和 write_file 放行目录
  #   bot+default: { description: "办公机", roots: ["~/work"] }   # 键 = 完整机器 ID
  # policy / limits 与 mcp.yaml 同格式，不写用内置默认
```

然后给每个客户端签发 token：

```bash
towstrap-server mcp add laptop --machine alice            # alice 名下全部机器
towstrap-server mcp add builder --machine alice+build     # 只给一台
towstrap-server mcp add everything --machine '*'          # 全部机器
towstrap-server mcp add ops --machine alice --machine bob # 多个账号
```

`--machine` 四种写法：`'*'`（全部）、`'alice'`（该账号全部）、`'alice+*'`（同上，显式通配）、`'alice+office'`（指定一台）。签发时机器不存在不挡（先建凭据后建机器），只提醒。

客户端（Claude Code 等）只填 URL 和 token（`mcp add` 的输出里就有现成的配置片段）：

```json
{
  "mcpServers": {
    "towstrap": {
      "type": "http",
      "url": "https://服务器:7880/mcp",
      "headers": { "Authorization": "Bearer tsm-..." }
    }
  }
}
```

`tsm-` token 只显示一次；忘了用 `mcp token 名字 --regen` 换（旧的立刻作废）。

### 9.3 MCP 客户端管理子命令

| 命令 | 作用 |
| --- | --- |
| `mcp add 名字 --machine 授权... [--allow-ip 地址]...` | 签发客户端 token（只显示一次），输出客户端配置和 skill 安装命令 |
| `mcp list` | 列客户端：机器范围、来源白名单、状态、创建时间 |
| `mcp set 名字 [--machine]... [--allow-ip]... [--clear-allow] [--disable\|--enable]` | 改授权/白名单/停启用 |
| `mcp remove 名字` | 删除，token 作废 |
| `mcp token 名字 [--regen]` | 看/换 token |
| `mcp pending [--approvals-dir 目录] [--config server.yaml]` | 列等待批准的请求 |
| `mcp approve [--remember] <id>\|--all` / `mcp deny <id>\|--all` | 批准/拒绝待批请求（--remember：本会话内相同命令不再问） |

批准目录查找顺序：`--approvals-dir` > server.yaml 的 `mcp.approvals_dir` > 审计日志目录下的 `approvals/`。

`--allow-ip` 给客户端加来源白名单（不在名单里的来源带这个 token 也进不来，记 `MCP-AUTH-FAIL reason=client-allow-ip`）。

### 9.4 策略名单

每条 `run_command` 过一遍策略（`policy` 小节），判定顺序 **deny > ask > allow > default**：

- `deny` 名单命中的**直接拒绝**，没有「确认一下就行」的余地（删根、格盘、`curl|sh` 管道执行、读私钥/sudoers、动 agent 自身等）
- `ask` 名单命中的**要用户确认后执行**——危险但有正当场景的操作：`rm`、`sudo`/`su`、`kill`/`pkill`、关机重启、`find -delete/-exec`、`git push/reset/clean/rebase`、`chmod`/`chown`、`dd`/`fdisk` 等
- `allow` 名单里的只读/低风险命令**自动放行**（`ls`、`cat`、`git status` 这类）；命令按 `&&`、`||`、`;`、`|`、换行切段，**每段**都得命中 allow 才算；段里出现反引号、`$(`、`>`、`<`、`&` 就不敢自动放行
- 其余落到 `policy.default`（`ask` 要确认 / `run` 直接跑 / `deny` 直接拒，默认 `ask`）

注意顺序是 ask 压过 allow：管理员把 `rm` 写进 allow 也压不过内置 ask 规则，想让某类命令静默放行得先把对应的 `ask` 规则撤掉（yaml 写了自己的 `ask:` 就整份替换内置名单）。

`read_file` 不需要批准但受 `deny_paths` 限制（私钥、凭证默认都在名单里）；agent 上线时还会把自己的 token 文件和配置文件路径报给服务器，这两个文件无论叫什么名字、放在哪都读写不到。`write_file` 落在机器的 `roots` 里自动放行，之外要批准；`deny_paths` 和 agent 自报清单照样先拦。

内置名单全文在 `internal/mcpsrv/policy.go` 的 `DefaultAllow`/`DefaultAsk`/`DefaultDeny`/`DefaultDenyPaths`；yaml 里写了对应项就**整份替换**，不是在默认上追加。

**机器级免批准**：机器是它部署者的，宽严部署者说了算——agent 端写 `mcp_policy: open`（agent.yaml 或 `--mcp-policy`），这台机器的 ask 命中（rm、sudo 等）和越界 write_file 就**不再问**直接执行；`deny` 名单保底不动。服务端也能在 `machines.<名字>.policy: open` 里定（没上报能力的老 agent 靠它；yaml 显式写的优先于 agent 自报）。放行的执行审计记 `MCP-POLICY-OPEN`，输出标 `approval=open`——事后能分清是姿态放行的、不是真人批的。stdio 模式的 `mcp.yaml` 也认 `machines.<名字>.policy`。

⚠️ 策略是过滤层**不是沙箱**：shell 语法总能绕过朴素切段。真正的边界是 agent 的系统用户权限。roots 是**文本前缀匹配**、不解析远端符号链接：`~/work/link -> /etc` 这种指向外面的链接会让 `write_file ~/work/link/x` 逃过 roots 检查——roots 目录里别放这种链接。

### 9.5 人工批准

需要批准的操作走哪条路由 `policy.ask_via` 决定；不写（auto）时客户端支持弹窗就弹窗、不支持就走本地待批文件——**审批默认要真人**，不会自动降格成让 LLM 自己确认：

1. **弹窗**（auto + 客户端支持 elicitation）：弹「允许执行」确认框，可勾「本次会话内相同命令不再询问」——这是最强的一种，同意是真人点的
2. **本地待批**（`ask_via: local`，或 auto 时客户端不支持弹窗）：待批文件落到 `approvals_dir`，人去终端跑 `towstrap-mcp approve <id>`（stdio）或 `towstrap-server mcp approve <id>`（内嵌）；加 `--remember` 时本会话内相同命令不再问。同时会弹一个**能点的系统对话框**——三个钮：拒绝 / 允许 / 「允许并不再问」（macOS 用系统对话框、Linux 用 zenity，弹不了退到桌面通知 + `wall` 广播到本机所有登录终端）；stdio 恒弹，内嵌模式默认也弹（`mcp.local_notify` 默认开；无桌面的服务器自动静默退化，嫌吵显式 `local_notify: false` 关）。**等批准期间发起调用的 MCP 客户端会收到一条日志通知**（id、机器、命令、怎么批）；内嵌服务器还会把提示直接写进**同账号正在登着的 towstrap SSH 终端**——你 `ssh` 登在服务器上时，终端里会冒出一行 `[towstrap] 等待人工批准 ap-xxxx（机器: 命令）…`，不用猜调用为什么挂着
3. **会话内确认**（`ask_via: llm`，显式配置才走）：第一次调用**不执行**，工具给 LLM 返回一段指引；LLM 把命令和风险转述给用户、问过同意后带 `confirmed=true` 原样重试才真正执行。确认按「会话 + 机器 + 命令」记账，**一次性**、10 分钟有效；`confirmed=true` 不能预授权没发起过确认的命令。用户说「以后这类都允许」时 LLM 可加 `remember=true`，本会话内同命令不再问。注意这只是 LLM 声称的同意，比前两条弱——不写 `ask_via` 不会自动走这条

⚠️ `ask_via` 写死了就**压过客户端能力**：有的客户端（如某些版本的 Cursor）声称支持弹窗却渲染不出来，调用会一直挂着直到超时——这时把 `policy.ask_via: local`（本机弹对话框，内嵌模式 `local_notify` 默认开着）或 `llm` 写上就能绕开。

等到 `ask_timeout`（默认 5 分钟）没人理就超时拒绝；会话内确认的 10 分钟是另一个窗口（等 LLM 带 confirmed 回来）。

⚠️ 「会话内确认」里服务端看到的是 **LLM 声称用户同意了**，防的是误操作和闷头执行，不能当作独立核实过的真人批准——审计里单独记 `MCP-CONFIRMED` 与真人点弹窗的 `MCP-APPROVED` 区分。对确认强度有要求的部署应该用支持弹窗的客户端或 `ask_via: local`。

### 9.6 授权会话记录

普通命令执行完不留内容级记录（只有审计事件）；**凡是批了才执行的操作会留档**，把「申请的命令 → 哪次批准 → 实际跑了什么 → 结果」串起来：

- 每次批准请求发一个授权编号 `ap-xxxx`（批准命令、审计事件里都用它）；每次实际执行再发执行编号 `ex-xxxx`
- 记录写在批准目录旁的 `auth-records/` 里（0600）：普通命令记命令全文、退出码、时长、stdout/stderr；`write_file` 记路径、字节数和内容的 sha256 指纹（不记文件全文）；授权开的 PTY 终端把输出全程落盘（单个文件上限 4MB，超出截断并注明）
- `remember` 过的重复执行各留一份记录，`auth` 指回当初那次批准——事后能查清「这条命令凭的是哪一次同意」

审计字段对应关系：`MCP-ASK auth=ap-…`（发起确认）→ `MCP-CONFIRMED`/`MCP-APPROVED auth=ap-…`（拿到同意）→ `MCP-AUTH-EXEC auth=ap-… exec=ex-… record=路径`（执行留档）。

---

## 10. 给 LLM 助手装 skill

仓库自带一份教编码助手「怎么安全地用 towstrap」的 skill（源文件 `skills/towstrap/SKILL.md`）。三条路任选：

### 服务器直接拉（不装 towstrap-mcp 也行）

```bash
mkdir -p ~/.claude/skills/towstrap && curl -fsSL https://服务器:7880/skill -o ~/.claude/skills/towstrap/SKILL.md
# 其他助手换目录：Cursor ~/.cursor/skills/，Codex/Grok 共用 ~/.agents/skills/
# 服务器是自签证书的话 curl 要加 -k
```

`GET /skill` 不需要口令（公开文档），`mcp add` 的输出末尾也自带这几行命令。

### towstrap-mcp 一键装

```bash
towstrap-mcp connect                  # 装到本机检测到的所有 harness
towstrap-mcp connect list             # 看支持哪些、检测到哪些、装没装
towstrap-mcp connect --path .claude/skills   # 只装到指定目录（比如项目级）
towstrap-mcp connect uninstall        # 卸载（你改过的内容默认不删，--force 才删）
towstrap-mcp connect --dry-run        # 演练，不写文件
```

支持：Claude Code、Codex、Grok Build、Cursor、Gemini CLI、OpenCode、GitHub Copilot CLI、Devin CLI（检测各家目录；Codex 和 Grok 共用 `~/.agents/skills`，只写一份）。安装是写 `<skills目录>/towstrap/SKILL.md` 加一份 `.towstrap-managed.json` 清单；你自己放的同名 skill 不会被误盖（要 `--force`）。

### 手工拷贝

把 `skills/towstrap/` 整个目录拷进任何一家认识的 skills 目录，效果一样。

### print-mcp：打印各家客户端的配置片段

```bash
towstrap-mcp connect print-mcp --url https://服务器:7880/mcp --token tsm-...
towstrap-mcp connect print-mcp --stdio [--config mcp.yaml]
```

打印 Claude Code / Codex / Grok / Cursor / Gemini / OpenCode 各家的 MCP 配置写法（不写文件）。token 是凭据，别贴进聊天和仓库。

---

## 11. 监控

```bash
# 活着没：不需要口令
curl https://服务器:7880/health        # ok

# 看谁在线：两种口令
curl -H "X-Admin-Token: <admin_token>" https://服务器:7880/status   # 管理口令看全量
curl -H "X-Agent-Token: tsa-..."       https://服务器:7880/status   # 机器 token 只看自己
```

`/status` 返回形如：

```json
{"ok":true,"http":":7880","ssh":":7822","users":[{"user":"alice","machine":"alice+default","online":true}]}
```

管理口令看全部机器（`machine` 是完整登录名），机器 token 只看得到自己那一台——普通用户没法枚举机群。没有在线机器时 `ok:false` 且 HTTP 状态 503。

---

## 12. 审计日志

两端各记各的，格式都是 `<时间> <事件> k=v`，16MB 轮转成 `.1`，权限 0600，值里的控制字符（含 C1、U+2028/2029）写入时清掉，值带空格/`=`/引号时整值加引号（防止伪造第二个字段）。

**agent 侧**（默认 `/var/lib/towstrap/audit.log` 或 `~/.towstrap/audit.log`）：

| 事件 | 含义 |
| --- | --- |
| `AGENT-START` | 进程启动：版本、服务器、shell、insecure/quiet、uid、审计路径 |
| `START` / `END` | 每个远程会话开始/结束：id、来源 `登录账号@IP`、模式、命令 |
| `TOKEN-ROTATED` | 服务器下推的新 token 已写进 token 文件 |

**服务器侧**（默认 `/var/lib/towstrap/server-audit.log` 或 `~/.towstrap/server-audit.log`，写 `/dev/null` 关）：

| 事件 | 含义 |
| --- | --- |
| `AUTH-OK` / `AUTH-FAIL` | SSH 认证成败：user、ip、method（password/kbd-interactive/publickey）、失败 reason（locked/password/disabled/allow-ip/totp） |
| `AGENT-CONNECT` / `AGENT-DISCONNECT` | agent 上下线：id、ip、version |
| `AGENT-REPLACE` | 同名 agent 顶替了旧连接 |
| `AGENT-DENY` | agent 接入被拒：reason=agent-allow（白名单）/old-version（版本过低） |
| `AGENT-IPCHANGE` | agent 换了来源 IP（没设白名单时）——token 泄露的典型信号 |
| `AGENT-REVOKE` | 巡检发现凭据失效（token 换过/机器删了/账号停用），当场断开 |
| `SESSION-START` / `SESSION-END` | SSH/MCP 会话：user、from、id、mode（pty/exec/mcp）、machine、cmd（>512 字节截断）；END 带退出码 |
| `SESSION-DENY` | 会话被拒：reason=cmd-too-long/no-machine/ambiguous/offline/credential/open |
| `MGMT-DENY` | `@` 管理命令被拒：reason=pubkey/locked/totp |
| `MACHINE-ADD` / `MACHINE-REMOVE` / `MACHINE-TOKEN` | SSH 自助管理：加机器/删机器/看 token |
| `MACHINE-ADD-ADMIN` / `MACHINE-TOKEN-ADMIN` | CLI `--admin` 跳过本人确认 |
| `MACHINE-TOKEN-REGEN-ADMIN` | CLI `--admin` 应急换 token |
| `TOKEN-REFRESH` | token 换发：每台一条，含发起方 `agent:调用机器@IP` 和结果 status |
| `TOKEN-REFRESH-DENY` | 换发被拒：reason=content-type/token/agent-allow/locked/body/password/totp |
| `MCP-SESSION` | MCP 客户端建会话：client、ip（30 秒内去重） |
| `MCP-SESSION-CMD` | 常驻 shell 会话里执行了一条命令：machine、session、cmd |
| `MCP-AUTH-FAIL` | MCP 认证失败：reason=allow-ip/token/client-allow-ip |
| `MCP-POLICY-DENY` | 命中策略 deny/deny_paths：client、machine、kind、detail |
| `MCP-ASK` / `MCP-APPROVED` / `MCP-CONFIRMED` / `MCP-DENIED` / `MCP-ASK-TIMEOUT` | 批准流转：via=elicit/local/llm，带授权编号 auth=ap-… |
| `MCP-AUTH-EXEC` | 授权过的执行留档：auth=ap-… exec=ex-… record=记录文件路径 |
| `MCP-TERMINAL-OPEN` / `MCP-TERMINAL-CLOSE` / `MCP-TERMINAL-END` | MCP PTY 终端的开关：machine、terminal、cmd、approval |

agent 侧（`audit.log`）另有 `START`/`END`（mode=mirror 的本机接入）、`MIRROR-KILL`（name、via=local 手动终结 / via=idle 闲置超时自动终结）。

---

## 13. 排错

| 症状 | 原因与处理 |
| --- | --- |
| `这台机器没上线（agent 未连接）` | agent 没在跑或连不上服务器。看 agent 端日志；确认 `--server` 地址端口对、token 文件内容对 |
| `这台机器的接入凭据已失效` | token 被换过/机器被删/账号被停用。用 `machine token` 拿到当前 token 更新 agent 的 token 文件 |
| SSH 提示 host key 变了 | 服务器的 `ssh_host_key` 被换过。确认是不是重装了服务器；是就删本地 `~/.ssh/known_hosts` 里对应行，不是就当中间人攻击处理 |
| `Permission denied` 反复出现 | 检查账号是否停用（`user list`）、IP 是否在白名单里、是否被限速锁定（等锁过期，初始 1 分钟） |
| 绑了 TOTP 后密码登录直接失败 | 正常现象：绑 TOTP 的账号必须走 keyboard-interactive（密码+验证码）；自动化改用公钥 |
| `mcp` 启不来：`mcp 开在明文 HTTP 上...` | `/mcp` 挂在明文 HTTP + 非回环地址会拒绝启动。开 `tls: true`，或确认只在内网/隧道后设 `mcp.allow_plain_http: true` |
| MCP 客户端 401 | token 不对/被删/被停用（`mcp list` 查），或来源不在客户端的 `--allow-ip` 名单里 |
| `token refresh` 报 `no-file` | 那台机器的 token 不是从文件读的——改用 `--agent-token-file` 并重启 agent，下次就能远程换 |
| `token refresh` 报 `offline`/`timeout` | 目标机器不在线或没确认；库里没换，重试即可 |
| `token refresh` 被 429 | 密码/TOTP 错太多次被锁，等锁过期（初始 1 分钟，翻倍封顶 1 小时） |
| agent 频繁 `AGENT-REPLACE` | 同一台机器起了两个 agent 互顶，或 token 被拷到别处。查重复进程；怀疑泄露就换 token |
| 连接数被打满 | 看 `max_conns`/`max_conns_per_ip` 的拒绝日志（`连接数达上限，拒绝新连接`），按需调大 |
| `towstrap mirror` 连不上 socket | agent 没在跑，或 socket 被旧文件占着（日志会写 `mirror socket 已被占用`）。socket 在 `~/.towstrap/mirror.sock`（root 装法 `/var/lib/towstrap/`），可用 `--sock` 或 `TOWSTRAP_MIRROR_SOCK` 换位置 |

---

## 14. 升级说明

- **自升级**：`towstrap update`（agent）/ `sudo towstrap-server update`（服务端）从官方 Release 拉本平台二进制，SHA256SUMS 校验后原子替换自身；`--check` 只查不装，`--version vX.Y.Z` 指定版本（含降级）。装成 systemd 服务或 Windows 计划任务的升级后自动重启生效；手工跑的进程要手工重启。重跑 install.sh/install-server.sh 同样能升级（配置、token 不动）
- **老账号库自动迁移**：从「一个账号一个 token」的旧版本升级时，打开库就把每个账号的 token、agent 白名单、最近来源 IP 搬到一台名为 `default` 的机器上——老 token 不变，agent 不用动；之后登录名变成 `账号+default`（单机时写账号名仍可用）
- **`users_key` 没配过**：默认用 `users_db` 去掉 `.db` 后缀 + `.key`（`/etc/towstrap/users.db` → `/etc/towstrap/users.key`），库和 key 要一起备份
- **SSH 主机密钥**：默认在 `users_db` 同目录的 `ssh_host_key`；换库路径时记得带上它，否则所有客户端会报 host key 变更
- agent 和服务器版本不必严格一致；服务器可以用 `min_agent_version` 淘汰过旧 agent（自报版本，不是安全控制）
