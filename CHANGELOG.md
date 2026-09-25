# Changelog

## v0.3.2（2026-09-25）

### 修复

- **Linux 上镜像终端/会话进程退出后可能挂死**：主进程退出（或被 kill）但有后台任务攥着 PTY 从端时，Linux 内核里 close 主端 fd 打不断阻塞在 read(2) 里的输出泵（等待挂在 tty 上不是 fd 表），镜像会一直挂在登记处、会话收不到退出码。主端改非阻塞 + poll（100ms）驱动读取，Close 靠标志位让泵自行退出——交互会话和镜像终端同一条路，一起修好。macOS 行为不变
- e2e 回显匹配剥 CSI 转义序列再比对：各发行版 bash 开 bracketed-paste（`\x1b[?2004h/l`）时回显和输出被隔开，行首 marker 匹配不上——此前 CI（Ubuntu）上整批 SSH 测试因此超时

### 新增

- **自助接入 `towstrap register`**：agent 装完的首次接入入口，交互先问有没有账号。没账号 → `POST /register` 自助建号（服务器开 `register: true` 才受理，`register_invite` 可配邀请码）；已有账号 → `POST /register/machine` 登录加机（密码验证，不受 register 开关管，等价 `@machine add`；同名机器视为重装换新 token）。两条路都上报机器指纹（SHA-256 哈希，原始硬件 ID 不出本机）；**一台机器的指纹只许绑一个账号**，重复注册返回既有账号名提示找回，`user del` 删号自动释放指纹；每来源 IP 每小时限 8 次
- `server.yaml` 新键：`register`（默认关）、`register_invite`（默认空不验）
- **向导式 TOTP 绑定**：`register` 成功后交互问要不要绑二因素——终端出二维码、输码确认才生效；`--skip-totp` 跳过
- **`towstrap totp` / `towstrap totp remove`**：机器上直接管账号的二因素（登进机器 shell 里敲最顺手），走 `POST /totp/{begin,confirm,remove}`——本机 agent token + 账号密码鉴权（token 反查账号，所以只问密码），已绑账号换绑/解绑还要当前动态码（对齐 SSH 管理命令的重验门槛）；失败计入登录锁，丢了验证器走管理员 `user totp --remove` 恢复
- **`@totp` SSH 自助命令**：`ssh '@totp'` 绑/换绑（出二维码），`@totp remove` 解绑；已绑账号走 TOTP 重验门槛——留给手边没这台机器的场合
- **`install-server.sh` 服务端一键安装**：`curl | sudo sh` 下二进制、校验 SHA256SUMS、写最小 `server.yaml`（0600，已有不覆盖）、Linux+root 自动装并启动 systemd 服务（`--no-systemd`/`--confdir`/`--prefix`/`--check` 可调）；服务器 `/install-server.sh` 下发同一份字节，单元样例 `examples/towstrap-server.service`
- **`towstrap-server init` 初始化向导**：装完后交互配三件事——对外地址（`public_url`）、自助注册开关（`register`/可选邀请码）、第一个账号（内联建号打印 SSH 登录名和机器 token）；写回 yaml 是 Node 级改写（注释和无关字段原样保留，同值不重复写），文件不存在时自动补最小骨架（http/ssh/users_db）；systemd 服务在跑则改完自动重启；脚本模式 `--yes` 加旗标走全参（`--public-url`/`--register`/`--no-register`/`--register-invite`/`--account`/`--password-stdin`/`--no-restart`），可反复跑改配置
- 落地页改版 + SSH 客户端推荐（桌面/手机）
- 机器指纹升级为硬件级：优先主板固件 UUID（macOS IOPlatformUUID+序列号、Linux product_uuid、Windows SMBIOS UUID），重装系统不变；占位 UUID 过滤；哈希带来源标签

## v0.3.1（2026-09-25）

### 修复

- **安装脚本占位符误判（影响 v0.3.0 服务器下发的脚本）**：`install.sh`/`install.ps1` 里"占位符未替换"的检测模式本身也被服务器端全文件替换成了真值，导致下发的脚本运行时把 `--server` 重置回官方域名、版本重置回 `latest`——版本钉和自建地址实际没生效。检测改为只认 `__TOWSTRAP` 前缀。GitHub 直拉的脚本不受影响
- 同理修复 `agent_conf`/`ssh_port` 两个新占位符的运行时回落检测
- 新增回归测试：把下发的安装脚本以 `--check` 真跑一遍验证解析结果（此前只比对文本，没覆盖到这类 bug）

### 新增

- **`server.yaml` 的 `agent_defaults:`**：管理员预设 agent 工作配置（`shell`/`mirror_idle`/`quiet`/`audit_log`/`insecure`/`mcp_policy`），服务器下发的安装脚本会自动写进新装机器的 `agent.yaml`；`server`/`agent_token*` 身份字段不允许预设（写了启动时 WARN 忽略）；首页展示预设内容
- `install.sh --check`：干跑模式，打印解析出的服务器地址/版本/SSH 地址/预设后退出，不下载不安装
- 安装完成时打印这台机器的 SSH 登录地址（主机从 `--server` 推导，端口取服务器配置的 SSH 口）

## v0.3.0（2026-09-25）

### 新增

- **mirror 持久终端**：`towstrap mirror <名字>` 创建/接入命名终端，会话存于 agent，`Ctrl-\` 脱离后续跑；本机、SSH、远程客户端接力同一终端；`mirror ls/-q`、`mirror kill`、`mirror setup` shell 钩子
- **MCP 审批**：`run_command`/`write_file`/`terminal_open` 按策略 ask/deny；MCP 弹窗 + 本地通知 + SSH 终端提示；会话内可记忆批准
- MCP `terminal_*` 交互式 PTY 工具（独立于 mirror）
- OAuth/OIDC 设备登录与令牌刷新
- 服务器落地页 `/`：产品介绍 + 各平台安装命令
- monitor 旁路审计/指标推送

### 变更

- 官方服务器 `wss://towstrap.vast-plan.com` 成为 `--server` 默认值
- 安装脚本默认从 GitHub Releases 下载；服务器下发的脚本钉到服务器同版本
- HTTP 默认 `:7880`、SSH 默认 `:7822`，可经 `server.yaml`/旗标配置
- `towstrap-agent` 二进制并入 `towstrap` 命令
