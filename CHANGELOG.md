# Changelog

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
