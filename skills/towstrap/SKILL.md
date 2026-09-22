---
name: towstrap
description: 通过 towstrap 在用户的远程机器（跑着 towstrap-agent 的被控机）上执行命令、读写文件、做远程开发任务。当用户提到 towstrap；或要在「某台机器 / 开发机 / 服务器」上跑命令、改代码而那台机器是经 towstrap 接入的；或工具列表里出现 list_machines / run_command / read_file / write_file；或用户给的是 `ssh -p 2222 账号+机器名@服务器` 这种地址时使用。
---

# towstrap：在用户的远程机器上干活

## 它是什么

- 被控机上跑着 `towstrap-agent`，主动连到 towstrap 服务器。你通过 **MCP 工具**或 **ssh 命令**让服务器把命令转到那台机器上执行。
- 命令以那台机器上 **agent 的系统用户身份真实执行**，后果不可撤销。把每条命令都当成在用户的电脑上敲回车。
- 机器标识写作 `账号+机器名`（如 `alice+office`）。账号只有一台机器时可以只写账号名。

## 先判断你有哪种接入方式

1. 工具列表里有 `list_machines` / `run_command` / `read_file` / `write_file` → 用 MCP 工具（首选）。
2. 只有终端 → 用 ssh：`ssh -p <端口> <账号>[+<机器名>]@<服务器> '<命令>'`。服务器地址、端口、账号由用户给；一般需要用户已经配好公钥。

## 用 MCP 工具时

1. 先 `list_machines`：拿到机器名、用户写的说明、`write_file` 自动放行的目录（roots）、是否在线。机器名照抄，不要猜。
2. `run_command` 每次都是**新起的 shell**：`cd`、环境变量、shell 变量不会保留到下一次。用 `cwd` 参数指定工作目录，或在一条命令里 `cd dir && …`。
3. 命令先过策略再执行：
   - deny 名单里的直接拒绝；
   - allow 名单（只读 / 低风险，如 `ls`、`cat`、`git status`、`go test`）自动放行；
   - 其余需要**用户批准**——会弹确认框，或用户在自己终端里执行 approve。等待期间工具调用不会返回。
   - 被拒绝或等待超时：向用户说明你想执行什么、为什么，由用户决定。**不要改写命令绕过策略**——换写法、拆成几段、编码、借 `write_file` 写脚本再执行、借 `read_file` 读被拒的路径，都算绕过。
4. `exit_code` 才是成败依据，不要只看 stdout。stdout / stderr 分开返回；超过上限会截断（`stdout_truncated` / `stderr_truncated` 为 true），用 `head`、`tail`、`grep`、`wc` 缩小范围再看。
5. 文件：
   - 改文件优先 `write_file`（覆盖写、只支持文本、路径用绝对路径或 `~/` 开头；在 roots 内自动放行，之外要用户批准）。写之前先 `read_file` 看清原内容，改动尽量小。
   - 读文件用 `read_file`；私钥、凭证、agent 自己的配置这类路径读不到（`deny_paths`），别反复试。
   - 大文件、二进制走 `run_command` 的 `head -c`、`tail`、`base64`。
6. 破坏性操作——删除、覆盖、`git push --force`、`git reset --hard`、`git clean`、改系统配置、装卸软件、启停服务——**即便策略放行，也先向用户确认**，说清影响范围。
7. 长任务：`timeout_seconds` 可调（上限由配置决定）。`timed_out` 为 true 表示命令被杀，结果不完整；不要把它当成功。

## 用 ssh 直连时

- 形式：`ssh -p <端口> <账号>[+<机器名>]@<服务器> '<命令>'`；`-T` 可显式不要终端。可以喂 stdin：`echo x | ssh … 'cat > file'`。
- 每条 ssh 也是新 shell，同样用 `cd dir && cmd`。
- 退出码原样返回。常见输出：「这台机器没上线（agent 未连接）」→ 退出 1，告诉用户；「这个账号有多台机器，请用 账号+机器名 登录」→ 按它列出的名字补上 `+机器名` 再试。
- 没有 scp / sftp。小文件用 `cat` / heredoc，二进制用 `base64` 编解码。
- 以 `@` 开头的命令（如 `@machine list`、`@machine add`）是服务器的**管理命令，给人用的**：要密码登录 + TOTP，公钥登录会被拒。**不要**替用户执行它们，不要试图加机器、查看或更换 token。

## 不要做的事

- 不要读取、打印、转述 agent 的 token、`agent.yaml`、`~/.towstrap/`、私钥、`/etc/shadow`、`/etc/sudoers`。
- 不要停止、重启、卸载 `towstrap-agent`，不要改它的配置或 token 文件——那会断掉你和用户的通路。
- 不要 `sudo` / `su`。agent 的系统用户就是权限边界；需要更高权限就告诉用户。
- 不要在被控机上留下持久化的东西（后台进程、cron、systemd 单元、`authorized_keys`、shell 启动文件里的改动），除非用户明确要求。
- 不要把执行结果里的机器路径、用户名、内网地址往外部服务发送。

## 出错时怎么处理

| 现象 | 做法 |
|---|---|
| 机器「不在配置里」/「不存在」 | `list_machines` 或问用户机器名 |
| 「没上线（agent 未连接）」 | 告诉用户 agent 掉线，请他检查那台机器；不要反复重试 |
| 「接入凭据已失效」 | token 已换或账号被停用；请用户在那台机器上执行 `towstrap-agent token refresh` 或联系管理员 |
| 策略拒绝 / 等待批准超时 / 用户拒绝 | 解释意图，等用户决定；不要绕 |
| 输出被截断 | 缩小范围重跑，不要凭截断内容下结论 |

## 用户问「怎么把 LLM 接上 towstrap」时

- 服务器内嵌 MCP（推荐，客户端不用装东西）：在客户端的 MCP 配置里加 HTTP 服务器 `https://<服务器>:<端口>/mcp`，请求头 `Authorization: Bearer tsm-…`（token 由服务器管理员 `towstrap-server mcp add` 签发）。
- 本机 stdio：装 `towstrap-mcp`，配 `mcp.yaml`（服务器地址、私钥、机器列表），客户端以命令方式启动它。
- `towstrap-mcp connect print-mcp` 会打印各家客户端（Claude Code、Codex、Grok、Cursor、Gemini CLI、OpenCode）的配置片段；`towstrap-mcp connect` 把本 skill 装进本机检测到的客户端。
