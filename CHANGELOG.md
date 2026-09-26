# Changelog

## v0.3.6（2026-09-26）

### 新增

- **`towstrap passwd` 子命令**：在这台机器上自助改账号的 SSH/登录密码（POST /passwd）。agent token 认机器 + 旧密码证本人 + 已绑 TOTP 要当前动态码（和 /totp/* 同一条鉴权链：IP 白名单、登录锁、oauth_only 拦截都算数）；改完全账号生效，名下所有机器 SSH 登录换新密码。`--password-stdin` 脚本模式从 stdin 读两行（旧、新），`--totp` 带当前动态码
- **`towstrap status` 凭据段**：显示 agent token 的实际来源（旗标/环境变量/配置项/文件路径）和遮中段后的值（`--show-token` 可看完整值）；并明确 agent token（tsa-，本机用）与 MCP token（tsm-，服务器 `mcp add` 签发、给 AI 客户端用）是两套互不相干的凭据
- **`towstrap status` 子命令**：显示本机 agent 跑没跑、连没连上服务器、上次断开原因、活跃远程会话/镜像数。数据走本机 mirror.sock 的 `status` 操作（实时权威），socket 不应答时退到进程表探测，再查 systemd/launchd/计划任务状态和 agent.yaml 凭据就位情况，没在跑时给启动指引。退出码：0 已连上、3 在跑未连、1 没在跑；`-q` 静默
- **裸跑 `towstrap` 自动加载默认配置**：不带 `--config` 时按安装脚本落点找 agent.yaml（root→/etc/towstrap，用户→~/.config/towstrap，Windows→%LOCALAPPDATA%\TowStrap），装完直接 `towstrap` 即起
- **`install.sh --launchd`（macOS 服务化）**：root 写 /Library/LaunchDaemons 守护项，普通用户写 ~/Library/LaunchAgents 并 `launchctl bootstrap`；已加载时 `kickstart -k` 重启让升级生效；无 token 时写 plist 不加载
- mirror.sock 新增 `status` 操作；root 连他人 agent socket 降为受限连接，只放行 status 只读查询

### 修复

- **`register` 不确认机器名**：之前未带 `--machine` 时静默用主机名，用户没机会命名——交互模式现在会问「这台机器的名字」（回车取主机名）；脚本模式不给旗标仍用主机名，行为不变
- **裸 `towstrap` 只打帮助不起 agent**：入口 `len(args)<2` 直接进用法，默认配置自动加载轮不到——现在默认路径有 agent.yaml（或 TOWSTRAP_* 环境变量已给凭据）时裸跑即启动 agent，什么都没装的机器才显示用法
- **`machineid.ConfDir` 不认 XDG_CONFIG_HOME**：install.sh 认，导致设了 XDG 的机器上 register/token/status 与安装路径分家——confDirOS 补上 XDG 分支，persistedID 对旧位置留兜底防指纹漂移

## v0.3.5（2026-09-26）

### 修复

- **`install.sh`/`install.ps1` 无 token 不能安装**：服务端开自助注册（`register`）时落地页下发的是不带 `--token` 的安装命令，但脚本硬要 token——现在 token 改为可选，装完跑 `towstrap register` 自助建号补齐；`--systemd` 无 token 时写好单元但不启动，避免崩退循环
- **`install.sh` 变量后紧跟全角字符触发 unbound variable**：`$asset（` 这类写法在部分 shell 下会把括号的首字节并进变量名，所有 `$var` 紧跟非 ASCII 的位置改为 `${var}`

### 文档

- 落地页文案改为正式书面风格
- 反向代理部署注意事项成文（用户手册新增「反向代理部署」节，`examples/server.yaml`/`nginx.conf`/`install-server.sh` 骨架注释补充）：容器化反代（NPM 等面板）转发 `127.0.0.1` 必 502——容器内回环是容器自身；需把 `http` 绑到 docker0 网桥或内网 IP 并设 `allow_plain_http: true`、开 WebSocket 转发、防火墙收公网；扁平顶层键与 `server:` 小节混用时顶层不生效

## v0.3.4（2026-09-26）

### 新增

- **`update` 自升级子命令**（`towstrap update` / `towstrap-server update`）：从官方 Release 拉本平台二进制，SHA256SUMS 校验通过后原子替换自身（旧文件先挪 .old 备份位，失败回滚）；装成 systemd 服务/Windows 计划任务的自动重启生效。`--check` 只查最新版，`--version vX.Y.Z` 指定版本（可降级，有提示）。升级源固定官方仓库不接受配置

### 修复

- **server 装完打印实际访问信息**：`install-server.sh` 收尾从 server.yaml 抠出真实 HTTP/SSH 监听地址，连同配置文件路径、SSH 登录示例、agent 接入命令一起打印；HTTP 只挂回环时明示对外接入的两条出路。`init` 就绪段同样固定打印监听地址（此前没填 public_url 时只给个 SSH 端口）
- **agent 升级真正生效**：`install.sh --systemd` 对已启用服务改为 `restart`（此前 `enable --now` 对运行中服务是空操作，二进制换了旧版还在跑）；不带 `--systemd` 重装时若服务在跑会提醒手工重启。`install.ps1` 覆盖 exe 前先停运行中的进程（Windows 锁运行中文件，此前升级直接失败），装完自动拉回计划任务
- **不认识的子命令不再悄悄启动进程**：`towstrap-server updte` 这类拼错以前落到默认分支直接当服务器跑；现在 runServer/runAgent 对位置参数报错并提示合法子命令

### 文档

- README 补升级路径说明（重装即升级、服务端下发脚本钉同版本、`min_agent_version` 版本淘汰）

## v0.3.3（2026-09-26）

### 安全修复（本轮安全审计批次）

**高危**

- **`machine list` 不再默认打印在线 agent token**：默认输出脱敏（`tsa-…<尾4位>`），`--show-tokens` 需现场再确认或 `--admin`；此前任何登上服务器的人能直接抄走 token 冒充机器、劫持会话
- **MCP 文件工具改为按远端真实路径判定**：先在目标机器上把路径解析成真实形态（符号链接、`..`、`~`、macOS `/var`→`/private/var`、Windows 盘符/分隔符归一），再对真实路径过 deny_paths 和 agent 自报禁碰清单，执行也走解析后的路径——`~/../etc/...`、`/proc/self/root/...`、Unicode 拼写差异、Windows 尾点/ADS 这类别名现在打不开也写不进保护文件；解析不出来一律拒
- **`/register/machine` 补齐认证链**：此前只凭账号密码就能换发/轮换 agent token。现在过登录锁、`oauth_only`（开了的账号拒绝密码路径）、绑了 TOTP 必须给动态码；`towstrap register --login` 会提示补码，`--totp` 旗标供脚本用
- **SSH 广播不再攥着全局锁做写**：每会话独立发送队列（满了丢消息不卡别人），一个停读的会话冻不住其他账号的登录、会话清理和 MCP 审批
- **SSH 输入行有长度上限**：不换行流式塞数据耗尽内存的路被堵死
- **内嵌 MCP 会话的机器元数据按调用刷新**：机器离线后重连补上的 protect 清单、`mcp_policy` 收紧，对老会话立即生效——不再按建会话时的旧快照判
- **`/totp/begin` 不再抹登录锁定**：「密码+机器 token」此前每调一次 begin 就清空共享失败计数，等于给了无限爆破 6 位码的口。现在 begin 只验不消费、不清零；已绑账号 begin 就要先验当前动态码（confirm 才消费时间片）

**中危**

- `users.key` 读不出来不再静默重建：库在而 key 没了/读不动 → 拒绝启动并明示恢复路径（此前重建等于永久销毁全部密封 token 和 TOTP 密钥）；新建走 `O_EXCL`，读到后顺手收敛 0600
- 客户端明文闸门堵拼写绕过：`http://` 和大写 `WS://` 同样算明文（此前只认字面 `ws://`）；register/totp/oauth 三处手写判断统一收进 `client.PlainCheck`
- **服务端整个 HTTP 口新增明文准入**：明文且非回环监听默认拒绝启动（密码/token 都在这条通道上跑）；确认内网/隧道部署设 `allow_plain_http: true`（`mcp.allow_plain_http` 同样算数）；回环监听照旧不受影响
- `/oauth/request`、`/oauth/result`、`/status` 补上机器 `agent_allow_ips` 检查——此前名单外的 token 持有者能领 SSH 凭据、还能占满机器 OAuth 待批槽；来源判定抽成 `agentIPAllowed` 一处共用
- OAuth 签发的一次性 SSH 凭据在用的时候复查账号停用状态和账号来源白名单（此前 grant 快速路径跳过这两项）
- **审批绑定收紧到完整上下文**：`machine+kind+detail+cwd+session+stdin/内容摘要`——同一个「同意」不能换个目录/换个 stdin/换个文件内容再复用；待批标记原子消费，一次批准并发也只能跑一趟
- 审批通知和 `towstrap-mcp pending` 打印剥控制字符：LLM 给的命令文本不能在别人终端上画假提示（SSH 广播、`wall`、桌面通知、confirm 弹窗同一道清洗）
- 命令策略匹配前先去引号归一：`r'm'`、`p"k"ill`、`-ex""ec` 这类拼写逃不出 ask/deny 名单
- 服务端→agent 的 ws 帧落实 256KiB 上限（超限断开），大数据改走 `data` 分片
- SSH 登录新增裸来源 IP 预算：换着用户名刷同一 IP 也累计锁定；三张失败表都有条目上限
- `/register*` 的每 IP 限速表加上限+清扫：乱喷来源刷不大内存
- **`install.sh`/`install-server.sh`/`install.ps1` 校验 fail-closed**：SHA256SUMS 拉不到、清单没有这行、机器没哈希工具都直接不装；显式 `--no-verify`/`-NoVerify` 可跳
- **Host 头注入堵住**：`installServerURL`/OAuth 回调推导用的 `r.Host` 过白名单字符集，脏 Host 退回监听地址——此前 `Host: x$(id)` 会让下发的安装脚本里藏进命令、`evil<b>` 混进落地页
- PTY 关闭按会话杀：交互 shell 后台 `job &` 这类独立进程组、同会话的幸存者不再漏杀（Linux 扫 /proc，macOS/BSD 走 pgrep -s；setsid 有意脱离的不追）。Windows 侧仍是 TerminateProcess+ConPTY 收尾，属已知差异

**审计「待验证」批次中已收紧的**

- 审计日志值不再能伪造字段：控制字符之外，值带空格/`=`/引号或为空时整值加引号——`user=evil admin=true` 这种一个值塞出第二个字段的写法失效
- Windows 路径冒号检查收紧：盘符以外再出现冒号一律拒——`C:\x\token::$DATA`、`file:stream` 这类 ADS/别名写法之前只查第一个冒号，漏查
- OAuth `redirect_uri` 不再被首次请求的 Host 钉死：改为每次请求现算（配了 `redirect_url`/`public_url` 照旧用配置值）——此前谁抢到进程里的第一次 `/oauth/begin`，谁的 Host 就成为所有人的回调域名
- `/status` 管理口令错试计入来源 IP 的锁定预算（与 SSH 登录共用），并记 `STATUS-DENY` 审计；锁定后回 429——此前管理口令可以被无限猜
- `towstrap-mcp` 在 `HOME` 未设置时不再把默认配置/批准目录落成 cwd 相对路径（cwd 可能是不可信目录，埋个 `mcp.yaml` 就被当操作员配置）；现在明确报错让用 `--config` 或写绝对路径
- `release.yml`：发布挂进 `release` 环境（可在仓库设置里加 reviewer / 把签名密钥挪进环境），并要求标签指向主干上的提交——此前任何人能推 v* 标签就能把私有分支代码发成签名产物

### 安全修复（第二轮复审批次）

**中危**

- **`deny_paths` 保护清单同步进命令通道**：`read_file` 明确拒掉的 `~/.aws/credentials`、`~/.config/towstrap/token` 这类凭据文件，此前一条 `cat` 命令零批准拿走——现在同一批路径模式直接进命令拒名单
- **stdin 过策略并进批准界面**：`run_command{command:"bash -s", stdin:"..."}` 此前批准界面只显示 `bash -s`、stdin 还绕过整个拒名单。现在 stdin 当第二份命令文本过 deny/ask，批准界面、通知、待批列表都带消毒过的预览（类型+长度+SHA-256 摘要+开头片段）
- **「记住的批准」按操作类型分桶**：批过一次 `run_command{bash -l}` 不再解锁同命令的 `terminal_open` 交互终端（终端后续按键不走命令策略，等于白名单被放大成任意命令通道）
- **OAuth 一次性授权会话进不了管理面**：`grant` 登录打上标记，`@machine token/add`、`@totp` 一律拒——15 分钟临时票不再能换长期 token 或绑走别人的验证器
- **远程系统类型探测失败不再静默放行**：`uname -s` 拿不到结果/认不出系统时直接报错重试，不再缓存「当大小写敏感处理」——此前 macOS 上探测一失败，`TOKEN` 这种大小写变体就能读走 token 文件且整会话缓存
- **UNC 路径在策略门前就拒**：`\\host\share`、`//host/share` 不再进远端解析——此前解析动作本身先触发 SMB/NTLM 认证，凭据在判定前就泄到攻击者主机
- **`towstrap-server init` 保留扁平配置写法**：见到顶层平铺的老格式（`http:`/`ssh:` 直接铺顶层）就把新键也写顶层，不再追加 `server:` 小节——此前追加后那些顶层键全部被 `server:` 段遮住静默失效（`tls`、`allow_ips`、`admin_token`、`users_db` 全丢）；`server:` 已存在而顶层还躺扁平键时打印提醒
- **agent 输出队列塞满不再拖死整机**：分发循环往满缓冲写时多了连接级取消口——客户端停读只丢自己的会话输出，机器不会变幽灵（此前吊销都踢不掉）
- **`mcp pending`/`towstrap-mcp pending` 输出消毒**：审批的机器名、命令、预览全过控制字符清洗——LLM 可控文本不能清管理员屏幕、伪造批准提示
- **SSH env 请求总量上限**：每条通道最多 128 个变量/64KiB，超限拒开会话——底层库在会话建立前无条件攒 env，没上限时一个通道能攒出十几 MB 常驻内存

**低危**

- `UseSSHGrant` 改条件更新原子扣减（`WHERE uses_left>0` + 影响行数判定）——并发下两张请求不再能分掉同一个最后次数
- `/token/refresh`、`/totp/*` 同样认 `oauth_only` 标记——此前只 `/register/machine` 和 SSH 面拦密码，这两个 HTTP 端点漏了
- 机器指纹入库前统一小写——`AA…`/`aa…` 大小写变体不再能绕过「一机一账号」；注册占坑的回滚只删自己插的行（并发败方不再错杀胜方绑定）
- 409 指纹冲突响应不再回带既有账号名——别想拿注册端点枚举已注册账号
- agent token 换发留 prev 兜底：服务端 401 拒收新 token 时回退旧 token 写回文件重试——换发半途失败（本地已写、服务端没提交）不再永久锁死
- 会话输出通道关闭即释放会话槽位，PTY 客户端断开不再泄漏配额
- Windows 路径拒 `PROGRA~1` 这类 `~数字` 短名段——8.3 别名不再能绕过保护清单的全名比对
- `towstrap-mcp` 的 `pending`/`approve`/`deny` 支持 `--approvals-dir`，批准通知里的非默认目录能直接用
- `MergeServer` 补上 `AllowPlainHTTP` 透传——文件里开的明文确认不再被合并丢掉
- 远端路径解析结果校验收紧：空输出、带换行、非绝对路径一律拒；POSIX 侧 `//x` 归一成 `/x`（直接挂在 `/` 下的保护文件不再因双斜杠逃逸对比）
- `examples/nginx.conf` 头注写明反代代价：代理后服务端只见 `127.0.0.1`，`agent_allow_ips`/登录限速的按 IP 配额坍缩成同一个桶

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
