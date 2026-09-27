# TowStrap agent 一键安装（Windows）。
#
#   powershell -ExecutionPolicy Bypass -File install.ps1 -Token tsa-xxx
#
# 或一条命令（地址由服务器下发时已填好）。全程没有双引号，
# cmd 和 PowerShell 粘贴都安全（powershell -Command 会剥双引号，
# "$(irm)" 那种写法在 PowerShell 里会先被外层展开、再被剥引号弄坏）：
#   powershell -Command "& ([scriptblock]::Create((irm https://<服务器>/install.ps1))) -Token tsa-xxx"
# 已在 PowerShell 里的话去掉 powershell -Command "…" 直接跑 & (…) 那段。
#
# 从 GitHub raw 拉的脚本默认指向官方服务器；自建用 -Server 换地址。
param(
    [string]$Token  = $env:TOWSTRAP_AGENT_TOKEN,
    [string]$Server = $(if ($env:TOWSTRAP_SERVER) { $env:TOWSTRAP_SERVER } else { "__TOWSTRAP_DEFAULT_SERVER__" }),
    [string]$Version = "__TOWSTRAP_DEFAULT_VERSION__",
    [string]$Prefix = "$env:LOCALAPPDATA\TowStrap",
    [switch]$NoVerify,
    [switch]$NoService,
    # 装完不问「现在注册吗」（默认有控制台就问，一条命令直通在线；
    # -NonInteractive / 无人值守自动跳过）
    [switch]$NoPrompt,
    # 发行签名公钥（minisign）：设了就强验 SHA256SUMS.minisig（需要本机
    # 有 minisign.exe）。也可用环境变量 TOWSTRAP_MINISIGN_PUB。
    [string]$MinisignPub = $(if ($env:TOWSTRAP_MINISIGN_PUB) { $env:TOWSTRAP_MINISIGN_PUB } else { "RWTbpo7F0knbUQIoW3pAhERl7E/Uh2YKlQu+3Cwjadh0Clz6A4BEA746" })
)
$ErrorActionPreference = "Stop"

function Die($msg) { Write-Host "install.ps1: $msg" -ForegroundColor Red; exit 1 }

# 占位符由服务器端下发时替换成那台服务器的地址；从 GitHub 拉的保持原样，
# 落到这里的官方默认。
$OfficialServer = "wss://towstrap.vast-plan.com"
# 注意：占位符是全文件替换，检测只能看 "__TOWSTRAP" 前缀，写完整占位符
# 名会让模式也被换掉、把注入的真值误判成"未替换"然后重置掉。
if ($Server -like "*__TOWSTRAP*") { $Server = $OfficialServer }
# 版本占位符：服务器下发时填成那台的 release tag；GitHub 直拉回落 latest。
if ($Version -like "*__TOWSTRAP*") { $Version = "latest" }
# agent.yaml 预设：服务器下发时填 server.yaml 里 agent_defaults: 的内容；
# GitHub 直拉的按无预设处理。
# 注意：占位符是全文件替换，检测只能看 "__TOWSTRAP" 前缀，写完整占位符
# 名会让模式也被换掉、把注入的值误判成未替换。
$AgentConf = "__TOWSTRAP_AGENT_CONFIG__"
if ($AgentConf -like "*__TOWSTRAP*") { $AgentConf = "" }
# SSH 端口：服务器下发时填那台配置的 SSH 口；GitHub 直拉回落默认 7822。
$SshPort = "__TOWSTRAP_SSH_PORT__"
if ($SshPort -like "*__TOWSTRAP*") { $SshPort = "7822" }
if ($Server -eq "") {
    Die "没有服务器地址：加 -Server wss://主机:端口，或设 TOWSTRAP_SERVER（从服务器 /install.ps1 拉的脚本会自动带上）"
}
# token 允许为空：服务器开自助注册时落地页的命令不带 -Token——
# 装完跑 towstrap register 交互建号，token 由它写进同一位置。
$haveToken = [bool]$Token

$arch = switch ($env:PROCESSOR_ARCHITECTURE) { "ARM64" { "arm64" } default { "amd64" } }
if ($Version -eq "latest") {
    $relbase = "https://github.com/towstrap/towstrap/releases/latest/download"
} else {
    $relbase = "https://github.com/towstrap/towstrap/releases/download/$Version"
}
$asset = "towstrap-windows-$arch.exe"

New-Item -ItemType Directory -Force -Path $Prefix | Out-Null
$exe = Join-Path $Prefix "towstrap.exe"
$tmpExe = "$exe.download"

Write-Host ">> 下载 $asset（$Version）"
try {
    Invoke-WebRequest -UseBasicParsing "$relbase/$asset" -OutFile $tmpExe
} catch {
    # 旧版本发布资产名是 towstrap-agent-windows-<arch>.exe
    $asset = "towstrap-agent-windows-$arch.exe"
    Write-Host ">> 试旧资产名 $asset"
    Invoke-WebRequest -UseBasicParsing "$relbase/$asset" -OutFile $tmpExe
}
# 校验是硬门槛：拉不到清单/清单没这行都算不过；实在要跳过得显式 -NoVerify。
if ($NoVerify) {
    Write-Host ">> -NoVerify：跳过 SHA256 校验（不推荐）"
} else {
    try {
        $raw = (Invoke-WebRequest -UseBasicParsing "$relbase/SHA256SUMS").Content
        # GitHub Releases 拿 application/octet-stream 回清单：Windows
        # PowerShell 5.1 里 .Content 是 byte[] 不是 string，直接 -split
        # 一行都对不上。显式按 UTF-8 解码。
        $sums = if ($raw -is [byte[]]) { [Text.Encoding]::UTF8.GetString($raw) } else { [string]$raw }
    } catch { Remove-Item $tmpExe -Force; Die "拉不到 SHA256SUMS，校验过不了就不装；要跳过加 -NoVerify" }
    if ($MinisignPub) {
        # 签名是独立信任根：清单和二进制同出一个 Release，光核 SHA256
        # 挡不住整个 Release 被换。本机没 minisign 降级成警告——装好后的
        # towstrap update 走内置验签，不受影响。
        if (Get-Command minisign -ErrorAction SilentlyContinue) {
            # minisign -m 要指到真实文件，签名自动找同名 .minisig——把已拉的
            # 清单落到临时文件一起验，避免再发一次请求（少一次被篡改的机会）。
            $sumsFile = "$tmpExe.SHA256SUMS"
            [IO.File]::WriteAllText($sumsFile, $sums)
            try {
                Invoke-WebRequest -UseBasicParsing "$relbase/SHA256SUMS.minisig" -OutFile "$sumsFile.minisig"
            } catch { Remove-Item $tmpExe -Force; Die "拉不到 SHA256SUMS.minisig，签名校验过不了就不装；要跳过加 -NoVerify" }
            & minisign -V -P $MinisignPub -m $sumsFile | Out-Null
            if ($LASTEXITCODE -ne 0) { Remove-Item $tmpExe -Force; Die "SHA256SUMS 签名校验失败——清单可能被换过，拒绝安装" }
            Write-Host ">> minisign 签名校验通过"
        } else {
            Write-Host ">> 警告：系统没有 minisign，跳过签名校验（winget/scoop 装一个可开启；SHA256 照验）"
        }
    }
    $want = ($sums -split "`r?`n" | Where-Object { $_ -match " $asset\s*$" } | ForEach-Object { ($_ -split "\s+")[0] })
    if (-not $want) { Remove-Item $tmpExe -Force; Die "SHA256SUMS 里没有 $asset 这一行；要跳过加 -NoVerify" }
    $got = (Get-FileHash $tmpExe -Algorithm SHA256).Hash.ToLower()
    if ($got -ne $want.Trim().ToLower()) { Remove-Item $tmpExe -Force; Die "SHA256 校验失败" }
    Write-Host ">> SHA256 校验通过"
}
# 升级重装时 exe 可能在跑（计划任务或手工启动）——Windows 锁运行中的
# 可执行文件，直接覆盖会失败。先停下来装完再视情况拉回来。
$wasTask = $false
$wasManual = $false
if (Get-Process towstrap -ErrorAction SilentlyContinue) {
    $hasTask = $false
    try { schtasks /query /tn towstrap 2>$null | Out-Null; $hasTask = ($LASTEXITCODE -eq 0) } catch {}
    if ($hasTask) {
        schtasks /end /tn towstrap 2>$null | Out-Null
        $wasTask = $true
        Write-Host ">> 计划任务 towstrap 已停（升级覆盖用）"
    } else {
        Stop-Process -Name towstrap -Force
        $wasManual = $true
        Write-Host ">> 正在运行的 towstrap 已停（升级覆盖用）"
    }
}
Move-Item -Force $tmpExe $exe
Write-Host ">> 已装到 $exe"

$tokenfile = Join-Path $Prefix "agent-token"
if (-not (Test-Path $tokenfile)) {
    if ($haveToken) {
        Set-Content -Path $tokenfile -Value $Token -Encoding ascii -NoNewline
        Write-Host ">> token 写入 $tokenfile（用户目录内，仅此账号可读）"
    } else {
        Write-Host ">> 未提供 token：跳过写 $tokenfile（自助注册由 towstrap register 补齐）"
    }
} else {
    Write-Host ">> $tokenfile 已存在，没动它"
}

$agentyaml = Join-Path $Prefix "agent.yaml"
if (-not (Test-Path $agentyaml)) {
    $cfg = "server: $Server`nagent_token_file: $tokenfile"
    if ($AgentConf) {
        $cfg += "`n" + $AgentConf
        Write-Host ">> 附带服务器预设的 agent 配置"
    }
    Set-Content -Path $agentyaml -Value $cfg -Encoding utf8
    Write-Host ">> 配置写入 $agentyaml"
} else {
    Write-Host ">> $agentyaml 已存在，没动它"
}

# SSH 登录提示：主机从 -Server 推导，端口是下发服务器配置的 SSH 口。
$sshhost = ([uri]$Server).Host

$svcStarted = $false
if ($wasTask) {
    schtasks /run /tn towstrap 2>$null | Out-Null
    $svcStarted = ($LASTEXITCODE -eq 0)
    Write-Host ">> 计划任务 towstrap 已重新拉起，新版本生效"
}
if ($wasManual) {
    Write-Host ">> 注意：之前手工跑的 towstrap 进程已停，用下面的命令重启它"
}

# 常驻默认开：注册「登录自起」的计划任务（-NoService 退出）。
# 已存在的不动（wasTask 分支已经把升级重启做了）；新建的现在有凭据就拉起，
# 没凭据等 register 写完 token 后下次登录自然生效。
if (-not $NoService) {
    $taskExists = $false
    try { schtasks /query /tn towstrap 2>$null | Out-Null; $taskExists = ($LASTEXITCODE -eq 0) } catch {}
    if (-not $taskExists) {
        schtasks /create /tn towstrap /sc onlogon /rl limited /f /tr "`"$exe`" --config `"$agentyaml`"" | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $taskExists = $true
            Write-Host ">> 计划任务 towstrap 已注册（每次登录自起）"
        } else {
            Write-Host ">> 计划任务注册失败；手动补：schtasks /create /tn towstrap /sc onlogon /rl limited /tr `"`"$exe`" --config `"`"$agentyaml`"`""
        }
    }
    if ($taskExists -and -not $wasTask -and ($haveToken -or (Test-Path $tokenfile))) {
        schtasks /run /tn towstrap 2>$null | Out-Null
        $svcStarted = ($LASTEXITCODE -eq 0)
        Write-Host ">> 计划任务 towstrap 已拉起（查状态：& `"$exe`" status）"
    }
} else {
    Write-Host ">> -NoService：没注册计划任务，手动跑：& `"$exe`" --config `"$agentyaml`""
}

# ---- 交互收尾：就地注册→拉起服务，一条命令直通在线 ----
# Read-Host 走控制台不走 stdin，irm 管道进来也能问；-NonInteractive /
# 无人值守下 Read-Host 直接抛，catch 掉等于选默认跳过。
$canPrompt = -not $NoPrompt -and [Environment]::UserInteractive
function _AskYN([string]$q) {
    try { return ((Read-Host "$q [Y/n]") -notmatch '^[nN]') } catch { return $false }
}
if ($canPrompt) {
    $noTok = (-not (Test-Path $tokenfile)) -or ((Get-Item $tokenfile).Length -eq 0)
    if ($noTok) {
        Write-Host ""
        if (_AskYN "现在跑注册向导，把这台机器挂上账号（建号/登录都行）") {
            # --server 必带：register 不读 agent.yaml，不给会打去官方服务器。
            # 注册成功后它自己会把已建未起的计划任务拉起。
            & $exe register --server $Server
        }
    }
    $haveTok = (Test-Path $tokenfile) -and ((Get-Item $tokenfile).Length -gt 0)
    if ($haveTok) {
        # register 已经把任务拉起来的话别重复问——看进程在不在。
        if (-not $svcStarted -and (Get-Process towstrap -ErrorAction SilentlyContinue)) { $svcStarted = $true }
        if ($NoService) {
            if (_AskYN "把 towstrap 注册成「登录自起」常驻任务") {
                & $exe service install --config $agentyaml
            }
        } elseif ($taskExists -and -not $svcStarted) {
            # 任务建了但注册前没凭据没拉；register 的拉起兜底失败时这里接住
            if (_AskYN "凭据就位——现在拉起 towstrap 上线") {
                schtasks /run /tn towstrap | Out-Null
                Write-Host ">> towstrap 已拉起（查状态：& `"$exe`" status）"
            }
        }
    }
}
Write-Host ""
if (-not $haveToken -and -not (Test-Path $tokenfile)) {
    Write-Host "完成（未提供 token）。下一步建号拿凭据："
    Write-Host "  & `"$exe`" register --server $Server   # 服务器开了自助注册时"
    Write-Host "或把管理员签发的 token 写入 $tokenfile 后直接跑："
    Write-Host "  & `"$exe`" --config `"$agentyaml`""
} else {
    Write-Host "完成。跑起来："
    Write-Host "  & `"$exe`" --config `"$agentyaml`""
}
Write-Host ""
Write-Host "远程进这台机器（标准 SSH 直连）："
Write-Host "  ssh -p $SshPort <账号名>@$sshhost"
Write-Host "（账号名 = 管理员给你发 token 的账号）"
