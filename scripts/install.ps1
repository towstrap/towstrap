# TowStrap agent 一键安装（Windows）。
#
#   powershell -ExecutionPolicy Bypass -File install.ps1 -Token tsa-xxx
#
# 或一条命令（地址由服务器下发时已填好）：
#   powershell -Command "& { $(irm https://<服务器>/install.ps1) } -Token tsa-xxx"
#
# 从 GitHub raw 拉的脚本默认指向官方服务器；自建用 -Server 换地址。
param(
    [string]$Token  = $env:TOWSTRAP_AGENT_TOKEN,
    [string]$Server = $(if ($env:TOWSTRAP_SERVER) { $env:TOWSTRAP_SERVER } else { "__TOWSTRAP_DEFAULT_SERVER__" }),
    [string]$Version = "__TOWSTRAP_DEFAULT_VERSION__",
    [string]$Prefix = "$env:LOCALAPPDATA\TowStrap",
    [switch]$NoVerify
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
if (-not $Token) { Die "没有 agent token：加 -Token tsa-xxx，或设 TOWSTRAP_AGENT_TOKEN" }

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
        $sums = (Invoke-WebRequest -UseBasicParsing "$relbase/SHA256SUMS").Content
    } catch { Remove-Item $tmpExe -Force; Die "拉不到 SHA256SUMS，校验过不了就不装；要跳过加 -NoVerify" }
    $want = ($sums -split "`n" | Where-Object { $_ -match " $asset`$" } | ForEach-Object { ($_ -split "\s+")[0] })
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
    Set-Content -Path $tokenfile -Value $Token -Encoding ascii -NoNewline
    Write-Host ">> token 写入 $tokenfile（用户目录内，仅此账号可读）"
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

if ($wasTask) {
    schtasks /run /tn towstrap 2>$null | Out-Null
    Write-Host ">> 计划任务 towstrap 已重新拉起，新版本生效"
}
if ($wasManual) {
    Write-Host ">> 注意：之前手工跑的 towstrap 进程已停，用下面的命令重启它"
}
Write-Host ""
Write-Host "完成。跑起来："
Write-Host "  & `"$exe`" --config `"$agentyaml`""
Write-Host "要开机自启可以注册计划任务（示例，按需调整）："
Write-Host "  schtasks /create /tn towstrap /sc onlogon /rl limited /tr `"`"$exe`" --config `"`"$agentyaml`"`"`""
Write-Host ""
Write-Host "远程进这台机器（标准 SSH 直连）："
Write-Host "  ssh -p $SshPort <账号名>@$sshhost"
Write-Host "（账号名 = 管理员给你发 token 的账号）"
