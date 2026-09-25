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
    [string]$Prefix = "$env:LOCALAPPDATA\TowStrap"
)
$ErrorActionPreference = "Stop"

function Die($msg) { Write-Host "install.ps1: $msg" -ForegroundColor Red; exit 1 }

# 占位符由服务器端下发时替换成那台服务器的地址；从 GitHub 拉的保持原样，
# 落到这里的官方默认。
$OfficialServer = "wss://towstrap.vast-plan.com"
if ($Server -like "*__TOWSTRAP_DEFAULT_SERVER__*") { $Server = $OfficialServer }
# 版本占位符：服务器下发时填成那台的 release tag；GitHub 直拉回落 latest。
if ($Version -like "*__TOWSTRAP_DEFAULT_VERSION__*") { $Version = "latest" }
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
try {
    $sums = (Invoke-WebRequest -UseBasicParsing "$relbase/SHA256SUMS").Content
    $want = ($sums -split "`n" | Where-Object { $_ -match " $asset`$" } | ForEach-Object { ($_ -split "\s+")[0] })
    if ($want) {
        $got = (Get-FileHash $tmpExe -Algorithm SHA256).Hash.ToLower()
        if ($got -ne $want.Trim().ToLower()) { Remove-Item $tmpExe -Force; Die "SHA256 校验失败" }
        Write-Host ">> SHA256 校验通过"
    }
} catch { Write-Host ">> 拉不到 SHA256SUMS，跳过校验（不建议）" }
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
    Set-Content -Path $agentyaml -Value "server: $Server`nagent_token_file: $tokenfile" -Encoding utf8
    Write-Host ">> 配置写入 $agentyaml"
} else {
    Write-Host ">> $agentyaml 已存在，没动它"
}

Write-Host ""
Write-Host "完成。跑起来："
Write-Host "  & `"$exe`" --config `"$agentyaml`""
Write-Host "要开机自启可以注册计划任务（示例，按需调整）："
Write-Host "  schtasks /create /tn towstrap /sc onlogon /rl limited /tr `"`"$exe`" --config `"`"$agentyaml`"`"`""
