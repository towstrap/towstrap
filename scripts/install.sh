#!/bin/sh
# TowStrap agent 一键安装（Linux / macOS）。
#
#   curl -fsSL https://<服务器>/install.sh | sh -s -- --token tsa-xxx
#
# 服务器端 /install.sh 下发时地址已自动填好；从 GitHub raw 拉的脚本
# 默认指向官方服务器，自建用 --server 或环境变量 TOWSTRAP_SERVER 换地址。
# Windows 用 install.ps1。
set -eu

# 占位符由服务器端下发时替换成那台服务器的地址；从 GitHub 拉的保持原样，
# 落到下面的官方默认。
DEFAULT_SERVER="__TOWSTRAP_DEFAULT_SERVER__"
OFFICIAL_SERVER="wss://towstrap.vast-plan.com"

# 版本占位符：服务器下发时填成那台的 release tag（装同版本 agent）；
# GitHub 直拉的保持原样，运行时回落 latest。--version 可覆盖。
VERSION="__TOWSTRAP_DEFAULT_VERSION__"

# agent.yaml 预设占位符：服务器下发时填 server.yaml 里 agent_defaults:
# 的内容（烤进新装的 agent.yaml）；GitHub 直拉的保持原样，按无预设处理。
AGENT_CONF="__TOWSTRAP_AGENT_CONFIG__"

# SSH 端口占位符：服务器下发时填那台配置的 SSH 端口；GitHub 直拉的
# 保持原样，回落默认 7822。
SSH_PORT="__TOWSTRAP_SSH_PORT__"
PREFIX=""
TOKEN="${TOWSTRAP_AGENT_TOKEN:-}"
SERVER="${TOWSTRAP_SERVER:-$DEFAULT_SERVER}"
SYSTEMD=0
CHECK=0

usage() {
	cat <<'EOF'
用法: install.sh --token tsa-xxx [选项]
  --token tsa-...    agent token（machine add 时打印的那个；也可用环境变量 TOWSTRAP_AGENT_TOKEN）
  --server wss://..  服务器地址（也可用 TOWSTRAP_SERVER；默认官方服务器）
  --version vX.Y.Z   版本，默认与下发服务器同版本（GitHub 直拉时 latest）
  --prefix 目录      安装目录，默认 /usr/local/bin（可写）或 ~/.local/bin
  --systemd          装 systemd 服务：root 跑建 towstrap 用户 + 系统单元并启动；
                     普通用户建 ~/.config/systemd/user 单元（需自己 enable）
  --check            干跑：打印解析出的服务器/版本/SSH 地址后退出（不安装）
  -h, --help
EOF
}

die() { echo "install.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
	case "$1" in
	--token) TOKEN="${2:-}"; shift 2 ;;
	--server) SERVER="${2:-}"; shift 2 ;;
	--version) VERSION="${2:-}"; shift 2 ;;
	--prefix) PREFIX="${2:-}"; shift 2 ;;
	--systemd) SYSTEMD=1; shift ;;
	--check) CHECK=1; shift ;;
	-h|--help) usage; exit 0 ;;
	*) die "未知参数 $1（--help 看用法）" ;;
	esac
done

# 注意：服务器下发时占位符是全文件替换——下面几个检测只能匹配
# "__TOWSTRAP" 前缀本身，不能写完整占位符名（否则模式也被换掉，
# 会把注入的真值误判成"未替换"然后重置掉）。
case "$SERVER" in
*__TOWSTRAP*) SERVER="$OFFICIAL_SERVER" ;;
"") die "没有服务器地址：加 --server wss://主机:端口，或设 TOWSTRAP_SERVER（从服务器 /install.sh 拉取的脚本会自动带上）" ;;
esac
case "$VERSION" in *__TOWSTRAP*) VERSION=latest ;; esac
case "$AGENT_CONF" in *__TOWSTRAP*) AGENT_CONF="" ;; esac
case "$SSH_PORT" in *__TOWSTRAP*) SSH_PORT=7822 ;; esac

# SSH 提示用的主机名从 $SERVER 推导：跟 --server/环境变量覆盖走，
# 服务器下发和 GitHub 直拉两条路都正确。IPv6 用方括号形式。
sshhost=${SERVER#wss://}
sshhost=${sshhost#ws://}
sshhost=${sshhost%%/*}
case "$sshhost" in
\[*\]*) sshhost="${sshhost#\[}"; sshhost="${sshhost%%\]*}" ;;
*) sshhost="${sshhost%%:*}" ;;
esac

# --check 干跑：只打印解析结果，不下载不安装（回归测试和管理员调试用）
if [ "$CHECK" = 1 ]; then
	printf 'server=%s\nversion=%s\nssh_port=%s\nssh_host=%s\nagent_conf=%s\n' \
		"$SERVER" "$VERSION" "$SSH_PORT" "$sshhost" "$AGENT_CONF"
	exit 0
fi
[ -n "$TOKEN" ] || die "没有 agent token：加 --token tsa-xxx，或设 TOWSTRAP_AGENT_TOKEN"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in linux | darwin) ;; *) die "不支持的系统 $os（Windows 用 install.ps1）" ;; esac
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
arm64 | aarch64) arch=arm64 ;;
*) die "不支持的架构 $(uname -m)" ;;
esac

if [ "$VERSION" = latest ]; then
	relbase="https://github.com/towstrap/towstrap/releases/latest/download"
else
	relbase="https://github.com/towstrap/towstrap/releases/download/$VERSION"
fi
asset="towstrap-$os-$arch"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo ">> 下载 $asset（$VERSION）"
if ! curl -fsSL "$relbase/$asset" -o "$tmp/$asset"; then
	# 旧版本发布资产名是 towstrap-agent-<os>-<arch>
	asset="towstrap-agent-$os-$arch"
	echo ">> 试旧资产名 $asset"
	curl -fsSL "$relbase/$asset" -o "$tmp/$asset" || die "下载失败：$relbase/{towstrap,towstrap-agent}-$os-$arch"
fi
if curl -fsSL "$relbase/SHA256SUMS" -o "$tmp/SHA256SUMS" 2>/dev/null; then
	if command -v shasum >/dev/null 2>&1; then
		(cd "$tmp" && grep " $asset\$" SHA256SUMS | shasum -a 256 -c -) || die "SHA256 校验失败"
	elif command -v sha256sum >/dev/null 2>&1; then
		(cd "$tmp" && grep " $asset\$" SHA256SUMS | sha256sum -c -) || die "SHA256 校验失败"
	else
		echo ">> 没有 shasum/sha256sum，跳过校验（不建议）"
	fi
else
	echo ">> 拉不到 SHA256SUMS，跳过校验（不建议）"
fi

if [ -z "$PREFIX" ]; then
	if [ -w /usr/local/bin ]; then
		PREFIX=/usr/local/bin
	else
		PREFIX="$HOME/.local/bin"
	fi
fi
mkdir -p "$PREFIX"
if [ -w "$PREFIX" ]; then
	install -m 0755 "$tmp/$asset" "$PREFIX/towstrap"
else
	command -v sudo >/dev/null 2>&1 || die "没有写 $PREFIX 的权限，也没有 sudo；加 --prefix 换个目录"
	sudo install -m 0755 "$tmp/$asset" "$PREFIX/towstrap"
fi
echo ">> 已装到 $PREFIX/towstrap"

# 旧版本叫 towstrap-agent，可能还留着：是个普通文件就提醒一下
if [ -e "$PREFIX/towstrap-agent" ] && [ ! -L "$PREFIX/towstrap-agent" ]; then
	echo ">> 提示：$PREFIX/towstrap-agent 是旧名二进制，新名是 towstrap；确认没引用后可删"
	if [ "$SYSTEMD" != 1 ] && command -v systemctl >/dev/null 2>&1 &&
		{ systemctl is-active --quiet towstrap-agent 2>/dev/null || systemctl --user is-active --quiet towstrap-agent 2>/dev/null; }; then
		echo ">> 注意：旧服务 towstrap-agent 还在跑旧二进制；加 --systemd 重跑本脚本会换成新服务 towstrap"
	fi
fi

# 短命令 mirror → towstrap（busybox 式：按调用名直接进 mirror 子命令）。
# 已存在且不是指向本程序的软链就不动，免得踩掉别人叫 mirror 的东西。
# -L 单独判：失效软链 -e 为假，也不能当成空位直接覆盖。
linkmirror=1
if [ -e "$PREFIX/mirror" ] || [ -L "$PREFIX/mirror" ]; then
	case "$(readlink "$PREFIX/mirror" 2>/dev/null || true)" in
	towstrap | towstrap-agent) ;; # 我们自己的软链（新老名字），覆盖之
	*) linkmirror=0 ;;
	esac
fi
if [ "$linkmirror" = 1 ]; then
	if [ -w "$PREFIX" ]; then
		ln -sfn towstrap "$PREFIX/mirror"
	else
		sudo ln -sfn towstrap "$PREFIX/mirror"
	fi
	echo ">> 短命令已就位：mirror（等价 towstrap mirror，如 mirror ls / mirror work）"
else
	echo ">> $PREFIX/mirror 已被占用且不是本程序的软链，跳过（仍可用 towstrap mirror ...）"
fi

# 老版本装过的 tui 软链会指向新二进制但落到不存在的 tui 子命令——是我们建的
# 就顺手清掉（指向别处的 tui 不动）。
case "$(readlink "$PREFIX/tui" 2>/dev/null || true)" in
towstrap | towstrap-agent)
	if [ -w "$PREFIX" ]; then rm -f "$PREFIX/tui"; else sudo rm -f "$PREFIX/tui"; fi
	echo ">> 已清掉旧版遗留的 $PREFIX/tui 软链（该命令改名 mirror）"
	;;
esac

# token 文件和配置：root 进 /etc/towstrap，普通用户进 ~/.config/towstrap
if [ "$(id -u)" = 0 ]; then
	confdir=/etc/towstrap
else
	confdir="${XDG_CONFIG_HOME:-$HOME/.config}/towstrap"
fi
mkdir -p "$confdir"
chmod 700 "$confdir"
tokenfile="$confdir/agent-token"
if [ ! -f "$tokenfile" ]; then
	printf '%s\n' "$TOKEN" >"$tokenfile"
	chmod 600 "$tokenfile"
	echo ">> token 写入 $tokenfile（0600，token refresh 能远程换发）"
else
	echo ">> $tokenfile 已存在，没动它（要换 token 请手工写或等 token refresh）"
fi

agentyaml="$confdir/agent.yaml"
if [ ! -f "$agentyaml" ]; then
	cat >"$agentyaml" <<EOF
server: $SERVER
agent_token_file: $tokenfile
EOF
	if [ -n "$AGENT_CONF" ]; then
		printf '%s\n' "$AGENT_CONF" >>"$agentyaml"
		echo ">> 附带服务器预设的 agent 配置"
	fi
	chmod 600 "$agentyaml"
	echo ">> 配置写入 $agentyaml"
else
	echo ">> $agentyaml 已存在，没动它"
fi

if [ "$SYSTEMD" = 1 ]; then
	if ! command -v systemctl >/dev/null 2>&1; then
		die "--systemd 需要 systemctl"
	fi
	# 旧版本的单元叫 towstrap-agent：不停掉它，新旧两个 agent 拿同一个
	# token 连服务器会互相顶替（AGENT-REPLACE 刷屏）。只处理本脚本写的那份。
	if [ "$(id -u)" = 0 ]; then
		oldunit=/etc/systemd/system/towstrap-agent.service
		sysctl="systemctl"
	else
		oldunit="$HOME/.config/systemd/user/towstrap-agent.service"
		sysctl="systemctl --user"
	fi
	if [ -f "$oldunit" ] && grep -q '^Description=towstrap agent' "$oldunit"; then
		$sysctl disable --now towstrap-agent 2>/dev/null || true
		rm -f "$oldunit"
		$sysctl daemon-reload 2>/dev/null || true
		echo ">> 旧服务 towstrap-agent 已停用并移除（改名为 towstrap）"
	fi
	if [ "$(id -u)" = 0 ]; then
		id -u towstrap >/dev/null 2>&1 || useradd -r -m -s /bin/bash towstrap
		chown -R towstrap:towstrap "$confdir"
		cat >/etc/systemd/system/towstrap.service <<EOF
[Unit]
Description=towstrap agent
After=network-online.target
Wants=network-online.target

[Service]
User=towstrap
Group=towstrap
ExecStart=$PREFIX/towstrap --config $agentyaml
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=true

[Install]
WantedBy=multi-user.target
EOF
		systemctl daemon-reload
		systemctl enable --now towstrap
		echo ">> systemd 服务 towstrap 已启动（journalctl -u towstrap 看日志）"
	else
		mkdir -p "$HOME/.config/systemd/user"
		cat >"$HOME/.config/systemd/user/towstrap.service" <<EOF
[Unit]
Description=towstrap agent
After=network-online.target

[Service]
ExecStart=$PREFIX/towstrap --config $agentyaml
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF
		systemctl --user daemon-reload 2>/dev/null || true
		systemctl --user enable --now towstrap 2>/dev/null &&
			echo ">> 用户级服务 towstrap 已启动" ||
			echo ">> 单元已写好（~/.config/systemd/user/towstrap.service），enable 失败的话手工: systemctl --user enable --now towstrap"
	fi
fi

echo ""
echo "完成。没装服务的话这样跑："
echo "  towstrap --config $agentyaml"
echo "或直接用旗标："
echo "  towstrap --server $SERVER --agent-token-file $tokenfile"
echo ""
echo "远程进这台机器（标准 SSH 直连）："
echo "  ssh -p $SSH_PORT <账号名>@$sshhost"
echo "（账号名 = 管理员给你发 token 的账号；进可接力终端：ssh -t -p $SSH_PORT <账号名>@$sshhost 'mirror 名字'）"
