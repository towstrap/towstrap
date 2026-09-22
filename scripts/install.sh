#!/bin/sh
# TowStrap agent 一键安装（Linux / macOS）。
#
#   curl -fsSL https://<服务器>/install.sh | sh -s -- --token tsa-xxx
#
# 服务器端 /install.sh 下发时地址已自动填好；从 GitHub raw 拉的脚本
# 需要 --server 或环境变量 TOWSTRAP_SERVER。Windows 用 install.ps1。
set -eu

# __TOWSTRAP_DEFAULT_SERVER__ 由服务器端下发时替换；从 GitHub 拉的保持原样。
DEFAULT_SERVER="__TOWSTRAP_DEFAULT_SERVER__"

VERSION="latest"
PREFIX=""
TOKEN="${TOWSTRAP_AGENT_TOKEN:-}"
SERVER="${TOWSTRAP_SERVER:-$DEFAULT_SERVER}"
SYSTEMD=0

usage() {
	cat <<'EOF'
用法: install.sh --token tsa-xxx [选项]
  --token tsa-...    agent token（machine add 时打印的那个；也可用环境变量 TOWSTRAP_AGENT_TOKEN）
  --server wss://..  服务器地址（也可用 TOWSTRAP_SERVER；从服务器拉脚本时已填好）
  --version vX.Y.Z   版本，默认 latest
  --prefix 目录      安装目录，默认 /usr/local/bin（可写）或 ~/.local/bin
  --systemd          装 systemd 服务：root 跑建 towstrap 用户 + 系统单元并启动；
                     普通用户建 ~/.config/systemd/user 单元（需自己 enable）
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
	-h|--help) usage; exit 0 ;;
	*) die "未知参数 $1（--help 看用法）" ;;
	esac
done

case "$SERVER" in
"" | *__TOWSTRAP_DEFAULT_SERVER__*)
	die "没有服务器地址：加 --server wss://主机:端口，或设 TOWSTRAP_SERVER（从服务器 /install.sh 拉取的脚本会自动带上）" ;;
esac
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
asset="towstrap-agent-$os-$arch"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo ">> 下载 $asset（$VERSION）"
curl -fsSL "$relbase/$asset" -o "$tmp/$asset" || die "下载失败：$relbase/$asset"
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
	install -m 0755 "$tmp/$asset" "$PREFIX/towstrap-agent"
else
	command -v sudo >/dev/null 2>&1 || die "没有写 $PREFIX 的权限，也没有 sudo；加 --prefix 换个目录"
	sudo install -m 0755 "$tmp/$asset" "$PREFIX/towstrap-agent"
fi
echo ">> 已装到 $PREFIX/towstrap-agent"

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
	chmod 600 "$agentyaml"
	echo ">> 配置写入 $agentyaml"
else
	echo ">> $agentyaml 已存在，没动它"
fi

if [ "$SYSTEMD" = 1 ]; then
	if ! command -v systemctl >/dev/null 2>&1; then
		die "--systemd 需要 systemctl"
	fi
	if [ "$(id -u)" = 0 ]; then
		id -u towstrap >/dev/null 2>&1 || useradd -r -m -s /bin/bash towstrap
		chown -R towstrap:towstrap "$confdir"
		cat >/etc/systemd/system/towstrap-agent.service <<EOF
[Unit]
Description=towstrap agent
After=network-online.target
Wants=network-online.target

[Service]
User=towstrap
Group=towstrap
ExecStart=$PREFIX/towstrap-agent --config $agentyaml
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=true

[Install]
WantedBy=multi-user.target
EOF
		systemctl daemon-reload
		systemctl enable --now towstrap-agent
		echo ">> systemd 服务 towstrap-agent 已启动（journalctl -u towstrap-agent 看日志）"
	else
		mkdir -p "$HOME/.config/systemd/user"
		cat >"$HOME/.config/systemd/user/towstrap-agent.service" <<EOF
[Unit]
Description=towstrap agent
After=network-online.target

[Service]
ExecStart=$PREFIX/towstrap-agent --config $agentyaml
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF
		systemctl --user daemon-reload 2>/dev/null || true
		systemctl --user enable --now towstrap-agent 2>/dev/null &&
			echo ">> 用户级服务 towstrap-agent 已启动" ||
			echo ">> 单元已写好（~/.config/systemd/user/towstrap-agent.service），enable 失败的话手工: systemctl --user enable --now towstrap-agent"
	fi
fi

echo ""
echo "完成。没装服务的话这样跑："
echo "  towstrap-agent --config $agentyaml"
echo "或直接用旗标："
echo "  towstrap-agent --server $SERVER --agent-token-file $tokenfile"
