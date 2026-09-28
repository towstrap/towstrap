#!/bin/sh
# TowStrap MCP 客户端一键接入（Linux / macOS）——给跑 AI 编码助手的机器用：
# 装 towstrap-mcp 二进制，并把 MCP 接入写进检测到的各家 harness 配置文件
# （Claude Code / Codex / Grok / Cursor / Gemini / OpenCode / Copilot /
# Devin / Pi）。即插即用：跑完重启你的 AI 客户端就能让 LLM 操作被控机。
#
#   curl -fsSL https://<服务器>/install-mcp.sh | sh -s -- --token tsm-xxx
#
# token 由服务器管理员签发：towstrap-server mcp add <名字> --machine <授权>
# Windows 机器：从 GitHub Releases 下 towstrap-mcp-windows-amd64.exe，
# 改名 towstrap-mcp.exe 后跑 towstrap-mcp.exe connect mcp --url <https://S:7880/mcp> --token tsm-...
set -eu

# 占位符由服务器端下发时替换成那台服务器的地址/版本；从 GitHub 拉的保持
# 原样，落到下面的官方默认。
DEFAULT_SERVER="__TOWSTRAP_DEFAULT_SERVER__"
OFFICIAL_SERVER="wss://towstrap.vast-plan.com"
VERSION="__TOWSTRAP_DEFAULT_VERSION__"

MINISIGN_PUB="${TOWSTRAP_MINISIGN_PUB:-RWTbpo7F0knbUQIoW3pAhERl7E/Uh2YKlQu+3Cwjadh0Clz6A4BEA746}"
PREFIX=""
TOKEN="${TOWSTRAP_MCP_TOKEN:-}"
SERVER="${TOWSTRAP_SERVER:-$DEFAULT_SERVER}"
MCP_URL=""
HARNESSES=""
SKILLS=1
NOVERIFY=0
CHECK=0

usage() {
	cat <<'EOF'
用法: install-mcp.sh --token tsm-xxx [选项]
  --token tsm-...    MCP 客户端 token（服务器上 towstrap-server mcp add 签发；
                       也可用环境变量 TOWSTRAP_MCP_TOKEN）
  --url https://...  MCP 接入点，默认 <服务器 http 地址>/mcp
  --server wss://..  towstrap 服务器地址（推 --url 用；也可 TOWSTRAP_SERVER）
  --harness a,b      只写给定的 AI 助手（claude,codex,grok,cursor,gemini,
                       opencode,copilot,devin,pi）；默认检测到的都写
  --no-skills        不把 towstrap skill 装进各助手（默认会顺带装）
  --version vX.Y.Z   towstrap-mcp 版本，默认与下发服务器同版本（GitHub 直拉 latest）
  --prefix 目录      二进制安装目录，默认 /usr/local/bin（可写）或 ~/.local/bin
  --check            干跑：打印解析出的接入地址与待写目标后退出
  --no-verify        跳过 SHA256 校验（不推荐）
  -h, --help
EOF
}

die() { echo "install-mcp.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
	case "$1" in
	--token) TOKEN="${2:-}"; shift 2 ;;
	--url) MCP_URL="${2:-}"; shift 2 ;;
	--server) SERVER="${2:-}"; shift 2 ;;
	--harness) HARNESSES="${2:-}"; shift 2 ;;
	--version) VERSION="${2:-}"; shift 2 ;;
	--prefix) PREFIX="${2:-}"; shift 2 ;;
	--no-skills) SKILLS=0; shift ;;
	--check) CHECK=1; shift ;;
	--no-verify) NOVERIFY=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) die "未知参数 $1（--help 看用法）" ;;
	esac
done

# 占位符没换（GitHub 直拉）就走官方默认；检测只看 "__TOWSTRAP" 前缀本身——
# 服务器下发是全文件替换，写完整占位名会把注入的真值误判成未替换。
case "$SERVER" in *__TOWSTRAP*) SERVER="$OFFICIAL_SERVER" ;; esac
case "$VERSION" in *__TOWSTRAP*) VERSION=latest ;; esac

# 从 ws(s) 服务器地址推 MCP 的 HTTP 接入点
if [ -z "$MCP_URL" ]; then
	case "$SERVER" in
	wss://*) MCP_URL="https://${SERVER#wss://}/mcp" ;;
	ws://*) MCP_URL="http://${SERVER#ws://}/mcp" ;;
	https://* | http://*) MCP_URL="${SERVER%/}/mcp" ;;
	*) die "--server 只认 ws(s):// 或 http(s)://：$SERVER" ;;
	esac
fi

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in linux | darwin) ;; *) die "不支持的系统 $os（Windows 见脚本头注释，下载 towstrap-mcp.exe 后跑 connect mcp）" ;; esac
case "$(uname -m)" in x86_64 | amd64) arch=amd64 ;; arm64 | aarch64) arch=arm64 ;; *) die "不支持的架构 $(uname -m)" ;; esac

if [ "$CHECK" = 1 ]; then
	printf 'server=%s\nmcp_url=%s\nversion=%s\nharness=%s\n' "$SERVER" "$MCP_URL" "$VERSION" "${HARNESSES:-<detected>}"
	exit 0
fi

[ -n "$TOKEN" ] || die "缺 --token：MCP 客户端 token 由管理员在服务器上签发（towstrap-server mcp add <名字> --machine <授权>）"

if [ "$VERSION" = latest ]; then
	relbase="https://github.com/towstrap/towstrap/releases/latest/download"
else
	relbase="https://github.com/towstrap/towstrap/releases/download/$VERSION"
fi
asset="towstrap-mcp-$os-$arch"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo ">> 下载 ${asset}（${VERSION}）"
curl -fsSL "$relbase/$asset" -o "$tmp/$asset" || die "下载失败：$relbase/$asset"
if [ "$NOVERIFY" = 1 ]; then
	echo ">> --no-verify：跳过 SHA256 校验（不推荐）"
else
	curl -fsSL "$relbase/SHA256SUMS" -o "$tmp/SHA256SUMS" 2>/dev/null ||
		die "拉不到 SHA256SUMS，校验过不了就不装；实在要跳过加 --no-verify"
	if command -v minisign >/dev/null 2>&1; then
		if curl -fsSL "$relbase/SHA256SUMS.minisig" -o "$tmp/SHA256SUMS.minisig" 2>/dev/null; then
			(cd "$tmp" && minisign -V -P "$MINISIGN_PUB" -m SHA256SUMS) ||
				die "SHA256SUMS 签名校验失败——清单可能被换过，拒绝安装"
			echo ">> minisign 签名校验通过"
		fi
	else
		echo ">> 提示：系统没有 minisign，跳过签名校验（SHA256 照验）"
	fi
	grep -q " $asset\$" "$tmp/SHA256SUMS" ||
		die "SHA256SUMS 里没有 $asset 这一行；实在要跳过加 --no-verify"
	if command -v shasum >/dev/null 2>&1; then
		(cd "$tmp" && grep " $asset\$" SHA256SUMS | shasum -a 256 -c -) || die "SHA256 校验失败"
	elif command -v sha256sum >/dev/null 2>&1; then
		(cd "$tmp" && grep " $asset\$" SHA256SUMS | sha256sum -c -) || die "SHA256 校验失败"
	else
		die "找不到 shasum/sha256sum，没法校验；实在要跳过加 --no-verify"
	fi
	echo ">> SHA256 校验通过"
fi

if [ -z "$PREFIX" ]; then
	if [ -w /usr/local/bin ]; then PREFIX=/usr/local/bin; else PREFIX="$HOME/.local/bin"; fi
fi
mkdir -p "$PREFIX"
if [ -w "$PREFIX" ]; then
	install -m 0755 "$tmp/$asset" "$PREFIX/towstrap-mcp"
else
	command -v sudo >/dev/null 2>&1 || die "没有写 $PREFIX 的权限，也没有 sudo；加 --prefix 换个目录"
	sudo install -m 0755 "$tmp/$asset" "$PREFIX/towstrap-mcp"
fi
echo ">> 已装到 $PREFIX/towstrap-mcp"

# 落 MCP 配置：写进检测到的各家 harness（原文件自动备份 .bak）。
# 没检测到也不算失败——也许用户稍后装客户端，手工重跑 connect mcp 就行。
harg=""
[ -z "$HARNESSES" ] || harg="--harness $HARNESSES"
echo ">> 把 MCP 接入写进各家 AI 助手（$MCP_URL）"
# shellcheck disable=SC2086
"$PREFIX/towstrap-mcp" connect mcp --url "$MCP_URL" --token "$TOKEN" $harg ||
	echo ">> 注意：没有 harness 被写入（可能都没装）。之后可重跑：towstrap-mcp connect mcp --url $MCP_URL --token <token>"

if [ "$SKILLS" = 1 ]; then
	echo ">> 顺带安装 towstrap skill 到检测到的助手"
	"$PREFIX/towstrap-mcp" connect || true
fi

echo ""
echo "完成。重启你的 AI 客户端让 MCP 配置生效，然后就能让 LLM 操作远程机器。"
echo "手动批准待批请求：towstrap-mcp pending / approve <id>"
