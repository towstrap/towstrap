#!/bin/sh
# TowStrap 服务端一键安装（Linux，systemd；macOS 只装二进制）。
#
#   curl -fsSL https://raw.githubusercontent.com/towstrap/towstrap/main/scripts/install-server.sh | sudo sh
#
# 脚本和二进制都来自 GitHub：本文件走 raw，二进制走 Releases+SHA256SUMS
# 校验。（官方域名 towstrap.vast-plan.com/install-server.sh 也挂了一份
# 同样的字节，纯图好记——自建的第一步总是从 GitHub 开始，那时还没有
# 自己的服务器可拉。）
#
# 装的是 towstrap-server（服务端）。被控机装 agent 走 install.sh，不是这个。
set -eu

VERSION="${TOWSTRAP_VERSION:-latest}"
PREFIX="/usr/local/bin"
CONFDIR=/etc/towstrap
SYSTEMD=auto   # auto|yes|no：Linux+root+有 systemctl 时 auto 会装服务
CHECK=0
NOVERIFY=0

usage() {
	cat <<'EOF'
用法: install-server.sh [选项]
  --version vX.Y.Z    装指定版本（默认 latest；也可设 TOWSTRAP_VERSION）
  --prefix 目录       安装目录（默认 /usr/local/bin）
  --systemd           强制装并启动 systemd 服务（Linux+root 默认就是这样）
  --no-systemd        只装二进制和配置，不碰 systemd
  --confdir 目录      配置/数据目录（默认 /etc/towstrap，需 root）
  --check             干跑：打印解析结果后退出（不下载不安装）
  --no-verify         跳过 SHA256 校验（不推荐；只在校验确实拉不动时用）
  -h, --help
EOF
}

die() { echo "install-server.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
	case "$1" in
	--version) VERSION="${2:-}"; shift 2 ;;
	--prefix) PREFIX="${2:-}"; shift 2 ;;
	--systemd) SYSTEMD=yes; shift ;;
	--no-systemd) SYSTEMD=no; shift ;;
	--confdir) CONFDIR="${2:-}"; shift 2 ;;
	--check) CHECK=1; shift ;;
	--no-verify) NOVERIFY=1; shift ;;
	-h|--help) usage; exit 0 ;;
	*) die "未知参数 $1（--help 看用法）" ;;
	esac
done

case "$VERSION" in *__TOWSTRAP*) VERSION=latest ;; esac

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in linux | darwin) ;; *) die "不支持的系统 $os（服务端只发 Linux/macOS；Windows 暂不支持）" ;; esac
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
arm64 | aarch64) arch=arm64 ;;
*) die "不支持的架构 $(uname -m)" ;;
esac

# systemd 服务只在 Linux + root + 有 systemctl 时自动装
wantsvc=0
if [ "$SYSTEMD" = yes ]; then
	wantsvc=1
elif [ "$SYSTEMD" = auto ] && [ "$os" = linux ] && [ "$(id -u)" = 0 ] && command -v systemctl >/dev/null 2>&1; then
	wantsvc=1
fi
if [ "$SYSTEMD" = yes ] && { [ "$os" != linux ] || [ "$(id -u)" != 0 ]; }; then
	die "--systemd 需要 Linux + root"
fi

if [ "$CHECK" = 1 ]; then
	printf 'version=%s\nos=%s\narch=%s\nprefix=%s\nconfdir=%s\nsystemd=%s\n' \
		"$VERSION" "$os" "$arch" "$PREFIX" "$CONFDIR" "$wantsvc"
	exit 0
fi

# 装服务、写 /etc 配置都要 root——明确在这里拦，别下到一半才失败。
if [ "$wantsvc" = 1 ] || [ "$CONFDIR" = /etc/towstrap ]; then
	[ "$(id -u)" = 0 ] || die "写 $CONFDIR 或装 systemd 服务要 root——请用 sudo sh 跑，或加 --confdir ~/.config/towstrap --no-systemd 只装二进制"
fi

if [ "$VERSION" = latest ]; then
	relbase="https://github.com/towstrap/towstrap/releases/latest/download"
else
	relbase="https://github.com/towstrap/towstrap/releases/download/$VERSION"
fi
asset="towstrap-server-$os-$arch"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo ">> 下载 ${asset}（${VERSION}）"
curl -fsSL "$relbase/$asset" -o "$tmp/$asset" || die "下载失败：$relbase/$asset"
# 校验是硬门槛：拉不到清单/清单没这行/没哈希工具都算不过——这二进制
# 要以 root 起服务，装之前必须验明正身；实在要跳过得显式 --no-verify。
if [ "$NOVERIFY" = 1 ]; then
	echo ">> --no-verify：跳过 SHA256 校验（不推荐）"
else
	curl -fsSL "$relbase/SHA256SUMS" -o "$tmp/SHA256SUMS" 2>/dev/null ||
		die "拉不到 SHA256SUMS，校验过不了就不装；实在要跳过加 --no-verify"
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

mkdir -p "$PREFIX" 2>/dev/null || sudo mkdir -p "$PREFIX"
install -m 0755 "$tmp/$asset" "$PREFIX/towstrap-server" ||
	{ command -v sudo >/dev/null 2>&1 && sudo install -m 0755 "$tmp/$asset" "$PREFIX/towstrap-server"; } ||
	die "写不进 $PREFIX"
echo ">> 已装到 $PREFIX/towstrap-server"

# 配置：只在缺失时写最小可用集——已有的不动（重装升级不覆盖调好的配置）。
mkdir -p "$CONFDIR"
chmod 700 "$CONFDIR"
srvyaml="$CONFDIR/server.yaml"
if [ ! -f "$srvyaml" ]; then
	cat >"$srvyaml" <<'YAML'
# towstrap-server 配置——最小可用集。全部选项见仓库 examples/server.yaml。
server:
  http: "127.0.0.1:7880"      # HTTP 面：落地页 /install.sh /agent WS——对外建议走 nginx 443 按路径分发。
                              # 反代在 Docker 里（NPM 等）时 127.0.0.1 指容器自身：改绑 docker0
                              # 网桥（默认 172.17.0.1）或内网 IP 并设 allow_plain_http: true
  ssh: ":7822"                # SSH 入口：裸 TCP 协议没有路径概念，nginx 分不了流，对外单独开端口
  users_db: /etc/towstrap/users.db   # 账号库（SQLite）：账号/token/TOTP/机器指纹都在这

  # register: true            # 打开后机器上跑 towstrap register 就能自助建号；
                              # 不开则管理员用 towstrap-server user add 建号，
                              # 已有账号照样能 register --login 加机器（不受开关管）
  # register_invite: ""       # 可选邀请码：开了后建号要带 --invite
YAML
	chmod 600 "$srvyaml"
	echo ">> 配置写入 ${srvyaml}（0600）"
else
	echo ">> $srvyaml 已存在，没动它"
fi

# —— 收尾打印实际访问信息 ——
# 从 server.yaml 抠出真实监听地址（扁平/嵌套写法都认：第一个 http:/ssh:
# 标量即生效值），再尽力猜一个对外地址拼接入命令。
yamlval() {
	sed -n "s/^ *$1: *//p" "$srvyaml" | head -1 | sed 's/#.*//; s/^["'"'"']*//; s/["'"'"' ]*$//'
}
http_listen=$(yamlval http); [ -n "$http_listen" ] || http_listen="127.0.0.1:7880"
ssh_listen=$(yamlval ssh);   [ -n "$ssh_listen" ]  || ssh_listen=":7822"
ssh_port=${ssh_listen##*:}
http_port=${http_listen##*:}

# 猜本机对外地址：Linux hostname -I 第一个地址；macOS ipconfig；都没有留占位符
hosthint=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -n "$hosthint" ] || hosthint=$(ipconfig getifaddr en0 2>/dev/null || true)
[ -n "$hosthint" ] || hosthint="<服务器地址>"

loopback=0
case "$http_listen" in 127.*|::1:*|localhost*) loopback=1 ;; esac

if [ "$wantsvc" = 1 ]; then
	cat >/etc/systemd/system/towstrap-server.service <<EOF
[Unit]
Description=towstrap server（SSH + HTTP + MCP 入口）
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$PREFIX/towstrap-server --config $srvyaml
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=true
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF
	systemctl daemon-reload
	if systemctl is-enabled --quiet towstrap-server 2>/dev/null; then
		systemctl restart towstrap-server
		echo ">> towstrap-server 服务已重启（沿用既有配置）"
	else
		systemctl enable --now towstrap-server
		echo ">> towstrap-server 服务已启动并设为开机自启"
	fi
	echo ">> 日志：journalctl -u towstrap-server -f"
else
	cat <<EOF

跑起来：
  towstrap-server --config $srvyaml
EOF
fi

cat <<EOF

—— 本机访问信息 ——
  HTTP 监听：  ${http_listen}
  SSH 监听：   ${ssh_listen}
  配置文件：   ${srvyaml}
  SSH 登录示例：ssh -p ${ssh_port} <账号>@${hosthint}
EOF
if [ "$loopback" = 1 ]; then
	cat <<EOF
  注意：HTTP 面当前只监听回环（${http_listen}），被控机从外面够不着
  install.sh——init 时给 public_url 配对外域名（走 nginx 443 反代回这个口），
  或把 server.yaml 的 http 改成 :${http_port} 直接对外。
EOF
else
	cat <<EOF
  被控机安装：curl -fsSL http://${hosthint}:${http_port}/install.sh | sh
EOF
fi
cat <<EOF

接下来：
  1. 跑初始化向导（对外地址 / 自助注册 / 第一个账号，可反复跑）：
       sudo towstrap-server init --config $srvyaml
  2. 对外只露两个口：HTTPS 443（nginx → ${http_listen}，分发见 examples/nginx.conf）
     和 SSH ${ssh_port}（裸 TCP，直出）
  3. 不想跑向导就手工改 ${srvyaml}（register: true 开自助建号；
     towstrap-server user add 名字 --config $srvyaml 建号发 token）
  4. 被控机装 agent：curl -fsSL https://<对外域名>/install.sh | sh -s -- --token tsa-...
     （开了 register 就不用 token：装完跑 towstrap register）
EOF
