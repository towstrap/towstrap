package mcpsrv

// resolve.go —— 文件工具在远端做真实路径归一化。
//
// 服务端拿字符串比前缀认不出文件系统别名：大小写（macOS/Windows 默认
// 不区分）、Unicode 拼法（HFS+/APFS 按 NFD 落盘）、符号链接、
// /proc/self/root 这类都能把同一个文件拼成另一种写法。策略要在
// 「文件系统认出的路径」上做才有效，所以 read_file/write_file 先把
// 路径交给远端解析器：~ 展开、相对路径按 shell 工作目录展开、逐层
// 解符号链接、目录部分拿真实形态（含大小写）。拿回来的路径再过
// deny_paths/protect/roots，执行也走解析后的路径。

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// resolveTimeout 是单次远端路径解析的超时：它就跑一个 shell 小脚本，
// 超过这个数只能是对端坏了，不该让文件工具一直挂着。
const resolveTimeout = 15 * time.Second

// maxPathBytes 是文件工具路径入参的上限——POSIX MAXPATH 4096，留一倍
// 余量够任何正常路径；再长只可能是刷流量的垃圾输入。
const maxPathBytes = 8192

// posixResolveFn 是 POSIX 侧的路径解析函数：~ 展开 → 相对转绝对 →
// 目录部分 cd -P 拿物理路径（一口气化掉 ..、多级符号链接和
// /proc/self/root 之类的魔法目录）→ 末级若是符号链接就跟一跳再来。
// 末级不存在/不是链接按字面返回（新建文件允许末级不存在）。结果
// 打印到 stdout，退出码非 0 一律算解析失败。
const posixResolveFn = `tsresolve() {
  p=$1
  i=0
  while :; do
    case "$p" in
      "~") p=$HOME ;;
      "~/"*) p=$HOME/${p#\~/} ;;
    esac
    case "$p" in
      /*) ;;
      *) p=$PWD/$p ;;
    esac
    case "$p" in
      */*) d=${p%%/*} ;;
      *) d=. ;;
    esac
    [ -z "$d" ] && d=/
    b=${p##*/}
    if [ -z "$b" ]; then
      # 结尾带斜杠（或整串是 /）：按目录自身解析
      rd=$(cd -P -- "$d" 2>/dev/null && pwd -P) || return 3
      printf '%%s' "$rd"
      return 0
    fi
    rd=$(cd -P -- "$d" 2>/dev/null && pwd -P) || return 3
    f=$rd/$b
    case "$b" in
      .|..) rd=$(cd -P -- "$f" 2>/dev/null && pwd -P) || return 3; printf '%%s' "$rd"; return 0 ;;
    esac
    if [ -L "$f" ]; then
      i=$((i+1))
      [ "$i" -gt 40 ] && return 4
      l=$(readlink "$f") || return 5
      case "$l" in
        /*) p=$l ;;
        *) p=$rd/$l ;;
      esac
      continue
    fi
    printf '%%s' "$f"
    return 0
  done
}
`

// posixResolveTmpl 是「仅解析」命令：参数 %s 处填单引号字面量路径。
const posixResolveTmpl = posixResolveFn + `tsresolve %s
`

// posixFileCmd 是「解析+读写」一体的命令：先解析出真实路径，和上次
// 批准时解析的结果比对（变了说明路径被换过，拒），紧接着就地读写。
// 解析和 open 挤在同一进程里做，两次远端调用之间的符号链接掉包窗口
// 压到脚本内部的微秒级。
// 参数：%s 原始路径（引号字面量）、%s 上次解析结果（引号字面量，可为空）、
// %s 动作（head -c N -- 或 cat >）。
const posixFileCmd = posixResolveFn + `f=$(tsresolve %s) || exit $?
exp=%s
if [ -n "$exp" ] && [ "$f" != "$exp" ]; then
  echo "resolved path changed: $f" >&2
  exit 6
fi
%s "$f"
`

// psResolveHead 是 Windows 侧解析脚本的前半段（PowerShell）：~ 展开 →
// GetFullPath 化掉 . / .. → 目录 Resolve-Path 拿真实形态（符号链接、
// 大小写一并归一）→ 末级 Get-Item 拿目录项真名，是 reparse point
// （符号链接/junction）就跟目标再来一轮，最多 40 跳。结果落在 $f 上，
// 收尾看用途接 print 还是 I/O。
const psResolveHead = `if($p -eq '~' -or $p.StartsWith('~/') -or $p.StartsWith('~\')){
  if([string]::IsNullOrEmpty($HOME)){[System.Console]::Error.WriteLine('no HOME');exit 3}
  if($p -eq '~'){$p=$HOME}else{$p=Join-Path $HOME $p.Substring(2)}
}
try{
  $full=[System.IO.Path]::GetFullPath($p)
  $d=[System.IO.Path]::GetDirectoryName($full)
  $b=[System.IO.Path]::GetFileName($full)
  if([string]::IsNullOrEmpty($b)){
    $f=(Resolve-Path -LiteralPath $full -ErrorAction Stop).ProviderPath
  }else{
    if([string]::IsNullOrEmpty($d)){$d=(Get-Location).Path}
    $rd=(Resolve-Path -LiteralPath $d -ErrorAction Stop).ProviderPath
    $f=Join-Path $rd $b
    $i=0
    while($i -lt 40){
      $gi=Get-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
      if($null -eq $gi){break}
      $f=$gi.FullName
      if(-not ($gi.Attributes -band [IO.FileAttributes]::ReparsePoint)){break}
      $t=$gi.Target
      if([string]::IsNullOrEmpty($t)){break}
      if(-not [System.IO.Path]::IsPathRooted($t)){
        $t=Join-Path ([System.IO.Path]::GetDirectoryName($f)) $t
      }
      $f=$t
      $i++
    }
  }
`

const psResolveTailPrint = `  [Console]::Out.Write($f)
}catch{[System.Console]::Error.WriteLine($_.Exception.Message);exit 3}
`

// psResolveTailIO 是「解析+读写」的收尾：$f 落定后先和上次批准的解析
// 结果比对（$exp，字符串不等即路径被换过），紧接着在 $f 上做 %s 动作。
// 解析和 open 在同一 PowerShell 进程里，掉包窗口压到微秒级。
const psResolveTailIO = `  if($exp -ne '' -and $f -ne $exp){[System.Console]::Error.WriteLine('resolved path changed: '+$f);exit 6}
%s
}catch{[System.Console]::Error.WriteLine($_.Exception.Message);exit 3}
`

const psResolveBody = psResolveHead + psResolveTailPrint

// resolvePath 让远端把路径解成文件系统认的真实形态。失败（目录不可达、
// 链接环、agent 掉线）一律报错——调用方对文件操作必须 fail closed：
// 解析不出真实路径就没法证明它不是受保护文件的别名。
func (s *Server) resolvePath(ctx context.Context, machine, p string, d shellDialect) (string, error) {
	if len(p) > maxPathBytes {
		return "", fmt.Errorf("路径太长（%d 字节 > 上限 %d）", len(p), maxPathBytes)
	}
	var cmd string
	if d.windows() {
		cmd = psCommand("$p=" + psQuote(p) + "\n" + psResolveBody)
	} else {
		cmd = fmt.Sprintf(posixResolveTmpl, shellQuote(p))
	}
	res, err := s.runner.Run(ctx, machine, cmd, nil, resolveTimeout, 4096)
	if err != nil {
		return "", fmt.Errorf("远端路径解析失败：%v", err)
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("远端路径解析失败：%s", strings.TrimSpace(res.Stderr))
	}
	out := strings.TrimRight(res.Stdout, "\r\n")
	if out == "" {
		return "", fmt.Errorf("远端路径解析失败：空结果")
	}
	// 结果必须是干净的绝对路径：多行输出说明 rc 噪声混了进来，相对
	// 路径形态说明脚本出了岔子——拿个形态不明的串去过清单等于没比。
	if strings.ContainsAny(out, "\r\n") {
		return "", fmt.Errorf("远端路径解析失败：输出里混了别的行（rc 打印噪声？）")
	}
	if d.windows() {
		if !winPathAbs(out) {
			return "", fmt.Errorf("远端路径解析返回了非绝对路径 %q", clip(out, 80))
		}
	} else {
		if !strings.HasPrefix(out, "/") {
			return "", fmt.Errorf("远端路径解析返回了非绝对路径 %q", clip(out, 80))
		}
		// 目录在根时脚本给出 //name 形态——文件系统里它和 /name 是同一个
		// 文件，但按字面值比对清单认不出来，归一掉。
		out = path.Clean(out)
	}
	return out, nil
}

// foldPath 把路径折成「大小写和 Unicode 拼法都归一」的形态：APFS/HFS+
// 和 Windows 文件系统不区分大小写、macOS 文件名按 NFD 落盘——/users/x
// 和 /Users/x、NFC 的 ü 和 NFD 的 ü 在那边都是同一个文件。只在远端
// 文件系统按字节判不出别名时才用它做比对（Linux 这类字节精确的不调）。
func foldPath(p string) string {
	return norm.NFC.String(caseFolder.String(p))
}

// caseFolder 是语言无关的全折叠器（Turkish i 这类地区差异不掺和），
// 给所有折叠文件系统共用。
var caseFolder = cases.Fold()
