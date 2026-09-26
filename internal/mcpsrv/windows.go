package mcpsrv

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

type shellDialect int

const (
	dialectPOSIX shellDialect = iota
	dialectCmd
	dialectPowerShell
)

func (d shellDialect) windows() bool { return d != dialectPOSIX }

// remoteInfo 是探测到的一次远端形态：shell 方言之外还记文件系统是否
// 大小写/Unicode 不敏感（fold）——macOS 和 Windows 的文件系统按字节
// 分不清别名，路径比对要多做一层折叠；Linux 这类字节精确的不用。
// resolvedRoots/rootsKey 缓存「远端解析过的 roots」：roots 是服务端文本
// 配置，输入路径经远端归一化后文本前缀对不上（/var→/private/var），
// roots 也得同样解析再比——内容没变就不重解。
type remoteInfo struct {
	dialect       shellDialect
	fold          bool
	resolvedRoots []string
	rootsKey      string
}

func (s *Server) dialect(ctx context.Context, machine string) (shellDialect, error) {
	ri, err := s.remoteInfo(ctx, machine)
	return ri.dialect, err
}

// remoteInfo 拿机器探测结果（每台机器缓存一份——shell 方言和文件系统
// 语义不会中途变）。
func (s *Server) remoteInfo(ctx context.Context, machine string) (remoteInfo, error) {
	s.mu.Lock()
	ri, ok := s.remotes[machine]
	s.mu.Unlock()
	if ok {
		return ri, nil
	}
	ri, err := s.probeRemote(ctx, machine)
	if err != nil {
		return remoteInfo{}, err
	}
	s.mu.Lock()
	s.remotes[machine] = ri
	s.mu.Unlock()
	return ri, nil
}

func (s *Server) probeRemote(ctx context.Context, machine string) (remoteInfo, error) {
	res, err := s.runner.Run(ctx, machine, "echo %OS%", nil, 15*time.Second, 4096)
	if err != nil {
		return remoteInfo{}, fmt.Errorf("探测 %s 的 shell 类型失败：%w", machine, err)
	}
	if res.ExitCode != 0 {
		return remoteInfo{}, fmt.Errorf("探测 %s 的 shell 类型失败：exit_code=%d", machine, res.ExitCode)
	}
	if lastLine(res.Stdout) == "Windows_NT" {
		return remoteInfo{dialect: dialectCmd, fold: true}, nil
	}
	res, err = s.runner.Run(ctx, machine, "echo $env:OS", nil, 15*time.Second, 4096)
	if err != nil {
		return remoteInfo{}, fmt.Errorf("探测 %s 的 shell 类型失败：%w", machine, err)
	}
	if res.ExitCode != 0 {
		return remoteInfo{}, fmt.Errorf("探测 %s 的 shell 类型失败：exit_code=%d", machine, res.ExitCode)
	}
	if lastLine(res.Stdout) == "Windows_NT" {
		return remoteInfo{dialect: dialectPowerShell, fold: true}, nil
	}
	// POSIX：macOS 的默认文件系统不区分大小写且按 NFD 落盘，比对要做
	// 折叠；Linux 等按字节精确，不用。
	// 这步探测失败绝不能按「不折叠」放行：失败结果一缓存就是整会话，
	// macOS 上 TOKEN 这类大小写变体就能绕过保护清单读走凭据。失败就
	// 报错不缓存，下次调用重新探。
	res, err = s.runner.Run(ctx, machine, "uname -s", nil, 15*time.Second, 4096)
	if err != nil {
		return remoteInfo{}, fmt.Errorf("探测 %s 的文件系统语义失败：%w", machine, err)
	}
	if res.ExitCode != 0 {
		return remoteInfo{}, fmt.Errorf("探测 %s 的文件系统语义失败：exit_code=%d", machine, res.ExitCode)
	}
	uname := lastLine(res.Stdout)
	switch uname {
	case "Darwin":
		return remoteInfo{dialect: dialectPOSIX, fold: true}, nil
	case "Linux", "FreeBSD", "OpenBSD", "NetBSD", "DragonFly", "SunOS", "AIX", "GNU":
		return remoteInfo{dialect: dialectPOSIX}, nil
	}
	if strings.Contains(uname, "_NT") {
		// MINGW64_NT-/MSYS_NT-/CYGWIN_NT-：Windows 机器被 POSIX shell
		// 接了（Git Bash 之类）——POSIX 路径规则在 Windows 上不成立，
		// 判了也是错判。
		return remoteInfo{}, fmt.Errorf("%s 是 Windows（uname=%q）却用 POSIX shell 应答——请把 agent 的默认 shell 换成 cmd/PowerShell", machine, uname)
	}
	return remoteInfo{}, fmt.Errorf("探测 %s 的文件系统语义失败：uname 返回不认得的值 %q", machine, uname)
}

// lastLine 取输出最后一个非空行：登录 shell 的 rc 可能往 stdout 前置
// 打印点东西，命令的真实输出在最后。
func lastLine(s string) string {
	s = strings.TrimRight(s, "\r\n \t")
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return strings.TrimRight(s[i+1:], "\r \t")
	}
	return s
}

func psQuote(p string) string {
	return "'" + strings.ReplaceAll(p, "'", "''") + "'"
}

func psEncode(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func psPathPrelude(p string) string {
	return "$p=" + psQuote(p) + "\n" +
		"if($p -eq '~' -or $p.StartsWith('~/') -or $p.StartsWith('~\\')){" +
		"if([string]::IsNullOrEmpty($HOME)){[System.Console]::Error.WriteLine('no HOME');exit 1};" +
		"if($p -eq '~'){$p=$HOME}else{$p=Join-Path $HOME $p.Substring(2)}}\n"
}

func psCommand(script string) string {
	return "powershell.exe -NoProfile -NonInteractive -EncodedCommand " + psEncode(script)
}

func psReadCommand(path string, maxPlusOne int) string {
	return psCommand(psPathPrelude(path) + fmt.Sprintf(
		"try{$f=[System.IO.File]::OpenRead($p);$o=[System.Console]::OpenStandardOutput();$b=New-Object byte[] 65536;$r=%d;while($r -gt 0){$n=$f.Read($b,0,[Math]::Min($b.Length,$r));if($n -le 0){break};$o.Write($b,0,$n);$r-=$n};$o.Flush();$f.Dispose()}catch{[System.Console]::Error.WriteLine($_.Exception.Message);exit 1}",
		maxPlusOne))
}

func psWriteCommand(path string) string {
	return psCommand(psPathPrelude(path) +
		"try{$f=[System.IO.File]::Create($p);[System.Console]::OpenStandardInput().CopyTo($f);$f.Dispose()}catch{[System.Console]::Error.WriteLine($_.Exception.Message);exit 1}")
}
