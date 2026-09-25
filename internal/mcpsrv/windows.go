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

func (s *Server) dialect(ctx context.Context, machine string) (shellDialect, error) {
	s.mu.Lock()
	d, ok := s.dialects[machine]
	s.mu.Unlock()
	if ok {
		return d, nil
	}
	d, err := s.probeDialect(ctx, machine)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.dialects[machine] = d
	s.mu.Unlock()
	return d, nil
}

func (s *Server) probeDialect(ctx context.Context, machine string) (shellDialect, error) {
	res, err := s.runner.Run(ctx, machine, "echo %OS%", nil, 15*time.Second, 4096)
	if err != nil {
		return 0, fmt.Errorf("探测 %s 的 shell 类型失败：%w", machine, err)
	}
	if res.ExitCode != 0 {
		return 0, fmt.Errorf("探测 %s 的 shell 类型失败：exit_code=%d", machine, res.ExitCode)
	}
	if strings.TrimSpace(res.Stdout) == "Windows_NT" {
		return dialectCmd, nil
	}
	res, err = s.runner.Run(ctx, machine, "echo $env:OS", nil, 15*time.Second, 4096)
	if err != nil {
		return 0, fmt.Errorf("探测 %s 的 shell 类型失败：%w", machine, err)
	}
	if res.ExitCode != 0 {
		return 0, fmt.Errorf("探测 %s 的 shell 类型失败：exit_code=%d", machine, res.ExitCode)
	}
	if strings.TrimSpace(res.Stdout) == "Windows_NT" {
		return dialectPowerShell, nil
	}
	return dialectPOSIX, nil
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
