package main

// 账号本人确认：machine add/token、user token 这类会签发或暴露机器 token
// 的操作，默认要求账号本人输入密码（绑了 TOTP 再输验证码）；--admin 跳过，
// 但会打警告并写一条审计。

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/towstrap/towstrap/internal/accounts"
	"github.com/towstrap/towstrap/internal/auditlog"
	"github.com/towstrap/towstrap/internal/config"
	"github.com/towstrap/towstrap/internal/server"
)

// confirmOwner 让账号本人确认：输入账号密码（绑了 TOTP 再输验证码）。
// admin=true 跳过（调用方负责警告和审计）。in 为终端时密码不回显。
func confirmOwner(store *accounts.Store, user string, in io.Reader, out io.Writer, admin bool) error {
	if admin {
		return nil
	}
	if _, ok := store.Get(user); !ok {
		return fmt.Errorf("%w: %s", accounts.ErrNotFound, user)
	}
	r := newCredReader(in)
	pw, err := r.read(out, "确认是账号本人操作，输入该账号的 SSH 密码: ")
	if err != nil {
		return err
	}
	if !store.Verify(user, pw) {
		return errors.New("密码不对或账号已停用")
	}
	if acct, ok := store.Get(user); ok && acct.TOTPEnabled {
		code, err := r.read(out, "TOTP 验证码: ")
		if err != nil {
			return err
		}
		if !store.VerifyTOTP(user, strings.TrimSpace(code)) {
			return errors.New("验证码不对")
		}
	}
	return nil
}

// credReader 读密码/验证码：in 是终端时不回显（term.ReadPassword），否则按行
// 读；多次读取共享同一个 bufio，不吞掉后面的输入。
type credReader struct {
	in     io.Reader
	br     *bufio.Reader
	termFd int // 终端 fd；-1 表示不是终端
}

func newCredReader(in io.Reader) *credReader {
	r := &credReader{in: in, termFd: -1}
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		r.termFd = int(f.Fd())
	}
	return r
}

func (r *credReader) read(out io.Writer, prompt string) (string, error) {
	_, _ = fmt.Fprint(out, prompt)
	if r.termFd >= 0 {
		b, err := term.ReadPassword(r.termFd)
		_, _ = fmt.Fprintln(out)
		return string(b), err
	}
	if r.br == nil {
		r.br = bufio.NewReader(r.in)
	}
	line, err := r.br.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// ownerOrAdmin：--admin 时打警告、写管理员审计后放行；否则走 confirmOwner。
// 返回 false 时原因已经打出，调用方直接退出。
func ownerOrAdmin(env userEnv, user, machine, adminEvent string, admin bool) bool {
	if admin {
		slog.Warn("以管理员身份跳过账号本人确认，已记审计", "user", user, "machine", machine)
		auditAdminAction(env.auditPath, adminEvent, "user", user, "machine", machine)
		return true
	}
	if err := confirmOwner(env.store, user, os.Stdin, os.Stderr, false); err != nil {
		slog.Error(err.Error())
		return false
	}
	return true
}

// cliAuditPath 决定 CLI 管理操作的审计写到哪：--audit-log 旗标 > server.yaml
// 的 audit_log > 服务器默认位置（和 runServer 同一套优先级）。
func cliAuditPath(flagValue, configPath string) string {
	if flagValue != "" {
		return flagValue
	}
	if configPath != "" {
		if s, err := config.LoadServer(configPath); err == nil && s.AuditLog != "" {
			return s.AuditLog
		}
	}
	return server.DefaultAuditPath()
}

// auditAdminAction 往服务器审计日志追加一条管理员操作记录。auditlog 的 Writer
// 用 O_APPEND 逐行写，CLI 和正在跑的服务器进程并发追加是安全的。
func auditAdminAction(path, event string, kv ...string) {
	w := auditlog.Open(path, 0)
	w.Log(event, kv...)
}
