package main

// towstrap token refresh 的命令行入口；核心逻辑在 internal/client
// （TokenRefresh），这里只做配置解析和旗标接线。

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/towstrap/towstrap/internal/client"
)

type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func runTokenRefresh(args []string) int {
	fs := flag.NewFlagSet("token refresh", flag.ExitOnError)
	cf := addCredFlags(fs)
	var machines stringList
	fs.Var(&machines, "machine", "")
	all := fs.Bool("all", false, "")
	_ = fs.Parse(args)

	env, err := loadAgentCLI(fs, cf)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	return client.TokenRefresh(client.RefreshOpts{
		Server:     env.srv,
		Token:      env.tok,
		Insecure:   env.cfg.Insecure,
		Machines:   machines,
		All:        *all,
		AllowPlain: *cf.allowPlain,
	}, os.Stdin, os.Stderr)
}

// 薄封装：测试打的是包内名，实现都在 client 包里。
func refreshURL(server string) (string, error)   { return client.RefreshURL(server) }
func plainCheck(server string, allow bool) error { return client.PlainCheck(server, allow) }
