package main

// towstrap token refresh 的命令行入口；核心逻辑在 internal/client
// （TokenRefresh），这里只做配置解析和旗标接线。

import (
	"flag"
	"log/slog"
	"os"
	"strings"

	"github.com/towstrap/towstrap/internal/client"
	"github.com/towstrap/towstrap/internal/config"
	"github.com/towstrap/towstrap/internal/proto"
)

type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func runTokenRefresh(args []string) int {
	fs := flag.NewFlagSet("token refresh", flag.ExitOnError)
	configPath := fs.String("config", "", "")
	fs.String("server", "", "")
	agentToken := fs.String("agent-token", "", "")
	tokenFile := fs.String("agent-token-file", "", "")
	fs.Bool("insecure", false, "")
	var machines stringList
	fs.Var(&machines, "machine", "")
	all := fs.Bool("all", false, "")
	allowPlain := fs.Bool("allow-plain", false, "")
	_ = fs.Parse(args)

	var file config.Agent
	if *configPath != "" {
		var err error
		file, err = config.LoadAgent(*configPath)
		if err != nil {
			slog.Error(err.Error())
			return 2
		}
	}
	cfg := config.MergeAgent(file, visited(fs))
	tok, _, _, err := resolveAgentToken(*agentToken, *tokenFile, os.Getenv("TOWSTRAP_AGENT_TOKEN"), cfg.AgentToken, cfg.AgentTokenFile)
	if err != nil {
		slog.Error(err.Error())
		return 2
	}
	if cfg.Server == "" {
		cfg.Server = proto.OfficialServer
	}
	return client.TokenRefresh(client.RefreshOpts{
		Server:     cfg.Server,
		Token:      tok,
		Insecure:   cfg.Insecure,
		Machines:   machines,
		All:        *all,
		AllowPlain: *allowPlain,
	}, os.Stdin, os.Stderr)
}

// 薄封装：测试打的是包内名，实现都在 client 包里。
func refreshURL(server string) (string, error)   { return client.RefreshURL(server) }
func plainCheck(server string, allow bool) error { return client.PlainCheck(server, allow) }
