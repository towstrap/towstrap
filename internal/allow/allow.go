package allow

import (
	"fmt"
	"net"
	"strings"
)

type List struct {
	rules []rule
}

type rule struct {
	any  bool
	cidr *net.IPNet
	ip   net.IP
	host string
	port string
	name string
}

func Parse(items []string) (*List, error) {
	l := &List{}
	for _, raw := range items {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		r, err := parseRule(raw)
		if err != nil {
			return nil, fmt.Errorf("白名单 %q: %w", raw, err)
		}
		l.rules = append(l.rules, r)
	}
	return l, nil
}

func parseRule(s string) (rule, error) {
	if s == "*" {
		return rule{any: true}, nil
	}
	if strings.Contains(s, "/") {
		hostpart, port := s, ""
		if i := strings.LastIndex(s, ":"); i > strings.Index(s, "/") {
			hostpart, port = s[:i], s[i+1:]
		}
		_, n, err := net.ParseCIDR(hostpart)
		if err != nil {
			return rule{}, err
		}
		return rule{cidr: n, port: port}, nil
	}
	if host, port, err := net.SplitHostPort(s); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return rule{ip: ip, port: port}, nil
		}
		return rule{host: strings.ToLower(host), port: port}, nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return rule{ip: ip}, nil
	}
	return rule{host: strings.ToLower(s), name: s}, nil
}

type Sets struct {
	IPs     *List
	Clients *List
}

func ParseSets(ips, clients []string) (Sets, error) {
	var s Sets
	var err error
	if s.IPs, err = Parse(ips); err != nil {
		return s, err
	}
	if s.Clients, err = Parse(clients); err != nil {
		return s, err
	}
	return s, nil
}

func (l *List) Empty() bool {
	return l == nil || len(l.rules) == 0
}

func (l *List) AllowsIP(ip net.IP) bool {
	if l.Empty() {
		return true
	}
	if ip == nil {
		return false
	}
	for _, r := range l.rules {
		if r.matchesIP(ip) {
			return true
		}
	}
	return false
}

func (l *List) AllowsName(name string) bool {
	if l.Empty() {
		return true
	}
	for _, r := range l.rules {
		if r.any || r.name == name {
			return true
		}
	}
	return false
}

func (l *List) AllowsAddr(addr net.Addr) bool {
	if l.Empty() {
		return true
	}
	return l.AllowsIP(ipFromAddr(addr))
}

func (l *List) AllowsRemote(hostPort string) bool {
	if l.Empty() {
		return true
	}
	return l.AllowsIP(ipFromHostPort(hostPort))
}

func (r rule) matchesIP(ip net.IP) bool {
	if r.any {
		return true
	}
	if r.cidr != nil {
		return r.cidr.Contains(ip)
	}
	if r.ip != nil {
		return r.ip.Equal(ip)
	}
	return false
}

func ipFromAddr(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	default:
		if addr == nil {
			return nil
		}
		return ipFromHostPort(addr.String())
	}
}

func ipFromHostPort(s string) net.IP {
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return net.ParseIP(s)
	}
	return net.ParseIP(host)
}
