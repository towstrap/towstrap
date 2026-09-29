// 审计日志的离线聚合：stats 子命令读，不依赖服务器进程在跑。
// 行格式是 Writer.Log 写的「RFC3339 时间 事件名 k=v k=v」，值含空格/等号/
// 引号时是 strconv.Quote 形态，这里按同一规则解回来。
package auditlog

import (
	"bufio"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// UseStat 是按主体（账号/机器）聚合的用量。
type UseStat struct {
	Count int64
	Dur   time.Duration // 已闭环的总时长
}

// Stats 是 Scan 的产出。
type Stats struct {
	First, Last time.Time        // 窗口内首/末条事件时间（Last 零值=窗口内无事件）
	Events      map[string]int64 // 每种事件的原始计数

	Sessions      int64         // SESSION-START 总数
	SessionsDone  int64         // 已等到 SESSION-END 的
	SessionDur    time.Duration // 已闭环会话总时长
	SessionDurMax time.Duration // 最长单会话

	AgentConnects int64         // AGENT-CONNECT 总数
	AgentOnline   time.Duration // 已配对 CONNECT/DISCONNECT 的总在线时长

	AuthOK   int64
	AuthFail int64

	// 分主体聚合：SessionUsers 键是 SESSION-START 的 user=（账号名），
	// AgentMachines 键是 AGENT-* 的 id=（机器全名）。
	SessionUsers  map[string]*UseStat
	AgentMachines map[string]*UseStat

	pendSess  map[string][]pendStart // 会话 id -> 还没等到 END 的 START（FIFO 配对）
	pendAgent map[string][]time.Time // 机器 id -> 还没等到 DISCONNECT 的 CONNECT
}

type pendStart struct {
	ts   time.Time
	user string
}

// Scan 读审计日志聚合统计。轮转文件 <path>.1 是上一轮的旧内容，先扫它
// 再扫 <path>，START 在旧文件、END 在新文件的会话也能配上对。
// since 非零时只统计 ts >= since 的行（配对要求两端都在窗内）。文件不
// 存在返回空统计、不算错——审计本来就可能没开。
func Scan(path string, since time.Time) (*Stats, error) {
	st := &Stats{
		Events:        map[string]int64{},
		SessionUsers:  map[string]*UseStat{},
		AgentMachines: map[string]*UseStat{},
		pendSess:      map[string][]pendStart{},
		pendAgent:     map[string][]time.Time{},
	}
	if path == "" {
		return st, nil
	}
	for _, f := range []string{path + ".1", path} {
		if err := st.scanFile(f, since); err != nil {
			return st, err
		}
	}
	return st, nil
}

// SessionsOpen / AgentsLive 是「扫到文件尾仍没等到收尾事件」的存量——
// 可能是真在进行中，也可能是上轮进程没留 END 就没了，语义上只是「未闭环」。
func (s *Stats) SessionsOpen() int64 {
	var n int64
	for _, q := range s.pendSess {
		n += int64(len(q))
	}
	return n
}

func (s *Stats) AgentsLive() int64 {
	var n int64
	for _, q := range s.pendAgent {
		n += int64(len(q))
	}
	return n
}

func (s *Stats) scanFile(path string, since time.Time) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		s.line(sc.Text(), since)
	}
	return sc.Err()
}

func (s *Stats) line(text string, since time.Time) {
	i := strings.IndexByte(text, ' ')
	if i < 0 {
		return
	}
	ts, err := time.Parse(time.RFC3339, text[:i])
	if err != nil || (!since.IsZero() && ts.Before(since)) {
		return
	}
	rest := text[i+1:]
	j := strings.IndexByte(rest, ' ')
	event, kvStr := rest, ""
	if j >= 0 {
		event, kvStr = rest[:j], rest[j+1:]
	}
	kv := parseKV(kvStr)

	s.Events[event]++
	if s.First.IsZero() {
		s.First = ts
	}
	s.Last = ts

	switch event {
	case "SESSION-START":
		s.Sessions++
		u := kv["user"]
		if u != "" {
			useStat(s.SessionUsers, u).Count++
		}
		if id := kv["id"]; id != "" {
			s.pendSess[id] = append(s.pendSess[id], pendStart{ts, u})
		}
	case "SESSION-END":
		if q := s.pendSess[kv["id"]]; len(q) > 0 {
			st := q[0]
			s.pendSess[kv["id"]] = q[1:]
			d := ts.Sub(st.ts)
			s.SessionsDone++
			s.SessionDur += d
			if d > s.SessionDurMax {
				s.SessionDurMax = d
			}
			if st.user != "" {
				useStat(s.SessionUsers, st.user).Dur += d
			}
		}
	case "AGENT-CONNECT":
		s.AgentConnects++
		if id := kv["id"]; id != "" {
			useStat(s.AgentMachines, id).Count++
			s.pendAgent[id] = append(s.pendAgent[id], ts)
		}
	case "AGENT-DISCONNECT":
		if q := s.pendAgent[kv["id"]]; len(q) > 0 {
			s.pendAgent[kv["id"]] = q[1:]
			d := ts.Sub(q[0])
			s.AgentOnline += d
			useStat(s.AgentMachines, kv["id"]).Dur += d
		}
	case "AUTH-OK":
		s.AuthOK++
	case "AUTH-FAIL":
		s.AuthFail++
	}
}

// useStat 取键对应的聚合桶，没有就建一个。
func useStat(m map[string]*UseStat, k string) *UseStat {
	u := m[k]
	if u == nil {
		u = &UseStat{}
		m[k] = u
	}
	return u
}

// parseKV 解「k=v k="quoted v"」串。值带引号用 strconv.Unquote 还原——
// 和 Writer.Log 的 Quote 写入互为镜像。
func parseKV(s string) map[string]string {
	m := map[string]string{}
	for s != "" {
		i := strings.IndexByte(s, '=')
		if i < 0 {
			break
		}
		k, rest := s[:i], s[i+1:]
		if strings.HasPrefix(rest, "\"") {
			end := 1
			for end < len(rest) {
				if rest[end] == '\\' {
					end += 2
					continue
				}
				if rest[end] == '"' {
					end++
					break
				}
				end++
			}
			v, err := strconv.Unquote(rest[:end])
			if err != nil {
				v = rest[:end]
			}
			m[k] = v
			s = strings.TrimLeft(rest[end:], " ")
		} else {
			j := strings.IndexByte(rest, ' ')
			if j < 0 {
				m[k] = rest
				break
			}
			m[k] = rest[:j]
			s = strings.TrimLeft(rest[j+1:], " ")
		}
	}
	return m
}

// TopN 把分主体聚合按 Count 降序截前 n 名，供展示用。
func TopN(m map[string]*UseStat, n int) []NamedStat {
	var es []NamedStat
	for k, v := range m {
		es = append(es, NamedStat{Name: k, UseStat: *v})
	}
	sort.Slice(es, func(i, j int) bool {
		if es[i].Count != es[j].Count {
			return es[i].Count > es[j].Count
		}
		return es[i].Name < es[j].Name
	})
	if len(es) > n {
		es = es[:n]
	}
	return es
}

// NamedStat 是 TopN 的返回项：主体名 + 聚合值。
type NamedStat struct {
	Name string
	UseStat
}
