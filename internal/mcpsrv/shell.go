package mcpsrv

// 常驻 shell：run_command 带 session 参数时，命令不再每次新起 shell，
// 而是写进一个按名字保持的远端 shell 进程——cd、export、source、
// 后台任务自然保留，跟本地终端一样。
//
// 完成判定靠哨兵：每条命令后面跟一行
//   __tsec_<tag>=$?; printf '\n__TS_<tag>_<seq>_%d\n' ...（stdout/stderr 各一份）
// 两条流的哨兵都到了，这条命令才算结束（两条流之间没有顺序保证，只等
// 一条会丢另一条尾巴上的数据）。tag 是会话级随机串、seq 逐条递增——
// 命令自己的输出伪造不了哨兵，不会造成「提前收工」。
//
// 已知的真实边界：命令是 exit/exec 这类把 shell 终结掉的，整个会话
// 死掉，下一次同名调用换新 shell（会标注 restarted）；命令超时会把整个
// shell 杀掉——shell 可能还在跑那条命令，留着它状态没法信，宁可重来。

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// markerKeep 是 pump 留给「还没凑齐的哨兵」的尾巴字节数：哨兵最长约
// 50 字节（前缀 + seq + 退出码 + 换行），留 128 足够跨读buffer 边界识别。
const markerKeep = 128

var sessNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// shellCall 是一次在途命令：两条流各自的截断缓冲、哨兵判定状态。
type shellCall struct {
	seq      int
	out, err *CapWriter
	// tail 是每条流还没法判定「是不是哨兵开头」的尾巴字节；
	// 哨兵确认后整条剥离，不进输出。
	tailOut, tailErr []byte
	ec               int
	gotOut, gotErr   bool
	fail             error // shell 中途死了
	done             chan struct{}
}

type shellSession struct {
	sh   Shell
	tag  string // 随机前缀，拼进哨兵防伪造
	name string

	execMu  sync.Mutex // 同一个 shell 里的命令串行
	mu      sync.Mutex // 保护下面几个字段
	cur     *shellCall
	backlog []byte // 两次命令之间到达的输出（后台任务的），并进下一条的 stdout
	seq     int
	dead    bool
	busy    bool // 有在途命令（回收器不碰）
	lastUse time.Time
}

func newShellSession(sh Shell, name string) *shellSession {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return &shellSession{sh: sh, tag: hex.EncodeToString(b), name: name, lastUse: time.Now()}
}

// start 起两个泵分别吃 stdout/stderr，活的就这一条命。
func (s *shellSession) start() {
	go s.pump(s.sh.Stdout(), false)
	go s.pump(s.sh.Stderr(), true)
}

func (s *shellSession) alive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.dead
}

// idleFor 返回空闲时长；有在途命令视为活跃。
func (s *shellSession) idleFor() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.busy {
		return 0
	}
	return time.Since(s.lastUse)
}

// marker 是这条命令的哨兵前缀（不含退出码）。
func (s *shellSession) marker(seq int) []byte {
	return []byte(fmt.Sprintf("__TS_%s_%d_", s.tag, seq))
}

// feed 是泵收到一片输出后的处理：没有在途命令就堆进 backlog；有就先扫
// 哨兵，扫到就收尾这条流，扫不到把安全部分推进缓冲。
func (s *shellSession) feed(b []byte, isErr bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dead {
		return
	}
	c := s.cur
	if c == nil {
		s.backlog = append(s.backlog, b...)
		if len(s.backlog) > 64<<10 {
			s.backlog = s.backlog[len(s.backlog)-64<<10:]
		}
		return
	}

	var tail *[]byte
	var w *CapWriter
	var doneFlag *bool
	if isErr {
		tail, w, doneFlag = &c.tailErr, c.err, &c.gotErr
	} else {
		tail, w, doneFlag = &c.tailOut, c.out, &c.gotOut
	}
	if *doneFlag {
		_, _ = w.Write(b) // 哨兵之后这条流的残余（正常不该有）
		return
	}
	*tail = append(*tail, b...)
	mk := s.marker(c.seq)
	for {
		i := bytes.Index(*tail, mk)
		if i < 0 {
			break
		}
		j := i + len(mk)
		k := j
		for k < len(*tail) && (*tail)[k] >= '0' && (*tail)[k] <= '9' {
			k++
		}
		switch {
		case k == len(*tail):
			// 哨兵尾巴还没来全（前缀或数字被切在两片之间），等下一波
			return
		case k > j && (*tail)[k] == '\n':
			// 真哨兵：前缀 + 至少一位数字 + 换行
			ec, _ := strconv.Atoi(string((*tail)[j:k]))
			end := i
			if end > 0 && (*tail)[end-1] == '\n' {
				end-- // 哨兵前的 \n 是我们 printf 打的，一起剥掉
			}
			_, _ = w.Write((*tail)[:end])
			c.ec = ec
			*doneFlag = true
			*tail = (*tail)[k+1:]
			if len(*tail) > 0 {
				_, _ = w.Write(*tail) // 哨兵后残余，正常不该有
				*tail = nil
			}
			s.finishLocked(c)
			return
		default:
			// 假命中：前缀出现在正常输出里（比如 set -x 把哨兵脚本
			// 回显出来）——前缀本身是输出内容，放到 j 为止，从 j 继续扫
			_, _ = w.Write((*tail)[:j])
			*tail = (*tail)[j:]
		}
	}
	// 没找到哨兵：留尾巴防哨兵被切断在两片之间，其余进缓冲
	if len(*tail) > markerKeep {
		_, _ = w.Write((*tail)[:len(*tail)-markerKeep])
		*tail = append((*tail)[:0], (*tail)[len(*tail)-markerKeep:]...)
	}
}

// streamDead 泵读到 EOF/错误：shell 死了。在途命令按失败收，会话标记死。
func (s *shellSession) streamDead(isErr bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dead = true
	s.busy = false
	if c := s.cur; c != nil {
		c.fail = fmt.Errorf("shell 会话中断（进程退出或连接断开）")
		select {
		case <-c.done:
		default:
			close(c.done)
		}
	}
}

func (s *shellSession) finishLocked(c *shellCall) {
	if c.gotOut && c.gotErr {
		select {
		case <-c.done:
		default:
			close(c.done)
		}
		s.cur = nil
		s.busy = false
		s.lastUse = time.Now()
	}
}

// exec 在常驻 shell 里跑一条命令：写命令行 + 双哨兵，等两条流的哨兵。
// 返回 errShellDead 表示 shell 中途死了（调用方决定要不要换个新的重试）。
var errShellDead = fmt.Errorf("shell exited")

func (s *shellSession) exec(ctx context.Context, cmd string, timeout time.Duration, maxOut int) (Result, error) {
	s.execMu.Lock()
	defer s.execMu.Unlock()

	s.mu.Lock()
	if s.dead {
		s.mu.Unlock()
		return Result{}, errShellDead
	}
	// seq 封顶：哨兵是 `__TS_<tag>_<seq>_<退出码>`，seq 太长会超过
	// markerKeep(128)，feed 会把没凑齐的哨兵尾巴当普通输出切碎，
	// 这条命令就永远等不到结束。16 位十进制远在 markerKeep 之内。
	// 到顶就停用整个会话（只设 dead，真杀交给调用方），不先自增。
	if s.seq >= 1e15 {
		s.dead = true
		s.mu.Unlock()
		_ = s.sh.Close()
		return Result{ExitCode: -1}, errShellDead
	}
	s.seq++
	c := &shellCall{seq: s.seq, out: NewCapWriter(maxOut), err: NewCapWriter(maxOut), done: make(chan struct{})}
	if len(s.backlog) > 0 {
		_, _ = c.out.Write(s.backlog)
		s.backlog = nil
	}
	s.cur = c
	s.busy = true
	s.lastUse = time.Now()
	tag := s.tag
	seq := s.seq
	s.mu.Unlock()

	// 命令和双哨兵并进同一行。cmd 在调用方已封成 `eval '字面量'`
	// （可选 `cd -- 'cwd' && ` 前缀）：
	//   - `|| __tsec=$?` 接住失败码，也让左边在 set -e 下免死（|| 左臂
	//     不做 -e 检查）；先 `=0` 初始化是为了 set -u 下展开不报错；
	//   - printf 自己会改 $?，所以退出码只能走变量，不能 inline。
	line := fmt.Sprintf("__tsec_%s=0; %s || __tsec_%s=$?; printf '\\n__TS_%s_%d_%%d\\n' \"$__tsec_%s\"; printf '\\n__TS_%s_%d_%%d\\n' \"$__tsec_%s\" >&2\n",
		tag, cmd, tag, tag, seq, tag, tag, seq, tag)
	start := time.Now()
	if _, err := s.sh.Write([]byte(line)); err != nil {
		// 写都写不进去 = 通道死了。只标 dead 不关 shell 的话，远端
		// 进程和两个泵会一直吊着——直接杀掉走正常收尾。
		s.kill()
		return Result{Duration: time.Since(start), ExitCode: -1}, errShellDead
	}

	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-c.done:
	case <-ctx.Done():
		s.kill()
		return Result{Duration: time.Since(start), ExitCode: -1}, ctx.Err()
	case <-t.C:
		res, _ := c.snapshot(&s.mu)
		res.TimedOut = true
		res.ExitCode = -1
		res.Duration = time.Since(start)
		s.kill()
		return res, nil
	}
	res, fail := c.snapshot(&s.mu)
	res.Duration = time.Since(start)
	if fail != nil {
		return res, errShellDead
	}
	return res, nil
}

// snapshot 读这次命令的累积输出和失败标记。必须在 s.mu 下做：泵在哨兵
// 落定后仍可能往 CapWriter 里补残余字节，所有写都拿 s.mu，读也得同一把锁。
func (c *shellCall) snapshot(mu *sync.Mutex) (Result, error) {
	mu.Lock()
	defer mu.Unlock()
	return Result{
		Stdout:          c.out.String(),
		Stderr:          c.err.String(),
		StdoutTruncated: c.out.Truncated(),
		StderrTruncated: c.err.Truncated(),
		ExitCode:        c.ec,
	}, c.fail
}

// kill 杀掉整个 shell（超时/取消/出错/回收时用）——会话标记死，进程关掉。
func (s *shellSession) kill() {
	s.mu.Lock()
	s.dead = true
	s.mu.Unlock()
	_ = s.sh.Close()
}

func (s *shellSession) pump(r io.Reader, isErr bool) {
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			s.feed(buf[:n], isErr)
		}
		if err != nil {
			s.streamDead(isErr)
			return
		}
	}
}
