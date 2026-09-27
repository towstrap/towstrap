package client

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/towstrap/towstrap/internal/selfupdate"
)

// stubUpdate 把升级路径的三处外部依赖换成记录器：Run 记录调用、
// 散开等 0、restart 只记标志不换进程映像。
func stubUpdate(t *testing.T, runErr error) (calls *atomic.Int64, restarted *atomic.Bool) {
	t.Helper()
	calls = &atomic.Int64{}
	restarted = &atomic.Bool{}
	origRun, origSpread, origRestart := selfUpdateRun, updateSpread, doRestart
	selfUpdateRun = func(selfupdate.Opts) error {
		calls.Add(1)
		return runErr
	}
	updateSpread = 0
	doRestart = func() { restarted.Store(true) }
	t.Cleanup(func() {
		selfUpdateRun, updateSpread, doRestart = origRun, origSpread, origRestart
	})
	return calls, restarted
}

func waitUpgrading(t *testing.T, a *agent) {
	t.Helper()
	for i := 0; i < 200 && a.upgrading.Load(); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if a.upgrading.Load() {
		t.Fatal("升级协程没退出")
	}
}

func TestOnUpgradeRuns(t *testing.T) {
	calls, restarted := stubUpdate(t, nil)
	a := &agent{cfg: Config{AutoUpdate: true}}
	a.onUpgrade("v99.0.0") // 远大于任何当前版本
	waitUpgrading(t, a)
	if calls.Load() != 1 {
		t.Fatalf("selfupdate 应被调一次，实际 %d", calls.Load())
	}
	if !restarted.Load() {
		t.Fatal("升级成功后应重启生效")
	}
}

func TestOnUpgradeSkips(t *testing.T) {
	calls, _ := stubUpdate(t, nil)
	a := &agent{cfg: Config{AutoUpdate: true}}
	for _, tag := range []string{
		"",                  // 空
		"0.0.1",             // 低于当前
		"../evil",           // 畸形（路径穿越味道）
		"v99.0.0; rm -rf /", // 注入味道
	} {
		a.onUpgrade(tag)
	}
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatalf("不该起升级，实际调了 %d 次", calls.Load())
	}
}

func TestOnUpgradeRespectsDisable(t *testing.T) {
	calls, _ := stubUpdate(t, nil)
	a := &agent{cfg: Config{AutoUpdate: false}}
	a.onUpgrade("v99.0.0")
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatal("auto_update 关掉时不该动手")
	}
}

func TestOnUpgradeSingleFlight(t *testing.T) {
	calls, _ := stubUpdate(t, nil)
	a := &agent{cfg: Config{AutoUpdate: true}}
	a.upgrading.Store(true) // 假装一个升级正在跑
	a.onUpgrade("v99.0.0")
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatal("已有升级在跑时不该再起一个")
	}
}

func TestOnUpgradeFailureKeepsRunning(t *testing.T) {
	calls, restarted := stubUpdate(t, errors.New("网络炸了"))
	a := &agent{cfg: Config{AutoUpdate: true}}
	a.onUpgrade("v99.0.0")
	waitUpgrading(t, a)
	if calls.Load() != 1 {
		t.Fatalf("应尝试一次，实际 %d", calls.Load())
	}
	if restarted.Load() {
		t.Fatal("升级失败不该重启")
	}
	// 失败后单飞锁已释放：服务器下一次推送（重连/下一轮扫描）还能再试。
	a.onUpgrade("v99.0.0")
	waitUpgrading(t, a)
	if calls.Load() != 2 {
		t.Fatalf("失败后应能重试，实际累计 %d", calls.Load())
	}
}
