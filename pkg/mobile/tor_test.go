package mobile

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type recordingListener struct {
	mu         sync.Mutex
	bootstraps []string
	percents   []int
	ready      int
	errors     []string
	stopped    int
}

func (l *recordingListener) OnBootstrap(percent int, msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.percents = append(l.percents, percent)
	l.bootstraps = append(l.bootstraps, msg)
}

func (l *recordingListener) OnReady() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ready++
}

func (l *recordingListener) OnError(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errors = append(l.errors, msg)
}

func (l *recordingListener) OnStopped() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stopped++
}

func (l *recordingListener) errorCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.errors)
}

func TestAPIShape(t *testing.T) {
	t.Parallel()

	_ = NewTor
	var tor *Tor
	_ = tor.Start
	_ = tor.Stop
	_ = tor.IsReady
	_ = tor.SocksAddr
	_ = tor.BootstrapPercent
	_ = tor.StatusText
	_ = tor.SetListener

	var _ StatusListener = (*recordingListener)(nil)
}

func TestUnstartedBehavior(t *testing.T) {
	t.Parallel()

	tor := NewTor()
	if tor.IsReady() {
		t.Fatal("未 Start 时 IsReady 应为 false")
	}
	if addr := tor.SocksAddr(); addr != "" {
		t.Fatalf("未 Start 时 SocksAddr 应为空, got %q", addr)
	}
	if tor.BootstrapPercent() != 0 {
		t.Fatalf("未 Start 时进度应为 0, got %d", tor.BootstrapPercent())
	}
	if tor.StatusText() != defaultStatus {
		t.Fatalf("未 Start 状态文案不符: %q", tor.StatusText())
	}
	if err := tor.Stop(); err != nil {
		t.Fatalf("未 Start 时 Stop 应成功: %v", err)
	}
	if err := tor.Stop(); err != nil {
		t.Fatalf("重复 Stop 应成功: %v", err)
	}
}

func TestNilReceiverSafe(t *testing.T) {
	t.Parallel()

	var tor *Tor
	if err := tor.Start(t.TempDir(), 9050); err == nil {
		t.Fatal("空接收者 Start 应报错")
	}
	if err := tor.Stop(); err != nil {
		t.Fatalf("空接收者 Stop 应成功: %v", err)
	}
	if tor.IsReady() || tor.SocksAddr() != "" || tor.BootstrapPercent() != 0 {
		t.Fatal("空接收者查询应返回零值")
	}
	if tor.StatusText() != defaultStatus {
		t.Fatalf("空接收者 StatusText=%q", tor.StatusText())
	}
	tor.SetListener(nil)
}

func TestStartEmptyDataDir(t *testing.T) {
	t.Parallel()

	tor := NewTor()
	lis := &recordingListener{}
	tor.SetListener(lis)

	if err := tor.Start("", 9050); err == nil {
		t.Fatal("空 dataDir 的 Start 应失败")
	}
	if tor.IsReady() {
		t.Fatal("失败后不应就绪")
	}
	if lis.errorCount() == 0 {
		t.Fatal("空 dataDir 应触发 OnError")
	}
}

func TestStartInvalidSocksPort(t *testing.T) {
	t.Parallel()

	tor := NewTor()
	lis := &recordingListener{}
	tor.SetListener(lis)

	if err := tor.Start(t.TempDir(), 0); err == nil {
		t.Fatal("非法 socksPort 的 Start 应失败")
	}
	if lis.errorCount() == 0 {
		t.Fatal("非法端口应触发 OnError")
	}
}

func TestStartDataDirIsFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	filePath := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	tor := NewTor()
	lis := &recordingListener{}
	tor.SetListener(lis)

	// client.New 会因路径不是目录失败，不会连真实网络。
	if err := tor.Start(filePath, 19052); err == nil {
		t.Fatal("dataDir 为文件时 Start 应失败")
	}
	if tor.IsReady() || tor.started {
		t.Fatal("失败路径不应留下 started 状态")
	}
	if lis.errorCount() == 0 {
		t.Fatal("失败路径应触发 OnError")
	}
}

func TestRepeatStartRejected(t *testing.T) {
	t.Parallel()

	tor := NewTor()
	tor.started = true
	tor.socksPort = 9050

	if err := tor.Start(t.TempDir(), 9050); err == nil {
		t.Fatal("重复 Start 应报错")
	}
	if addr := tor.SocksAddr(); addr != "127.0.0.1:9050" {
		t.Fatalf("已标记启动时 SocksAddr=%q", addr)
	}
}

func TestStartingBlocksSecondStart(t *testing.T) {
	t.Parallel()

	tor := NewTor()
	tor.starting = true
	if err := tor.Start(t.TempDir(), 9050); err == nil {
		t.Fatal("正在启动时再次 Start 应报错")
	}
}

func TestListenerNilSafe(t *testing.T) {
	t.Parallel()

	notifyBootstrap(nil, 10, "x")
	notifyReady(nil)
	notifyError(nil, "e")
	notifyStopped(nil)

	tor := NewTor()
	tor.SetListener(nil)
	notifyBootstrap(tor.snapshotListener(), 1, "init")
}

func TestListenerCallbacks(t *testing.T) {
	t.Parallel()

	lis := &recordingListener{}
	notifyBootstrap(lis, 20, "正在引导")
	notifyReady(lis)
	notifyError(lis, "失败")
	notifyStopped(lis)

	lis.mu.Lock()
	defer lis.mu.Unlock()
	if len(lis.percents) != 1 || lis.percents[0] != 20 {
		t.Fatalf("OnBootstrap 记录不符: %v", lis.percents)
	}
	if lis.ready != 1 || lis.stopped != 1 || len(lis.errors) != 1 {
		t.Fatalf("回调次数不符 ready=%d stopped=%d errors=%v", lis.ready, lis.stopped, lis.errors)
	}
}

type panicListener struct{}

func (panicListener) OnBootstrap(int, string) { panic("bootstrap") }
func (panicListener) OnReady()                { panic("ready") }
func (panicListener) OnError(string)          { panic("error") }
func (panicListener) OnStopped()              { panic("stopped") }

func TestListenerPanicRecovered(t *testing.T) {
	t.Parallel()

	l := panicListener{}
	notifyBootstrap(l, 1, "x")
	notifyReady(l)
	notifyError(l, "e")
	notifyStopped(l)
}

func TestStopDuringStartRequestsCancel(t *testing.T) {
	t.Parallel()

	tor := NewTor()
	ctxCanceled := make(chan struct{})
	tor.mu.Lock()
	tor.starting = true
	tor.startCancel = func() { close(ctxCanceled) }
	tor.mu.Unlock()

	if err := tor.Stop(); err != nil {
		t.Fatalf("启动中 Stop 应立即返回: %v", err)
	}
	select {
	case <-ctxCanceled:
	case <-time.After(time.Second):
		t.Fatal("Stop 应取消 Start 的 context")
	}
	if !tor.consumeStopRequest() {
		t.Fatal("应记录 stopRequested")
	}
}

func TestConcurrentReadsAndStop(t *testing.T) {
	t.Parallel()

	tor := NewTor()
	var wg sync.WaitGroup
	var stops atomic.Int32
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tor.SetListener(&recordingListener{})
			_ = tor.IsReady()
			_ = tor.SocksAddr()
			_ = tor.BootstrapPercent()
			_ = tor.StatusText()
			if err := tor.Stop(); err != nil {
				t.Errorf("并发 Stop: %v", err)
			}
			stops.Add(1)
		}()
	}
	wg.Wait()
	if stops.Load() != 16 {
		t.Fatalf("并发 Stop 次数=%d", stops.Load())
	}
}

func TestNotifyReadySkippedAfterEpochBump(t *testing.T) {
	t.Parallel()

	tor := NewTor()
	lis := &recordingListener{}
	tor.SetListener(lis)
	tor.started = true
	tor.epoch = 1
	tor.epoch = 2 // 模拟 Stop 推进代数
	tor.notifyReadyIfCurrent(1)

	lis.mu.Lock()
	defer lis.mu.Unlock()
	if lis.ready != 0 || len(lis.percents) != 0 {
		t.Fatalf("代数已变时不应 OnReady: ready=%d percents=%v", lis.ready, lis.percents)
	}
}

func TestNotifyReadyIfCurrent(t *testing.T) {
	t.Parallel()

	tor := NewTor()
	lis := &recordingListener{}
	tor.SetListener(lis)
	tor.started = true
	tor.epoch = 3
	tor.notifyReadyIfCurrent(3)

	lis.mu.Lock()
	defer lis.mu.Unlock()
	if lis.ready != 1 || len(lis.percents) != 1 || lis.percents[0] != 100 {
		t.Fatalf("当前代数应通知就绪: ready=%d percents=%v", lis.ready, lis.percents)
	}
}

func TestSocksAddrFormatWhenStarted(t *testing.T) {
	t.Parallel()

	tor := NewTor()
	tor.started = true
	tor.socksPort = 9150
	if got := tor.SocksAddr(); got != "127.0.0.1:9150" {
		t.Fatalf("SocksAddr=%q, want 127.0.0.1:9150", got)
	}
}
