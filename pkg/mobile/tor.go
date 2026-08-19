// Package mobile 提供 gomobile 可绑定的 Tor 客户端薄封装。
//
// 本包只暴露 string / int / bool / error / 简单方法 / StatusListener，
// 不导出 *client.Client、context、map 或 channel。
// Android 工程、Gradle、VpnService、Sample App 不在本仓库。
package mobile

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"

	"github.com/opd-ai/go-tor/pkg/client"
	"github.com/opd-ai/go-tor/pkg/logger"
)

const defaultStatus = "未启动"

// StatusListener 接收引导进度与生命周期回调。
// 实现应尽快返回；不要在回调中再次调用 Start/Stop，以免死锁。
type StatusListener interface {
	OnBootstrap(percent int, msg string)
	OnReady()
	OnError(msg string)
	OnStopped()
}

// Tor 是 Android / gomobile 绑定入口。必须由调用方传入 dataDir。
type Tor struct {
	mu sync.Mutex

	client   *client.Client
	listener StatusListener

	starting      bool
	started       bool
	stopRequested bool
	startCancel   context.CancelFunc
	epoch         uint64

	socksPort int

	bootstrapPercent int
	statusText       string
}

// NewTor 创建尚未启动的客户端。
func NewTor() *Tor {
	return &Tor{statusText: defaultStatus}
}

// SetListener 设置状态回调，可为 nil。
func (t *Tor) SetListener(l StatusListener) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.listener = l
	t.mu.Unlock()
}

// Start 启动 Tor 客户端。dataDir 不能为空；SOCKS 只绑定 127.0.0.1。
// 该方法会阻塞至引导完成或失败，请勿在 Android 主线程调用。
func (t *Tor) Start(dataDir string, socksPort int) error {
	if t == nil {
		return errors.New("Tor 实例为空")
	}
	if err := validateStartArgs(dataDir, socksPort); err != nil {
		notifyError(t.snapshotListener(), err.Error())
		return err
	}

	t.mu.Lock()
	if t.started || t.starting {
		t.mu.Unlock()
		err := errors.New("Tor 已启动或正在启动，请先 Stop")
		notifyError(t.snapshotListener(), err.Error())
		return err
	}
	t.starting = true
	t.stopRequested = false
	t.socksPort = socksPort
	t.setStatusLocked(5, "正在初始化")
	ctx, cancel := context.WithCancel(context.Background())
	t.startCancel = cancel
	t.mu.Unlock()

	notifyBootstrap(t.snapshotListener(), 5, "正在初始化")

	defer func() {
		t.mu.Lock()
		t.starting = false
		// 成功启动后绝不能 cancel 传给 client.Start 的 ctx：
		// client 会把它并入生命周期，取消会导致 SOCKS 立刻退出。
		if t.started {
			t.mu.Unlock()
			return
		}
		t.startCancel = nil
		t.mu.Unlock()
		cancel()
	}()

	cfg := buildMobileConfig(dataDir, socksPort)
	if err := enforceLoopbackSocks(cfg); err != nil {
		t.setStatus(0, "启动失败")
		notifyError(t.snapshotListener(), err.Error())
		return err
	}

	c, err := client.New(cfg, newMobileLogger())
	if err != nil {
		t.setStatus(0, "启动失败")
		msg := fmt.Sprintf("创建 Tor 客户端失败: %v", err)
		notifyError(t.snapshotListener(), msg)
		return errors.New(msg)
	}

	if t.consumeStopRequest() {
		_ = c.Stop()
		t.finishCancelled()
		return errors.New("启动已取消")
	}

	t.setStatus(20, "正在引导")
	notifyBootstrap(t.snapshotListener(), 20, "正在引导")

	if err := c.Start(ctx); err != nil {
		_ = c.Stop()
		if t.consumeStopRequest() || ctx.Err() != nil {
			t.finishCancelled()
			return errors.New("启动已取消")
		}
		t.setStatus(0, "启动失败")
		msg := fmt.Sprintf("启动 Tor 客户端失败: %v", err)
		notifyError(t.snapshotListener(), msg)
		return errors.New(msg)
	}

	t.mu.Lock()
	if t.stopRequested {
		t.mu.Unlock()
		_ = c.Stop()
		t.finishCancelled()
		return errors.New("启动已取消")
	}
	t.epoch++
	startEpoch := t.epoch
	t.client = c
	t.started = true
	t.setStatusLocked(100, "就绪")
	t.mu.Unlock()

	t.notifyReadyIfCurrent(startEpoch)
	return nil
}

// Stop 停止客户端。未启动或重复调用是安全的。
func (t *Tor) Stop() error {
	if t == nil {
		return nil
	}

	t.mu.Lock()
	if t.starting && !t.started {
		t.stopRequested = true
		if t.startCancel != nil {
			t.startCancel()
		}
		t.mu.Unlock()
		return nil
	}
	if !t.started || t.client == nil {
		t.started = false
		t.client = nil
		t.mu.Unlock()
		return nil
	}
	c := t.client
	cancelFn := t.startCancel
	t.client = nil
	t.started = false
	t.startCancel = nil
	t.epoch++
	t.mu.Unlock()

	if cancelFn != nil {
		cancelFn()
	}
	err := c.Stop()
	t.setStatus(0, "已停止")
	notifyStopped(t.snapshotListener())
	return err
}

// IsReady 表示已启动且有可用电路。
func (t *Tor) IsReady() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	c := t.client
	started := t.started
	t.mu.Unlock()
	if !started || c == nil {
		return false
	}
	return clientIsReady(c)
}

// SocksAddr 返回 "127.0.0.1:port"；未启动时为空字符串。
func (t *Tor) SocksAddr() string {
	if t == nil {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.started || t.socksPort < 1 {
		return ""
	}
	return net.JoinHostPort(socksBindAddr, strconv.Itoa(t.socksPort))
}

// BootstrapPercent 返回 0–100 的引导进度估计。
func (t *Tor) BootstrapPercent() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.bootstrapPercent
}

// StatusText 返回简短状态文案，适合 UI 展示。
func (t *Tor) StatusText() string {
	if t == nil {
		return defaultStatus
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.statusText == "" {
		return defaultStatus
	}
	return t.statusText
}

func (t *Tor) consumeStopRequest() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stopRequested
}

func (t *Tor) finishCancelled() {
	t.setStatus(0, "已停止")
	notifyStopped(t.snapshotListener())
}

// notifyReadyIfCurrent 仅在本轮启动仍有效时发出就绪回调，避免 Stop 之后误报 OnReady。
func (t *Tor) notifyReadyIfCurrent(epoch uint64) {
	l := t.snapshotListener()
	t.mu.Lock()
	ok := t.started && t.epoch == epoch
	t.mu.Unlock()
	if !ok {
		return
	}
	notifyBootstrap(l, 100, "就绪")
	t.mu.Lock()
	ok = t.started && t.epoch == epoch
	t.mu.Unlock()
	if ok {
		notifyReady(l)
	}
}

func clientIsReady(c *client.Client) bool {
	if c == nil {
		return false
	}
	stats := c.GetStats()
	if stats.ActiveCircuits > 0 {
		return true
	}
	return stats.CircuitPoolEnabled && stats.CircuitPoolOpen > 0
}

func newMobileLogger() *logger.Logger {
	// info 便于 logcat 接日志；不使用 debug，避免默认输出电路细节。
	level, err := logger.ParseLevel("info")
	if err != nil {
		return logger.NewDefault()
	}
	return logger.New(level, os.Stdout)
}
