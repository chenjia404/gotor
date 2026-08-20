package relay

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/logger"
)

func testSelftestLog() *logger.Logger {
	return logger.New(slog.LevelInfo, io.Discard)
}

func TestReachabilityNilSafe(t *testing.T) {
	var r *Reachability
	if r.ShouldProbe() || r.CanPublish() {
		t.Fatal("nil 应安全")
	}
	r.SetProber(nil)
	r.SetOnReachable(nil)
	r.Stop()
	if r.Status().CanPublish {
		t.Fatal("nil status")
	}
}

func TestReachabilityAssumeReachableSkipsProbe(t *testing.T) {
	var probes atomic.Int32
	r := NewReachability(ReachabilityConfig{
		AssumeReachable: true,
		Address:         "192.0.2.1",
		ORPort:          9001,
		Publish:         true,
	}, testSelftestLog())
	r.SetProber(func(context.Context) error {
		probes.Add(1)
		return nil
	})

	if r.ShouldProbe() {
		t.Fatal("AssumeReachable 时不应探测")
	}
	if !r.CanPublish() {
		t.Fatal("AssumeReachable 应允许发布")
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if probes.Load() != 0 {
		t.Fatalf("AssumeReachable 仍调用了 prober: %d", probes.Load())
	}
	st := r.Status()
	if !st.Assumed || !st.CanPublish || !st.Reachable {
		t.Fatalf("status %+v", st)
	}
}

func TestReachabilityBlocksPublishUntilProbeSucceeds(t *testing.T) {
	r := NewReachability(ReachabilityConfig{
		Address: "192.0.2.1",
		ORPort:  9001,
		Publish: true,
	}, testSelftestLog())
	if r.CanPublish() {
		t.Fatal("未测活不得发布")
	}
	if !r.ShouldProbe() {
		t.Fatal("应探测")
	}

	r.SetProber(func(context.Context) error {
		return errors.New("extend failed")
	})
	if err := r.RunOnce(context.Background()); err == nil {
		t.Fatal("期望探测失败")
	}
	if r.CanPublish() {
		t.Fatal("失败后仍不得发布")
	}
	st := r.Status()
	if st.Reachable || st.Attempts != 1 || st.LastError == "" {
		t.Fatalf("失败快照 %+v", st)
	}

	r.SetProber(func(context.Context) error { return nil })
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !r.CanPublish() || !r.Status().Reachable {
		t.Fatal("成功后应允许发布")
	}
	if r.ShouldProbe() {
		t.Fatal("成功后不应再探测")
	}
}

func TestReachabilityDisableNetworkNoPublishNoProbe(t *testing.T) {
	var probes atomic.Int32
	r := NewReachability(ReachabilityConfig{
		AssumeReachable: true,
		DisableNetwork:  true,
		Address:         "192.0.2.1",
		ORPort:          9001,
		Publish:         true,
	}, testSelftestLog())
	r.SetProber(func(context.Context) error {
		probes.Add(1)
		return nil
	})
	if r.ShouldProbe() {
		t.Fatal("DisableNetwork 不应探测")
	}
	if r.CanPublish() {
		t.Fatal("DisableNetwork 不应发布")
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if probes.Load() != 0 {
		t.Fatal("DisableNetwork 调用了 prober")
	}
}

func TestReachabilityMissingAddressCannotPublish(t *testing.T) {
	r := NewReachability(ReachabilityConfig{
		ORPort:  9001,
		Publish: true,
	}, testSelftestLog())
	if r.ShouldProbe() || r.CanPublish() {
		t.Fatal("无 Address 不得探测/发布")
	}
}

func TestReachabilityNoPublishFlag(t *testing.T) {
	r := NewReachability(ReachabilityConfig{
		Address: "192.0.2.1",
		ORPort:  9001,
		Publish: false,
	}, testSelftestLog())
	if r.ShouldProbe() || r.CanPublish() {
		t.Fatal("Publish=0 不测不发")
	}
}

func TestReachabilityMissingProberFails(t *testing.T) {
	r := NewReachability(ReachabilityConfig{
		Address: "192.0.2.1",
		ORPort:  9001,
		Publish: true,
	}, testSelftestLog())
	err := r.RunOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no circuit prober") {
		t.Fatalf("err=%v", err)
	}
	if r.CanPublish() {
		t.Fatal("无 prober 不得发布")
	}
}

func TestReachabilityOnReachableCallbackOnce(t *testing.T) {
	var n atomic.Int32
	r := NewReachability(ReachabilityConfig{
		Address: "192.0.2.1",
		ORPort:  9001,
		Publish: true,
	}, testSelftestLog())
	r.SetOnReachable(func() { n.Add(1) })
	r.SetProber(func(context.Context) error { return nil })
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n.Load() != 1 {
		t.Fatalf("回调次数 %d", n.Load())
	}
}

func TestReachabilityComplaintAfterFailures(t *testing.T) {
	r := NewReachability(ReachabilityConfig{
		Address:        "192.0.2.1",
		ORPort:         9001,
		Publish:        true,
		ComplaintAfter: time.Millisecond,
	}, testSelftestLog())
	r.SetProber(func(context.Context) error {
		return errors.New("still unreachable")
	})
	_ = r.RunOnce(context.Background())
	time.Sleep(2 * time.Millisecond)
	_ = r.RunOnce(context.Background())
	st := r.Status()
	if st.Attempts != 2 || st.CanPublish {
		t.Fatalf("%+v", st)
	}
}

func TestReachabilityLoopStopsOnSuccess(t *testing.T) {
	var probes atomic.Int32
	r := NewReachability(ReachabilityConfig{
		Address:       "192.0.2.1",
		ORPort:        9001,
		Publish:       true,
		RetryInterval: 15 * time.Millisecond,
	}, testSelftestLog())
	r.SetProber(func(context.Context) error {
		if probes.Add(1) == 1 {
			return errors.New("first fail")
		}
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if r.CanPublish() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !r.CanPublish() {
		t.Fatal("循环未在成功后允许发布")
	}
	r.Stop()
	r.Stop() // 幂等
	if probes.Load() < 2 {
		t.Fatalf("探测次数 %d", probes.Load())
	}
}

func TestReachabilityStatusHasNoRunningClaim(t *testing.T) {
	r := NewReachability(ReachabilityConfig{
		AssumeReachable: true,
		Address:         "192.0.2.1",
		ORPort:          9001,
		Publish:         true,
	}, testSelftestLog())
	_ = r.RunOnce(context.Background())
	st := r.Status()
	// 结构体本身没有 Running / Consensus 字段；成功只表示 CanPublish。
	if !st.CanPublish || !st.Assumed {
		t.Fatalf("%+v", st)
	}
}

func TestTestingHopHasExtendKeys(t *testing.T) {
	keys, err := GenerateRelayKeys()
	if err != nil {
		t.Fatal(err)
	}
	hop := keys.TestingHop("gotorTest", "192.0.2.10", 9001)
	if hop == nil {
		t.Fatal("TestingHop 返回 nil")
	}
	if !hop.HasExtendKeys() {
		t.Fatal("self-test 末跳缺 EXTEND2 密钥")
	}
	if hop.Address != "192.0.2.10" || hop.ORPort != 9001 {
		t.Fatalf("地址 %s:%d", hop.Address, hop.ORPort)
	}
	if hop.HasFlag("Running") {
		t.Fatal("TestingHop 不得带 Running flag")
	}
	if keys.TestingHop("x", "", 9001) != nil {
		t.Fatal("空地址应返回 nil")
	}
}

func TestReachabilityDoubleStart(t *testing.T) {
	r := NewReachability(ReachabilityConfig{
		AssumeReachable: true,
		Address:         "192.0.2.1",
		ORPort:          9001,
		Publish:         true,
		RetryInterval:   time.Hour,
	}, testSelftestLog())
	ctx := context.Background()
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	if err := r.Start(ctx); err == nil {
		t.Fatal("重复 Start 应失败")
	}
}
