package mobile

import (
	"fmt"
	"strings"

	"github.com/opd-ai/go-tor/pkg/config"
)

const (
	// socksBindAddr 是移动端 SOCKS 唯一允许的绑定地址，禁止 0.0.0.0。
	socksBindAddr = "127.0.0.1"

	// 电路池按移动端内存约束缩小。
	mobileCircuitPoolMin = 1
	mobileCircuitPoolMax = 3
)

// validateStartArgs 校验 Start 入参。dataDir 必须由调用方显式传入。
func validateStartArgs(dataDir string, socksPort int) error {
	if strings.TrimSpace(dataDir) == "" {
		return fmt.Errorf("dataDir 不能为空，必须由调用方传入应用私有目录")
	}
	if socksPort < 1 || socksPort > 65535 {
		return fmt.Errorf("非法 socksPort: %d（有效范围 1-65535）", socksPort)
	}
	return nil
}

// buildMobileConfig 构造移动端安全默认配置：仅本机 SOCKS，关闭多余端口与中继。
func buildMobileConfig(dataDir string, socksPort int) *config.Config {
	cfg := config.DefaultConfig()

	cfg.DataDirectory = dataDir
	cfg.CacheDirectory = ""
	cfg.SocksPort = socksPort
	cfg.SocksListenAddr = socksBindAddr
	cfg.SocksUnixPath = ""

	// Control / Metrics / DNSPort / HTTPTunnel 默认全关。
	cfg.ControlPort = 0
	cfg.ControlListenAddr = socksBindAddr
	cfg.ControlSocket = ""
	cfg.ControlPassword = ""
	cfg.HashedControlPassword = ""
	cfg.CookieAuthentication = false
	cfg.MetricsPort = 0
	cfg.EnableMetrics = false
	cfg.EnableProfiling = false
	cfg.DNSPort = 0
	cfg.HTTPTunnelPort = 0

	// 禁止中继与洋葱托管。
	cfg.ClientOnly = true
	cfg.ORPort = 0
	cfg.OnionServices = nil
	cfg.PublishServerDescriptor = false
	cfg.ExitRelay = false

	// 移动端小电路池。
	cfg.EnableCircuitPrebuilding = true
	cfg.CircuitPoolMinSize = mobileCircuitPoolMin
	cfg.CircuitPoolMaxSize = mobileCircuitPoolMax

	// 按目的地隔离，降低多应用误用同一回环代理时的电路混用。
	cfg.IsolationLevel = "destination"
	cfg.IsolateDestinations = true

	cfg.EnableTracing = false
	cfg.LogLevel = "info"

	return cfg
}

// enforceLoopbackSocks 防止配置被改成通配绑定。
func enforceLoopbackSocks(cfg *config.Config) error {
	if cfg == nil {
		return fmt.Errorf("配置为空")
	}
	if !isLoopbackBind(cfg.SocksListenAddr) {
		return fmt.Errorf("SOCKS 只能绑定 127.0.0.1，拒绝 %q", cfg.SocksListenAddr)
	}
	return nil
}

func isLoopbackBind(addr string) bool {
	switch strings.TrimSpace(addr) {
	case "127.0.0.1", "localhost":
		return true
	default:
		return false
	}
}
