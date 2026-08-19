package config

import (
	"fmt"
	"sort"
	"strings"
)

// DeprecatedTorrcOptions 是已识别但弃用的键（--list-deprecated-options）。
func DeprecatedTorrcOptions() []string {
	return []string{
		"SocksListenAddress",
		"ControlListenAddress",
		"ORListenAddress",
		"DirListenAddress",
		"DNSListenAddress",
		"NatdListenAddress",
		"TransListenAddress",
	}
}

// ModuleStatus 描述可选模块是否具备生产路径。
type ModuleStatus struct {
	Name    string
	Enabled bool
	Note    string
}

// ListModules 列出 drop-in 模块状态：relay 有、pt/exit 无生产。
func ListModules() []ModuleStatus {
	return []ModuleStatus{
		{Name: "relay", Enabled: true, Note: "ORPort 非出口中继"},
		{Name: "pt", Enabled: false, Note: "仅解析 UseBridges/Bridge/ClientTransportPlugin，无生产路径"},
		{Name: "exit", Enabled: false, Note: "ExitRelay 1 拒绝启动"},
	}
}

// FormatModules 生成 --list-modules 输出。
func FormatModules() string {
	var b strings.Builder
	for _, m := range ListModules() {
		yn := "no"
		if m.Enabled {
			yn = "yes"
		}
		fmt.Fprintf(&b, "%s: %s (%s)\n", m.Name, yn, m.Note)
	}
	return b.String()
}

// SocksEnabled 表示需要启动 SOCKS（TCP 端口或 unix socket）。
func (c *Config) SocksEnabled() bool {
	return c != nil && (c.SocksPort > 0 || c.SocksUnixPath != "")
}

// ControlEnabled 表示需要启动控制口（TCP 端口或 ControlSocket）。
func (c *Config) ControlEnabled() bool {
	return c != nil && (c.ControlPort > 0 || c.ControlSocket != "")
}

// EnsureControlAuth 在 CLI 路径上：只要控制口会监听且尚无认证，就启用 CookieAuthentication。
// 库 DefaultConfig()（AllowUnauthenticatedControl=true）不改动。
func (c *Config) EnsureControlAuth() {
	if c == nil || !c.ControlEnabled() || c.AllowUnauthenticatedControl {
		return
	}
	if !c.CookieAuthentication && c.ControlPassword == "" && c.HashedControlPassword == "" {
		c.CookieAuthentication = true
	}
}

// EffectiveCacheDirectory 返回 CacheDirectory，空则回退 DataDirectory。
func (c *Config) EffectiveCacheDirectory() string {
	if c == nil {
		return ""
	}
	if c.CacheDirectory != "" {
		return c.CacheDirectory
	}
	return c.DataDirectory
}

// CheckDropInConstraints 检查 drop-in 二进制不允许的组合（不改变 Validate 库行为）。
func (c *Config) CheckDropInConstraints() error {
	if c == nil {
		return fmt.Errorf("config cannot be nil")
	}
	if c.ExitRelay {
		return fmt.Errorf("ExitRelay 1 不受支持：gotor 不会作为出口中继运行")
	}
	if c.ClientOnly && c.ORPort > 0 {
		return fmt.Errorf("ClientOnly 1 与 ORPort 冲突：客户端模式不会启动中继")
	}
	if c.TransPort != 0 {
		return fmt.Errorf("TransPort 未实现（gotor 不提供透明代理）")
	}
	if c.NATDPort != 0 {
		return fmt.Errorf("NATDPort 未实现")
	}
	return nil
}

// DumpConfig 输出 --dump-config short|full。
func DumpConfig(cfg *Config, mode string) string {
	if cfg == nil {
		return ""
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "short"
	}
	defaults := DefaultCLIConfig()
	type pair struct {
		k, v string
	}
	all := []pair{
		{"SocksPort", fmt.Sprintf("%d", cfg.SocksPort)},
		{"SocksListenAddr", cfg.SocksListenAddr},
		{"ControlPort", fmt.Sprintf("%d", cfg.ControlPort)},
		{"ControlListenAddr", cfg.ControlListenAddr},
		{"ControlSocket", cfg.ControlSocket},
		{"SocksUnixPath", cfg.SocksUnixPath},
		{"DataDirectory", cfg.DataDirectory},
		{"CacheDirectory", cfg.EffectiveCacheDirectory()},
		{"PidFile", cfg.PidFile},
		{"RunAsDaemon", formatBool(cfg.RunAsDaemon)},
		{"ClientOnly", formatBool(cfg.ClientOnly)},
		{"DisableNetwork", formatBool(cfg.DisableNetwork)},
		{"HTTPTunnelPort", fmt.Sprintf("%d", cfg.HTTPTunnelPort)},
		{"DNSPort", fmt.Sprintf("%d", cfg.DNSPort)},
		{"CookieAuthentication", formatBool(cfg.CookieAuthentication)},
		{"CookieAuthFile", cfg.CookieAuthFile},
		{"HashedControlPassword", cfg.HashedControlPassword},
		{"LogLevel", cfg.LogLevel},
		{"LogFile", cfg.LogFile},
		{"CircuitBuildTimeout", formatDuration(cfg.CircuitBuildTimeout)},
		{"MaxCircuitDirtiness", formatDuration(cfg.MaxCircuitDirtiness)},
		{"NewCircuitPeriod", formatDuration(cfg.NewCircuitPeriod)},
		{"NumEntryGuards", fmt.Sprintf("%d", cfg.NumEntryGuards)},
		{"UseEntryGuards", formatBool(cfg.UseEntryGuards)},
		{"ClientUseIPv4", formatBool(cfg.ClientUseIPv4)},
		{"ClientUseIPv6", formatBool(cfg.ClientUseIPv6)},
		{"ClientPreferIPv6ORPort", formatBool(cfg.ClientPreferIPv6ORPort)},
		{"AutomapHostsOnResolve", formatBool(cfg.AutomapHostsOnResolve)},
		{"VirtualAddrNetworkIPv4", cfg.VirtualAddrNetworkIPv4},
		{"VirtualAddrNetworkIPv6", cfg.VirtualAddrNetworkIPv6},
		{"SafeSocks", formatBool(cfg.SafeSocks)},
		{"TestSocks", formatBool(cfg.TestSocks)},
		{"ClientRejectInternalAddresses", formatBool(cfg.ClientRejectInternalAddresses)},
		{"CircuitPadding", formatBool(cfg.EnableCircuitPadding)},
		{"ReducedCircuitPadding", formatBool(cfg.ReducedCircuitPadding)},
		{"ConnectionPadding", cfg.ConnectionPadding},
		{"SocksTimeout", formatDuration(cfg.SocksTimeout)},
		{"UseDefaultFallbackDirs", formatBool(cfg.UseDefaultFallbackDirs)},
		{"AvoidDiskWrites", formatBool(cfg.AvoidDiskWrites)},
		{"ORPort", fmt.Sprintf("%d", cfg.ORPort)},
		{"Nickname", cfg.Nickname},
		{"ExitRelay", formatBool(cfg.ExitRelay)},
		{"UseBridges", formatBool(cfg.UseBridges)},
	}
	defMap := map[string]string{
		"SocksPort":                     fmt.Sprintf("%d", defaults.SocksPort),
		"SocksListenAddr":               defaults.SocksListenAddr,
		"ControlPort":                   fmt.Sprintf("%d", defaults.ControlPort),
		"ControlListenAddr":             defaults.ControlListenAddr,
		"ControlSocket":                 defaults.ControlSocket,
		"SocksUnixPath":                 defaults.SocksUnixPath,
		"DataDirectory":                 defaults.DataDirectory,
		"CacheDirectory":                defaults.EffectiveCacheDirectory(),
		"PidFile":                       defaults.PidFile,
		"RunAsDaemon":                   formatBool(defaults.RunAsDaemon),
		"ClientOnly":                    formatBool(defaults.ClientOnly),
		"DisableNetwork":                formatBool(defaults.DisableNetwork),
		"HTTPTunnelPort":                fmt.Sprintf("%d", defaults.HTTPTunnelPort),
		"DNSPort":                       fmt.Sprintf("%d", defaults.DNSPort),
		"CookieAuthentication":          formatBool(defaults.CookieAuthentication),
		"CookieAuthFile":                defaults.CookieAuthFile,
		"HashedControlPassword":         defaults.HashedControlPassword,
		"LogLevel":                      defaults.LogLevel,
		"LogFile":                       defaults.LogFile,
		"CircuitBuildTimeout":           formatDuration(defaults.CircuitBuildTimeout),
		"MaxCircuitDirtiness":           formatDuration(defaults.MaxCircuitDirtiness),
		"NewCircuitPeriod":              formatDuration(defaults.NewCircuitPeriod),
		"NumEntryGuards":                fmt.Sprintf("%d", defaults.NumEntryGuards),
		"UseEntryGuards":                formatBool(defaults.UseEntryGuards),
		"ClientUseIPv4":                 formatBool(defaults.ClientUseIPv4),
		"ClientUseIPv6":                 formatBool(defaults.ClientUseIPv6),
		"ClientPreferIPv6ORPort":        formatBool(defaults.ClientPreferIPv6ORPort),
		"AutomapHostsOnResolve":         formatBool(defaults.AutomapHostsOnResolve),
		"VirtualAddrNetworkIPv4":        defaults.VirtualAddrNetworkIPv4,
		"VirtualAddrNetworkIPv6":        defaults.VirtualAddrNetworkIPv6,
		"SafeSocks":                     formatBool(defaults.SafeSocks),
		"TestSocks":                     formatBool(defaults.TestSocks),
		"ClientRejectInternalAddresses": formatBool(defaults.ClientRejectInternalAddresses),
		"CircuitPadding":                formatBool(defaults.EnableCircuitPadding),
		"ReducedCircuitPadding":         formatBool(defaults.ReducedCircuitPadding),
		"ConnectionPadding":             defaults.ConnectionPadding,
		"SocksTimeout":                  formatDuration(defaults.SocksTimeout),
		"UseDefaultFallbackDirs":        formatBool(defaults.UseDefaultFallbackDirs),
		"AvoidDiskWrites":               formatBool(defaults.AvoidDiskWrites),
		"ORPort":                        fmt.Sprintf("%d", defaults.ORPort),
		"Nickname":                      defaults.Nickname,
		"ExitRelay":                     formatBool(defaults.ExitRelay),
		"UseBridges":                    formatBool(defaults.UseBridges),
	}

	var lines []string
	for _, p := range all {
		if mode == "full" || p.v != defMap[p.k] {
			if p.v == "" && mode != "full" {
				continue
			}
			lines = append(lines, p.k+" "+p.v)
		}
	}
	for _, m := range cfg.MapAddress {
		lines = append(lines, "MapAddress "+m.From+" "+m.To)
	}
	for _, s := range cfg.AutomapHostsSuffixes {
		if mode == "full" || !containsString(defaults.AutomapHostsSuffixes, s) {
			lines = append(lines, "AutomapHostsSuffixes "+s)
		}
	}
	for _, f := range cfg.FallbackDirs {
		lines = append(lines, "FallbackDir "+f)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}

func containsString(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}
