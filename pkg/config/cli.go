// Package config — C Tor 风格 CLI 参数解析（供 gotor 使用）。
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CLIResult 是解析 argv 后的动作与配置。
type CLIResult struct {
	Config          *Config
	ShowVersion     bool
	ShowHelp        bool
	ListTorrcOpts   bool
	HashPassword    bool
	HashPasswordArg string // 若命令行直接给出明文
	ConfigFile      string // -f / --config 最终路径
	DefaultsTorrc   string
}

// legacyOverrides 在 torrc 加载后再应用，保证命令行优先于文件。
type legacyOverrides struct {
	socksPort   int
	socksSet    bool
	controlPort int
	controlSet  bool
	metricsPort int
	metricsSet  bool
	dataDir     string
	dataDirSet  bool
	logLevel    string
	logLevelSet bool
}

// ParseCLI 解析类似 C Tor 的 argv。
//
// 支持：
//   - -f / --config PATH
//   - --defaults-torrc PATH
//   - --hash-password [PASSWORD]
//   - --version / -version / -h / --help / --list-torrc-options
//   - 遗留：-socks-port、-control-port、-data-dir、-log-level、-metrics-port（覆盖 torrc）
//   - 其余位置参数：Key Value...（最后覆盖）
func ParseCLI(args []string) (*CLIResult, error) {
	res := &CLIResult{Config: DefaultConfig()}
	var positional []string
	var leg legacyOverrides

	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case a == "-f" || a == "--torrc" || a == "-config" || a == "--config":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a path", a)
			}
			res.ConfigFile = args[i+1]
			i += 2
		case strings.HasPrefix(a, "-f=") || strings.HasPrefix(a, "--config=") || strings.HasPrefix(a, "-config="):
			res.ConfigFile = a[strings.Index(a, "=")+1:]
			i++
		case a == "--defaults-torrc":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--defaults-torrc requires a path")
			}
			res.DefaultsTorrc = args[i+1]
			i += 2
		case a == "--hash-password":
			res.HashPassword = true
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				res.HashPasswordArg = args[i+1]
				i += 2
			} else {
				i++
			}
		case a == "--version" || a == "-version":
			res.ShowVersion = true
			i++
		case a == "-h" || a == "--help" || a == "-help":
			res.ShowHelp = true
			i++
		case a == "--list-torrc-options":
			res.ListTorrcOpts = true
			i++
		case a == "-socks-port" || a == "--socks-port":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a port", a)
			}
			p, err := strconv.Atoi(args[i+1])
			if err != nil {
				return nil, fmt.Errorf("invalid socks port: %w", err)
			}
			leg.socksPort, leg.socksSet = p, true
			i += 2
		case a == "-control-port" || a == "--control-port":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a port", a)
			}
			p, err := strconv.Atoi(args[i+1])
			if err != nil {
				return nil, fmt.Errorf("invalid control port: %w", err)
			}
			leg.controlPort, leg.controlSet = p, true
			i += 2
		case a == "-metrics-port" || a == "--metrics-port":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a port", a)
			}
			p, err := strconv.Atoi(args[i+1])
			if err != nil {
				return nil, fmt.Errorf("invalid metrics port: %w", err)
			}
			leg.metricsPort, leg.metricsSet = p, true
			i += 2
		case a == "-data-dir" || a == "--data-dir":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a path", a)
			}
			leg.dataDir, leg.dataDirSet = args[i+1], true
			i += 2
		case a == "-log-level" || a == "--log-level":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a level", a)
			}
			leg.logLevel, leg.logLevelSet = strings.ToLower(args[i+1]), true
			i += 2
		case strings.HasPrefix(a, "-") && !isTorrcKeyLookalike(a):
			return nil, fmt.Errorf("unknown flag: %s", a)
		default:
			positional = append(positional, a)
			i++
		}
	}

	if res.ShowVersion || res.ShowHelp || res.ListTorrcOpts || res.HashPassword {
		return res, nil
	}

	// 加载 defaults → 主 torrc → 遗留 flag → 位置 Key Value（后者覆盖前者）
	if res.DefaultsTorrc != "" {
		if err := LoadFromFile(res.DefaultsTorrc, res.Config); err != nil {
			return nil, fmt.Errorf("defaults-torrc: %w", err)
		}
	}
	cfgPath := res.ConfigFile
	if cfgPath == "" {
		cfgPath = findDefaultTorrc()
		res.ConfigFile = cfgPath
	}
	if cfgPath != "" {
		if err := LoadFromFile(cfgPath, res.Config); err != nil {
			return nil, fmt.Errorf("load torrc %s: %w", cfgPath, err)
		}
	}
	applyLegacyOverrides(res.Config, leg)

	if err := applyPositionalOverrides(res.Config, positional); err != nil {
		return nil, err
	}
	return res, nil
}

func applyLegacyOverrides(cfg *Config, leg legacyOverrides) {
	if leg.socksSet {
		cfg.SocksPort = leg.socksPort
	}
	if leg.controlSet {
		cfg.ControlPort = leg.controlPort
	}
	if leg.metricsSet {
		cfg.MetricsPort = leg.metricsPort
		cfg.EnableMetrics = true
	}
	if leg.dataDirSet {
		cfg.DataDirectory = leg.dataDir
	}
	if leg.logLevelSet {
		cfg.LogLevel = leg.logLevel
	}
}

func isTorrcKeyLookalike(a string) bool {
	return false
}

func findDefaultTorrc() string {
	candidates := []string{
		"torrc",
		filepath.Join(".", "torrc"),
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".torrc"))
	}
	candidates = append(candidates, "/etc/tor/torrc")
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}

func applyPositionalOverrides(cfg *Config, args []string) error {
	st := &loadState{}
	for i := 0; i < len(args); {
		key := args[i]
		if strings.HasPrefix(key, "-") {
			return fmt.Errorf("unexpected argument: %s", key)
		}
		i++
		var parts []string
		for i < len(args) && !looksLikeTorrcKey(args[i]) && !strings.HasPrefix(args[i], "-") {
			parts = append(parts, args[i])
			i++
		}
		val := strings.Join(parts, " ")
		if err := processConfigOption(cfg, key, val, st); err != nil {
			return fmt.Errorf("command-line %s: %w", key, err)
		}
	}
	flushPendingHS(cfg, st)
	return nil
}

// looksLikeTorrcKey：下一个 token 是否更像配置键。
func looksLikeTorrcKey(s string) bool {
	if s == "" || strings.HasPrefix(s, "-") {
		return false
	}
	if _, err := strconv.Atoi(s); err == nil {
		return false
	}
	if strings.Contains(s, "/") || strings.Contains(s, ":") || strings.Contains(s, ".") {
		return false
	}
	if s[0] >= 'A' && s[0] <= 'Z' {
		return true
	}
	return false
}

// KnownTorrcOptions 列出 gotor 已识别的 torrc 键（--list-torrc-options）。
func KnownTorrcOptions() []string {
	return []string{
		"SocksPort", "SocksListenAddress", "ControlPort", "DataDirectory",
		"CookieAuthentication", "CookieAuthFile", "HashedControlPassword", "ControlPassword",
		"CircuitBuildTimeout", "MaxCircuitDirtiness", "NewCircuitPeriod", "NumEntryGuards",
		"UseEntryGuards", "UseBridges", "Bridge", "ExcludeNodes", "ExcludeExitNodes",
		"ExitNodes", "EntryNodes", "StrictNodes",
		"ConnLimit", "DormantTimeout", "LogLevel", "Log",
		"ClientTransportPlugin", "ServerTransportPlugin", "ServerTransportListenAddr",
		"ServerTransportOptions", "TransportProxy",
		"HiddenServiceDir", "HiddenServicePort", "HiddenServiceVersion", "HiddenServiceMaxStreams",
		"ORPort", "Nickname", "ContactInfo", "Address", "ExitRelay",
		"IPv6Exit", "ReduceExitPolicy", "ExitPolicy", "ExitPolicyRejectPrivate",
		"PublishServerDescriptor", "AssumeReachable", "RelayBandwidthRate", "RelayBandwidthBurst",
		"%include", "Include",
	}
}
