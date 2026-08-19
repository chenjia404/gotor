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

// ParseCLI 解析类似 C Tor 的 argv。
//
// 支持：
//   - -f / --config PATH
//   - --defaults-torrc PATH
//   - --hash-password [PASSWORD]
//   - --version / -version / -h / --help / --list-torrc-options
//   - 遗留：-socks-port、-control-port、-data-dir、-log-level、-metrics-port
//   - 其余位置参数：Key Value...（覆盖配置，与 C Tor 一致）
func ParseCLI(args []string) (*CLIResult, error) {
	res := &CLIResult{Config: DefaultConfig()}
	var positional []string

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
			res.Config.SocksPort = p
			i += 2
		case a == "-control-port" || a == "--control-port":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a port", a)
			}
			p, err := strconv.Atoi(args[i+1])
			if err != nil {
				return nil, fmt.Errorf("invalid control port: %w", err)
			}
			res.Config.ControlPort = p
			i += 2
		case a == "-metrics-port" || a == "--metrics-port":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a port", a)
			}
			p, err := strconv.Atoi(args[i+1])
			if err != nil {
				return nil, fmt.Errorf("invalid metrics port: %w", err)
			}
			res.Config.MetricsPort = p
			res.Config.EnableMetrics = true
			i += 2
		case a == "-data-dir" || a == "--data-dir":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a path", a)
			}
			res.Config.DataDirectory = args[i+1]
			i += 2
		case a == "-log-level" || a == "--log-level":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a level", a)
			}
			res.Config.LogLevel = strings.ToLower(args[i+1])
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

	// 加载 defaults → 主 torrc → 命令行 Key Value
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

	if err := applyPositionalOverrides(res.Config, positional); err != nil {
		return nil, err
	}
	return res, nil
}

func isTorrcKeyLookalike(a string) bool {
	// C Tor 允许 -SocksPort 形式较少见；我们把单横线长选项留给遗留 flag。
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
	for i := 0; i < len(args); {
		key := args[i]
		if strings.HasPrefix(key, "-") {
			return fmt.Errorf("unexpected argument: %s", key)
		}
		val := ""
		if i+1 < len(args) && !looksLikeTorrcKey(args[i+1]) {
			val = args[i+1]
			i += 2
		} else {
			i++
		}
		if err := processConfigOption(cfg, key, val, nil); err != nil {
			return fmt.Errorf("command-line %s: %w", key, err)
		}
	}
	return nil
}

// looksLikeTorrcKey：下一个 token 是否更像配置键（无空格的 CamelCase/已知模式）。
func looksLikeTorrcKey(s string) bool {
	if s == "" || strings.HasPrefix(s, "-") {
		return false
	}
	// 端口数字、路径、16: 哈希等视为 value
	if _, err := strconv.Atoi(s); err == nil {
		return false
	}
	if strings.Contains(s, "/") || strings.Contains(s, ":") || strings.Contains(s, ".") {
		return false
	}
	// 纯字母开头的 CamelCase 更像下一键
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
		"%include", "Include",
	}
}
