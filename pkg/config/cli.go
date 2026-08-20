// Package config — C Tor 风格 CLI 参数解析（供 gotor 使用）。
package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CLIResult 是解析 argv 后的动作与配置。
type CLIResult struct {
	Config            *Config
	ShowVersion       bool
	ShowHelp          bool
	ListTorrcOpts     bool
	ListDeprecated    bool
	ListModules       bool
	ListFingerprint   bool
	FingerprintType   string // rsa | ed25519
	HashPassword      bool
	HashPasswordArg   string
	Keygen            bool
	VerifyConfig      bool
	DumpConfig        string // short | full；空表示不 dump
	Quiet             bool
	Hush              bool
	NTService         bool
	ConfigFile        string // -f / --config 最终路径；"-" 表示 stdin
	DefaultsTorrc     string
	AllowMissingTorrc bool
	ReadStdin         bool
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

// ParseCLI 解析类似 C Tor 的 argv。使用 DefaultCLIConfig()，不改变 DefaultConfig() 库行为。
func ParseCLI(args []string) (*CLIResult, error) {
	return ParseCLIWithStdin(args, os.Stdin)
}

// ParseCLIWithStdin 允许测试注入 stdin（-f -）。
func ParseCLIWithStdin(args []string, stdin io.Reader) (*CLIResult, error) {
	res := &CLIResult{Config: DefaultCLIConfig()}
	var positional []string
	var leg legacyOverrides

	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case a == "-f" || a == "--torrc" || a == "--torrc-file" || a == "-config" || a == "--config":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a path", a)
			}
			res.ConfigFile = args[i+1]
			i += 2
		case strings.HasPrefix(a, "-f=") || strings.HasPrefix(a, "--config=") ||
			strings.HasPrefix(a, "-config=") || strings.HasPrefix(a, "--torrc-file=") ||
			strings.HasPrefix(a, "--torrc="):
			res.ConfigFile = a[strings.Index(a, "=")+1:]
			i++
		case a == "--defaults-torrc":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--defaults-torrc requires a path")
			}
			res.DefaultsTorrc = args[i+1]
			i += 2
		case strings.HasPrefix(a, "--defaults-torrc="):
			res.DefaultsTorrc = a[strings.Index(a, "=")+1:]
			i++
		case a == "--allow-missing-torrc" || a == "--ignore-missing-torrc":
			res.AllowMissingTorrc = true
			i++
		case a == "--hash-password":
			res.HashPassword = true
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				res.HashPasswordArg = args[i+1]
				i += 2
			} else {
				i++
			}
		case a == "--verify-config":
			res.VerifyConfig = true
			i++
		case a == "--dump-config":
			res.DumpConfig = "short"
			if i+1 < len(args) && (args[i+1] == "short" || args[i+1] == "full") {
				res.DumpConfig = args[i+1]
				i += 2
			} else {
				i++
			}
		case a == "--quiet":
			res.Quiet = true
			i++
		case a == "--hush":
			res.Hush = true
			i++
		case a == "--list-torrc-options":
			res.ListTorrcOpts = true
			i++
		case a == "--list-deprecated-options":
			res.ListDeprecated = true
			i++
		case a == "--list-modules":
			res.ListModules = true
			i++
		case a == "--list-fingerprint":
			res.ListFingerprint = true
			res.FingerprintType = "rsa"
			if i+1 < len(args) && (args[i+1] == "rsa" || args[i+1] == "ed25519") {
				res.FingerprintType = args[i+1]
				i += 2
			} else {
				i++
			}
		case a == "--keygen":
			res.Keygen = true
			i++
		case a == "--service" || a == "--nt-service":
			res.NTService = true
			i++
		case a == "--version" || a == "-version":
			res.ShowVersion = true
			i++
		case a == "-h" || a == "--help" || a == "-help":
			res.ShowHelp = true
			i++
		case strings.HasPrefix(a, "--dbg-"):
			i++
			if i < len(args) && !strings.HasPrefix(args[i], "-") && !looksLikeTorrcKey(args[i]) {
				i++
			}
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

	if res.ShowVersion || res.ShowHelp || res.ListTorrcOpts || res.ListDeprecated ||
		res.ListModules || res.HashPassword || res.NTService {
		return res, nil
	}

	if err := loadCLIConfig(res, stdin); err != nil {
		return nil, err
	}
	applyLegacyOverrides(res.Config, leg)
	if err := applyPositionalOverrides(res.Config, positional); err != nil {
		return nil, err
	}
	if res.Config.CacheDirectory == "" {
		res.Config.CacheDirectory = res.Config.DataDirectory
	}
	if res.Quiet {
		res.Config.LogLevel = "error"
	} else if res.Hush && (res.Config.LogLevel == "debug" || res.Config.LogLevel == "info") {
		res.Config.LogLevel = "warn"
	}
	res.Config.EnsureControlAuth()
	return res, nil
}

func loadCLIConfig(res *CLIResult, stdin io.Reader) error {
	if res.DefaultsTorrc == "" {
		if st, err := os.Stat("/etc/tor/torrc-defaults"); err == nil && !st.IsDir() {
			res.DefaultsTorrc = "/etc/tor/torrc-defaults"
		}
	}
	if res.DefaultsTorrc != "" {
		if err := LoadFromFile(res.DefaultsTorrc, res.Config); err != nil {
			if !(res.AllowMissingTorrc && isNotExistErr(err)) {
				return fmt.Errorf("defaults-torrc: %w", err)
			}
		}
	}

	cfgPath := res.ConfigFile
	if cfgPath == "" {
		cfgPath = findDefaultTorrc()
		res.ConfigFile = cfgPath
	}
	if cfgPath == "-" {
		res.ReadStdin = true
		if stdin == nil {
			stdin = os.Stdin
		}
		if err := LoadFromReader(stdin, res.Config); err != nil {
			return fmt.Errorf("load torrc from stdin: %w", err)
		}
		return nil
	}
	if cfgPath == "" {
		return nil
	}
	if err := LoadFromFile(cfgPath, res.Config); err != nil {
		if res.AllowMissingTorrc && isNotExistErr(err) {
			return nil
		}
		return fmt.Errorf("load torrc %s: %w", cfgPath, err)
	}
	return nil
}

// isNotExistErr 仅在文件确实不存在时为真。
// 不得把权限错误、解析错误等“打不开配置”一律当成缺失，否则
// --allow-missing-torrc 会静默丢掉本应生效的认证/访问限制。
func isNotExistErr(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, fs.ErrNotExist)
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

// findDefaultTorrc 对齐 C Tor：先 /etc/tor/torrc，再 $HOME/.torrc。
// ./torrc 仅作为额外便利放在最后，不会盖过 C Tor 顺序。
func findDefaultTorrc() string {
	var candidates []string
	candidates = append(candidates, "/etc/tor/torrc")
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".torrc"))
	}
	candidates = append(candidates, "torrc", filepath.Join(".", "torrc"))
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
		"SocksPort", "SocksListenAddress", "ControlPort", "ControlSocket", "DataDirectory",
		"CacheDirectory", "PidFile", "RunAsDaemon", "ClientOnly", "DisableNetwork",
		"HTTPTunnelPort", "DNSPort",
		"CookieAuthentication", "CookieAuthFile", "HashedControlPassword", "ControlPassword",
		"CircuitBuildTimeout", "MaxCircuitDirtiness", "NewCircuitPeriod", "NumEntryGuards",
		"UseEntryGuards", "UseBridges", "Bridge", "ExcludeNodes", "ExcludeExitNodes",
		"ExitNodes", "EntryNodes", "StrictNodes",
		"ConnLimit", "DormantTimeout", "LogLevel", "Log",
		"DoSCircuitCreationEnabled", "DoSCircuitCreationMinConnections",
		"DoSCircuitCreationRate", "DoSCircuitCreationBurst",
		"DoSCircuitCreationDefenseTimePeriod",
		"DoSConnectionEnabled", "DoSConnectionMaxConcurrentCount",
		"DoSRefuseSingleHopClient",
		"ClientUseIPv4", "ClientUseIPv6", "ClientPreferIPv6ORPort",
		"MapAddress", "AutomapHostsOnResolve", "AutomapHostsSuffixes",
		"VirtualAddrNetworkIPv4", "VirtualAddrNetworkIPv6",
		"ClientOnionAuthDir", "SafeSocks", "TestSocks", "ClientRejectInternalAddresses",
		"UnixSocksGroupWritable",
		"CircuitPadding", "ReducedCircuitPadding", "ConnectionPadding",
		"SocksTimeout", "FallbackDir", "UseDefaultFallbackDirs", "AvoidDiskWrites",
		"TransPort", "NATDPort",
		"ClientTransportPlugin", "ServerTransportPlugin", "ServerTransportListenAddr",
		"ServerTransportOptions", "TransportProxy",
		"HiddenServiceDir", "HiddenServicePort", "HiddenServiceVersion", "HiddenServiceMaxStreams",
		"ORPort", "Nickname", "ContactInfo", "Address", "ExitRelay",
		"IPv6Exit", "ReduceExitPolicy", "ExitPolicy", "ExitPolicyRejectPrivate",
		"ExitPolicyRejectLocalInterfaces", "DirPort", "DirCache", "MyFamily", "FamilyID",
		"PublishServerDescriptor", "AssumeReachable", "RelayBandwidthRate", "RelayBandwidthBurst",
		"%include", "Include",
	}
}
