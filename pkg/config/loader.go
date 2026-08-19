// Package config provides configuration file loading for torrc-compatible files.
package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/opd-ai/go-tor/pkg/autoconfig"
)

// loadState 跟踪 HiddenService 块与 Include 深度。
type loadState struct {
	pendingHS *OnionServiceConfig
	depth     int
	baseDir   string
}

const maxIncludeDepth = 16

// LoadFromFile loads configuration from a torrc-compatible file.
// It parses the file line by line and updates the provided config.
// Lines starting with # are treated as comments and ignored.
// Empty lines are ignored.
// Each configuration line follows the format: Key Value
// 未知键静默忽略（与 C Tor 客户端兼容策略一致）。
func LoadFromFile(path string, cfg *Config) error {
	return loadFromFileDepth(path, cfg, &loadState{depth: 0})
}

// LoadFromReader 从 io.Reader 加载 torrc（用于 -f -）。
func LoadFromReader(r io.Reader, cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config cannot be nil")
	}
	st := &loadState{depth: 0}
	if err := loadFromReader(r, cfg, st); err != nil {
		return err
	}
	flushPendingHS(cfg, st)
	if err := parseBridges(cfg); err != nil {
		return fmt.Errorf("failed to parse bridges: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	return nil
}

func loadFromFileDepth(path string, cfg *Config, st *loadState) error {
	if cfg == nil {
		return fmt.Errorf("config cannot be nil")
	}
	if st.depth > maxIncludeDepth {
		return fmt.Errorf("include depth exceeded (%d)", maxIncludeDepth)
	}

	if err := validatePath(path); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}

	file, err := os.Open(path) // #nosec G304 - path is validated by validatePath
	if err != nil {
		return fmt.Errorf("failed to open config file: %w", err)
	}
	defer func() { _ = file.Close() }()

	abs, _ := filepath.Abs(path)
	prevBase := st.baseDir
	st.baseDir = filepath.Dir(abs)
	defer func() { st.baseDir = prevBase }()

	if err := loadFromReader(file, cfg, st); err != nil {
		return err
	}

	flushPendingHS(cfg, st)

	if st.depth == 0 {
		if err := parseBridges(cfg); err != nil {
			return fmt.Errorf("failed to parse bridges: %w", err)
		}
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("invalid configuration: %w", err)
		}
	}
	return nil
}

func loadFromReader(r io.Reader, cfg *Config, st *loadState) error {
	scanner := bufio.NewScanner(r)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, err := splitTorrcLine(line)
		if err != nil {
			return fmt.Errorf("line %d: %w", lineNum, err)
		}
		if key == "" {
			continue
		}
		if err := processConfigOption(cfg, key, value, st); err != nil {
			return fmt.Errorf("line %d: %w", lineNum, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading config file: %w", err)
	}
	return nil
}

// splitTorrcLine 解析 `Key Value`，支持 DataDirectory "/path with spaces"。
func splitTorrcLine(line string) (key, value string, err error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", nil
	}
	fields, err := tokenizeQuoted(line)
	if err != nil {
		return "", "", err
	}
	if len(fields) == 0 {
		return "", "", nil
	}
	return fields[0], strings.Join(fields[1:], " "), nil
}

func tokenizeQuoted(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inQuote := false
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			cur.WriteByte(c)
			escaped = false
			continue
		}
		if c == '\\' && inQuote && i+1 < len(s) && s[i+1] == '"' {
			escaped = true
			continue
		}
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if !inQuote && (c == ' ' || c == '\t') {
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteByte(c)
	}
	if inQuote {
		return nil, fmt.Errorf("unclosed quote")
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out, nil
}

func flushPendingHS(cfg *Config, st *loadState) {
	if st == nil || st.pendingHS == nil {
		return
	}
	if st.pendingHS.ServiceDir != "" {
		cfg.OnionServices = append(cfg.OnionServices, *st.pendingHS)
	}
	st.pendingHS = nil
}

// processConfigOption processes a single configuration option.
// st 可为 nil（命令行覆盖时）。
func processConfigOption(cfg *Config, key, value string, st *loadState) error {
	switch key {
	case "SocksPort":
		return parseSocksPort(cfg, value)

	case "SocksListenAddress":
		// 弃用别名：host:port 或 port
		return parseSocksListenAddress(cfg, value)

	case "ControlPort":
		return parseControlPort(cfg, value)

	case "DataDirectory":
		cfg.DataDirectory = value

	case "CacheDirectory":
		cfg.CacheDirectory = value

	case "PidFile":
		cfg.PidFile = value

	case "RunAsDaemon":
		cfg.RunAsDaemon = parseBool(value)

	case "ClientOnly":
		cfg.ClientOnly = parseBool(value)

	case "DisableNetwork":
		cfg.DisableNetwork = parseBool(value)

	case "HTTPTunnelPort":
		return parseHTTPTunnelPort(cfg, value)

	case "DNSPort":
		return parseDNSPort(cfg, value)

	case "ControlSocket":
		cfg.ControlSocket = strings.TrimPrefix(value, "unix:")
		if f := strings.Fields(cfg.ControlSocket); len(f) > 0 {
			cfg.ControlSocket = f[0]
		}

	case "ClientUseIPv4":
		cfg.ClientUseIPv4 = parseBool(value)

	case "ClientUseIPv6":
		cfg.ClientUseIPv6 = parseBool(value)

	case "ClientPreferIPv6ORPort":
		cfg.ClientPreferIPv6ORPort = parseBool(value)

	case "MapAddress":
		from, to, err := parseMapAddress(value)
		if err != nil {
			return err
		}
		cfg.MapAddress = append(cfg.MapAddress, MapAddressEntry{From: from, To: to})

	case "AutomapHostsOnResolve":
		cfg.AutomapHostsOnResolve = parseBool(value)

	case "AutomapHostsSuffixes":
		cfg.AutomapHostsSuffixes = splitNodeList(strings.ReplaceAll(value, ",", " "))

	case "VirtualAddrNetworkIPv4":
		cfg.VirtualAddrNetworkIPv4 = value

	case "VirtualAddrNetworkIPv6":
		cfg.VirtualAddrNetworkIPv6 = value

	case "ClientOnionAuthDir":
		cfg.ClientOnionAuthDir = value

	case "SafeSocks":
		cfg.SafeSocks = parseBool(value)

	case "TestSocks":
		cfg.TestSocks = parseBool(value)

	case "ClientRejectInternalAddresses":
		cfg.ClientRejectInternalAddresses = parseBool(value)

	case "CircuitPadding":
		cfg.EnableCircuitPadding = parseBool(value)

	case "ReducedCircuitPadding":
		cfg.ReducedCircuitPadding = parseBool(value)

	case "ConnectionPadding":
		v := strings.ToLower(strings.TrimSpace(value))
		switch v {
		case "0", "1", "auto":
			cfg.ConnectionPadding = v
		default:
			if parseBool(value) {
				cfg.ConnectionPadding = "1"
			} else {
				cfg.ConnectionPadding = "0"
			}
		}

	case "SocksTimeout":
		d, err := parseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid SocksTimeout: %w", err)
		}
		cfg.SocksTimeout = d

	case "FallbackDir":
		cfg.FallbackDirs = append(cfg.FallbackDirs, value)

	case "UseDefaultFallbackDirs":
		cfg.UseDefaultFallbackDirs = parseBool(value)

	case "AvoidDiskWrites":
		cfg.AvoidDiskWrites = parseBool(value)

	case "TransPort":
		p, _, err := parsePortOrAddr(value)
		if err != nil {
			return fmt.Errorf("invalid TransPort: %w", err)
		}
		cfg.TransPort = p

	case "NATDPort":
		p, _, err := parsePortOrAddr(value)
		if err != nil {
			return fmt.Errorf("invalid NATDPort: %w", err)
		}
		cfg.NATDPort = p

	case "CookieAuthentication":
		cfg.CookieAuthentication = parseBool(value)

	case "CookieAuthFile":
		cfg.CookieAuthFile = value

	case "HashedControlPassword":
		cfg.HashedControlPassword = value

	case "ControlPassword":
		// 非标准扩展：明文口令
		cfg.ControlPassword = value

	case "CircuitBuildTimeout":
		timeout, err := parseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid CircuitBuildTimeout: %w", err)
		}
		cfg.CircuitBuildTimeout = timeout

	case "MaxCircuitDirtiness":
		duration, err := parseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid MaxCircuitDirtiness: %w", err)
		}
		cfg.MaxCircuitDirtiness = duration

	case "NewCircuitPeriod":
		period, err := parseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid NewCircuitPeriod: %w", err)
		}
		cfg.NewCircuitPeriod = period

	case "NumEntryGuards":
		num, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid NumEntryGuards value: %s", value)
		}
		cfg.NumEntryGuards = num

	case "UseEntryGuards":
		cfg.UseEntryGuards = parseBool(value)

	case "UseBridges":
		cfg.UseBridges = parseBool(value)

	case "Bridge":
		cfg.BridgeAddresses = append(cfg.BridgeAddresses, value)

	case "ExcludeNodes":
		cfg.ExcludeNodes = append(cfg.ExcludeNodes, splitNodeList(value)...)

	case "ExcludeExitNodes":
		cfg.ExcludeExitNodes = append(cfg.ExcludeExitNodes, splitNodeList(value)...)

	case "ExitNodes":
		cfg.ExitNodes = append(cfg.ExitNodes, splitNodeList(value)...)

	case "EntryNodes":
		cfg.EntryNodes = append(cfg.EntryNodes, splitNodeList(value)...)

	case "StrictNodes":
		cfg.StrictNodes = parseBool(value)

	case "ConnLimit":
		limit, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid ConnLimit value: %s", value)
		}
		cfg.ConnLimit = limit

	case "DormantTimeout":
		timeout, err := parseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid DormantTimeout: %w", err)
		}
		cfg.DormantTimeout = timeout

	case "LogLevel":
		cfg.LogLevel = strings.ToLower(value)

	case "Log":
		parseLogDirective(cfg, value)

	case "ClientTransportPlugin":
		transport, err := parseClientTransportPlugin(value)
		if err != nil {
			return fmt.Errorf("invalid ClientTransportPlugin: %w", err)
		}
		cfg.ClientTransports = append(cfg.ClientTransports, transport)

	case "ServerTransportPlugin":
		transport, err := parseServerTransportPlugin(value)
		if err != nil {
			return fmt.Errorf("invalid ServerTransportPlugin: %w", err)
		}
		cfg.ServerTransports = append(cfg.ServerTransports, transport)

	case "ServerTransportListenAddr":
		if err := parseServerTransportListenAddr(cfg, value); err != nil {
			return fmt.Errorf("invalid ServerTransportListenAddr: %w", err)
		}

	case "ServerTransportOptions":
		if err := parseServerTransportOptions(cfg, value); err != nil {
			return fmt.Errorf("invalid ServerTransportOptions: %w", err)
		}

	case "TransportProxy":
		cfg.TransportProxy = value

	case "ORPort":
		return parseORPort(cfg, value)

	case "Nickname":
		cfg.Nickname = value

	case "ContactInfo":
		cfg.ContactInfo = value

	case "Address":
		cfg.RelayAddress = value

	case "ExitRelay":
		cfg.ExitRelay = parseBool(value)

	case "IPv6Exit":
		cfg.IPv6Exit = parseBool(value)

	case "ReduceExitPolicy":
		cfg.ReduceExitPolicy = parseBool(value)

	case "ExitPolicy":
		cfg.ExitPolicyLines = append(cfg.ExitPolicyLines, value)

	case "ExitPolicyRejectPrivate":
		if parseBool(value) {
			cfg.ExitPolicyLines = append([]string{
				"reject 0.0.0.0/8:*",
				"reject 127.0.0.0/8:*",
				"reject 10.0.0.0/8:*",
				"reject 172.16.0.0/12:*",
				"reject 192.168.0.0/16:*",
				"reject 169.254.0.0/16:*",
				"reject 100.64.0.0/10:*",
				"reject 224.0.0.0/4:*",
				"reject 240.0.0.0/4:*",
				"reject 255.255.255.255/32:*",
				"reject [::]/128:*",
				"reject [::1]/128:*",
				"reject [fe80::]/10:*",
				"reject [fc00::]/7:*",
				"reject [ff00::]/8:*",
				"reject *:25",
			}, cfg.ExitPolicyLines...)
		}

	case "PublishServerDescriptor":
		// CSV；含 0/false/none 视为关闭
		v := strings.ToLower(strings.TrimSpace(value))
		cfg.PublishServerDescriptor = !(v == "0" || v == "false" || v == "no" || v == "none" || v == "")

	case "AssumeReachable":
		cfg.AssumeReachable = parseBool(value)

	case "RelayBandwidthRate", "BandwidthRate":
		n, err := parseByteRate(value)
		if err != nil {
			return fmt.Errorf("invalid %s: %w", key, err)
		}
		cfg.RelayBandwidthRate = n

	case "RelayBandwidthBurst", "BandwidthBurst":
		n, err := parseByteRate(value)
		if err != nil {
			return fmt.Errorf("invalid %s: %w", key, err)
		}
		cfg.RelayBandwidthBurst = n

	case "HiddenServiceDir":
		if st == nil {
			st = &loadState{}
		}
		flushPendingHS(cfg, st)
		st.pendingHS = &OnionServiceConfig{ServiceDir: value}

	case "HiddenServicePort":
		if st == nil || st.pendingHS == nil {
			return fmt.Errorf("HiddenServicePort without preceding HiddenServiceDir")
		}
		vp, target, err := parseHiddenServicePort(value)
		if err != nil {
			return err
		}
		// 多 Port：追加为独立服务条目共享 ServiceDir
		if st.pendingHS.VirtualPort != 0 {
			cfg.OnionServices = append(cfg.OnionServices, *st.pendingHS)
			dir := st.pendingHS.ServiceDir
			st.pendingHS = &OnionServiceConfig{ServiceDir: dir}
		}
		st.pendingHS.VirtualPort = vp
		st.pendingHS.TargetAddr = target

	case "HiddenServiceVersion":
		if value != "" && value != "3" {
			return fmt.Errorf("only HiddenServiceVersion 3 is supported, got %s", value)
		}

	case "HiddenServiceMaxStreams":
		if st == nil || st.pendingHS == nil {
			return fmt.Errorf("HiddenServiceMaxStreams without HiddenServiceDir")
		}
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid HiddenServiceMaxStreams: %s", value)
		}
		st.pendingHS.MaxStreams = n

	case "%include", "Include":
		if st == nil {
			st = &loadState{}
		}
		incPath := value
		if !filepath.IsAbs(incPath) && st.baseDir != "" {
			incPath = filepath.Join(st.baseDir, incPath)
		}
		files, err := expandIncludePath(incPath)
		if err != nil {
			return fmt.Errorf("include %s: %w", value, err)
		}
		for _, f := range files {
			child := &loadState{depth: st.depth + 1, baseDir: st.baseDir, pendingHS: st.pendingHS}
			if err := loadFromFileDepth(f, cfg, child); err != nil {
				return fmt.Errorf("include %s: %w", value, err)
			}
			st.pendingHS = child.pendingHS
		}

	default:
		// 未知键静默忽略
	}

	return nil
}

func splitNodeList(value string) []string {
	value = strings.ReplaceAll(value, ",", " ")
	parts := strings.Fields(value)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// expandIncludePath 展开 %include：通配符按词法排序；目录内忽略点文件。
func expandIncludePath(pattern string) ([]string, error) {
	if st, err := os.Stat(pattern); err == nil && st.IsDir() {
		entries, err := os.ReadDir(pattern)
		if err != nil {
			return nil, err
		}
		var files []string
		for _, e := range entries {
			if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			files = append(files, filepath.Join(pattern, e.Name()))
		}
		sort.Strings(files)
		return files, nil
	}
	if strings.ContainsAny(pattern, "*?[]") {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		var files []string
		for _, m := range matches {
			base := filepath.Base(m)
			if strings.HasPrefix(base, ".") {
				continue
			}
			info, err := os.Stat(m)
			if err != nil || info.IsDir() {
				continue
			}
			files = append(files, m)
		}
		sort.Strings(files)
		return files, nil
	}
	return []string{pattern}, nil
}

func parseMapAddress(value string) (from, to string, err error) {
	fields, err := tokenizeQuoted(value)
	if err != nil {
		return "", "", err
	}
	if len(fields) < 2 {
		return "", "", fmt.Errorf("MapAddress requires FROM TO")
	}
	return fields[0], fields[1], nil
}

func parseHTTPTunnelPort(cfg *Config, value string) error {
	p, host, err := parsePortOrAddr(value)
	if err != nil {
		return fmt.Errorf("invalid HTTPTunnelPort: %w", err)
	}
	cfg.HTTPTunnelPort = p
	if host != "" {
		cfg.HTTPTunnelListenAddr = host
	}
	return nil
}

func parseDNSPort(cfg *Config, value string) error {
	p, host, err := parsePortOrAddr(value)
	if err != nil {
		return fmt.Errorf("invalid DNSPort: %w", err)
	}
	cfg.DNSPort = p
	if host != "" {
		cfg.DNSPortListenAddr = host
	}
	return nil
}

func parsePortOrAddr(value string) (port int, host string, err error) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0, "", fmt.Errorf("empty value")
	}
	addrPort := fields[0]
	if strings.EqualFold(addrPort, "auto") {
		return autoconfig.FindAvailablePort(0), "", nil
	}
	if strings.Contains(addrPort, ":") && !strings.HasPrefix(addrPort, "unix:") {
		h, portStr, err := splitHostPortLoose(addrPort)
		if err != nil {
			return 0, "", err
		}
		p, err := strconv.Atoi(portStr)
		if err != nil {
			return 0, "", fmt.Errorf("invalid port: %s", portStr)
		}
		return p, h, nil
	}
	p, err := strconv.Atoi(addrPort)
	if err != nil {
		return 0, "", fmt.Errorf("invalid port: %s", addrPort)
	}
	return p, "", nil
}

// parseSocksPort 支持：9050 | 0 | auto | 127.0.0.1:9050 | unix:/path | Isolate*
func parseSocksPort(cfg *Config, value string) error {
	fields, err := tokenizeQuoted(value)
	if err != nil {
		return err
	}
	if len(fields) == 0 {
		return fmt.Errorf("empty SocksPort")
	}
	addrPort := fields[0]
	if strings.HasPrefix(addrPort, "unix:") {
		cfg.SocksUnixPath = strings.TrimPrefix(addrPort, "unix:")
		cfg.SocksPort = 0
	} else if strings.EqualFold(addrPort, "auto") {
		cfg.SocksPort = autoconfig.FindAvailablePort(9050)
	} else if strings.Contains(addrPort, ":") {
		host, portStr, err := splitHostPortLoose(addrPort)
		if err != nil {
			return fmt.Errorf("invalid SocksPort: %w", err)
		}
		cfg.SocksListenAddr = host
		if strings.EqualFold(portStr, "auto") {
			cfg.SocksPort = autoconfig.FindAvailablePort(9050)
		} else {
			p, err := strconv.Atoi(portStr)
			if err != nil {
				return fmt.Errorf("invalid SocksPort port: %s", portStr)
			}
			cfg.SocksPort = p
		}
	} else {
		p, err := strconv.Atoi(addrPort)
		if err != nil {
			return fmt.Errorf("invalid SocksPort value: %s", addrPort)
		}
		cfg.SocksPort = p
		if p == 0 {
			cfg.SocksUnixPath = ""
		}
	}
	for _, f := range fields[1:] {
		switch strings.ToLower(f) {
		case "isolatedestinations":
			cfg.IsolateDestinations = true
		case "isolatesocksauth":
			cfg.IsolateSOCKSAuth = true
		case "isolateclientport":
			cfg.IsolateClientPort = true
		case "isolateclientprotocol":
			cfg.IsolateClientProtocol = true
		default:
			// 未知 flag 静默忽略
		}
	}
	return nil
}

func parseSocksListenAddress(cfg *Config, value string) error {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return fmt.Errorf("empty SocksListenAddress")
	}
	return parseSocksPort(cfg, fields[0])
}

// parseORPort 支持：9001 | 0.0.0.0:9001 | [::<]:9001
// parseControlPort 支持：9051 | 127.0.0.1:9051 | [::1]:9051
func parseControlPort(cfg *Config, value string) error {
	fields, err := tokenizeQuoted(value)
	if err != nil {
		return err
	}
	if len(fields) == 0 {
		return fmt.Errorf("empty ControlPort")
	}
	addrPort := fields[0]
	if strings.HasPrefix(addrPort, "unix:") {
		cfg.ControlSocket = strings.TrimPrefix(addrPort, "unix:")
		cfg.ControlPort = 0
		return nil
	}
	if strings.EqualFold(addrPort, "auto") {
		cfg.ControlPort = autoconfig.FindAvailablePort(9051)
		return nil
	}
	if strings.Contains(addrPort, ":") {
		host, portStr, err := splitHostPortLoose(addrPort)
		if err != nil {
			return fmt.Errorf("invalid ControlPort: %w", err)
		}
		cfg.ControlListenAddr = host
		p, err := strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("invalid ControlPort port: %s", portStr)
		}
		if p < 0 || p > 65535 {
			return fmt.Errorf("invalid ControlPort port: %d", p)
		}
		cfg.ControlPort = p
		return nil
	}
	p, err := strconv.Atoi(addrPort)
	if err != nil {
		return fmt.Errorf("invalid ControlPort value: %s", value)
	}
	cfg.ControlPort = p
	return nil
}

func parseORPort(cfg *Config, value string) error {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return fmt.Errorf("empty ORPort")
	}
	addrPort := fields[0]
	if strings.Contains(addrPort, ":") {
		host, portStr, err := splitHostPortLoose(addrPort)
		if err != nil {
			return fmt.Errorf("invalid ORPort: %w", err)
		}
		cfg.ORListenAddr = host
		p, err := strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("invalid ORPort port: %s", portStr)
		}
		cfg.ORPort = p
		return nil
	}
	p, err := strconv.Atoi(addrPort)
	if err != nil {
		return fmt.Errorf("invalid ORPort: %s", addrPort)
	}
	cfg.ORPort = p
	return nil
}

// parseByteRate 解析 "1 MB" / "1048576" / "1MB" 为字节/秒。
func parseByteRate(value string) (int64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	fields := strings.Fields(value)
	numStr := fields[0]
	unit := ""
	if len(fields) >= 2 {
		unit = strings.ToUpper(fields[1])
	} else {
		// 1MB 粘连
		for i, c := range numStr {
			if c < '0' || c > '9' {
				if i == 0 {
					break
				}
				unit = strings.ToUpper(numStr[i:])
				numStr = numStr[:i]
				break
			}
		}
	}
	n, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return 0, err
	}
	switch unit {
	case "", "B", "BYTES":
		return n, nil
	case "KB", "KBYTES":
		return n * 1024, nil
	case "MB", "MBYTES":
		return n * 1024 * 1024, nil
	case "GB", "GBYTES":
		return n * 1024 * 1024 * 1024, nil
	default:
		return 0, fmt.Errorf("unknown unit %q", unit)
	}
}

func splitHostPortLoose(s string) (host, port string, err error) {
	// 支持 [ipv6]:port 与 host:port
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]:")
		if end < 0 {
			return "", "", fmt.Errorf("bad IPv6 listen %s", s)
		}
		return s[1:end], s[end+2:], nil
	}
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", "", fmt.Errorf("missing port in %s", s)
	}
	return s[:i], s[i+1:], nil
}

func parseLogDirective(cfg *Config, value string) {
	// Log [min][-max] stderr|stdout|file PATH|syslog
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return
	}
	level := strings.ToLower(fields[0])
	if idx := strings.Index(level, "-"); idx > 0 {
		level = level[:idx]
	}
	switch level {
	case "debug", "info", "notice", "warn", "warning", "err", "error":
		if level == "notice" {
			cfg.LogLevel = "info"
		} else if level == "warning" {
			cfg.LogLevel = "warn"
		} else if level == "err" {
			cfg.LogLevel = "error"
		} else {
			cfg.LogLevel = level
		}
	}
	for i := 1; i < len(fields); i++ {
		switch strings.ToLower(fields[i]) {
		case "file":
			if i+1 < len(fields) {
				cfg.LogFile = fields[i+1]
				i++
			}
		case "stdout", "stderr":
			cfg.LogFile = ""
		}
	}
}

func parseHiddenServicePort(value string) (virtualPort int, target string, err error) {
	fields := strings.Fields(value)
	if len(fields) < 1 {
		return 0, "", fmt.Errorf("empty HiddenServicePort")
	}
	vp, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, "", fmt.Errorf("invalid HiddenServicePort virtual port: %s", fields[0])
	}
	target = "127.0.0.1:" + fields[0]
	if len(fields) >= 2 {
		t := fields[1]
		if !strings.Contains(t, ":") {
			t = "127.0.0.1:" + t
		}
		target = t
	}
	return vp, target, nil
}

// parseDuration parses a duration string with support for common time units.
// Supports: seconds (s), minutes (m), hours (h), days (d)
// Examples: "60s", "5m", "2h", "1d"
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration string")
	}

	// Try parsing as Go duration first
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}

	// Check if it ends with a known suffix
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid duration format: %s", s)
	}

	suffix := s[len(s)-1:]
	valueStr := s[:len(s)-1]

	value, err := strconv.ParseInt(valueStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid duration value: %s", s)
	}

	switch suffix {
	case "s", "S":
		return time.Duration(value) * time.Second, nil
	case "m", "M":
		return time.Duration(value) * time.Minute, nil
	case "h", "H":
		return time.Duration(value) * time.Hour, nil
	case "d", "D":
		return time.Duration(value) * 24 * time.Hour, nil
	default:
		// Try parsing as seconds without suffix
		val, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration format: %s", s)
		}
		return time.Duration(val) * time.Second, nil
	}
}

// parseBridges parses all bridge address strings into BridgeInfo structures
func parseBridges(cfg *Config) error {
	if len(cfg.BridgeAddresses) == 0 {
		cfg.Bridges = nil
		return nil
	}

	cfg.Bridges = make([]*BridgeInfo, 0, len(cfg.BridgeAddresses))
	for i, bridgeLine := range cfg.BridgeAddresses {
		bridge, err := ParseBridge(bridgeLine)
		if err != nil {
			return fmt.Errorf("bridge %d: %w", i+1, err)
		}
		cfg.Bridges = append(cfg.Bridges, bridge)
	}

	return nil
}

// parseBool parses a boolean value from various string formats.
// Accepts: 1/0, true/false, yes/no, on/off (case-insensitive)
func parseBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return false
	}
}

// validatePath validates a file path to prevent directory traversal attacks.
// It ensures the path doesn't contain ".." components and is an absolute or safe relative path.
func validatePath(path string) error {
	// Clean the path to normalize it
	cleanPath := filepath.Clean(path)

	// Check for directory traversal attempts
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("invalid path: directory traversal detected")
	}

	// Additional check: ensure the clean path doesn't escape the intended directory
	// by checking if it becomes absolute when it shouldn't be
	if !filepath.IsAbs(path) && filepath.IsAbs(cleanPath) {
		return fmt.Errorf("invalid path: attempts to escape working directory")
	}

	return nil
}

// SaveToFile saves the configuration to a torrc-compatible file.
// This creates a human-readable configuration file that can be loaded later.
func SaveToFile(path string, cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config cannot be nil")
	}

	// Validate path to prevent directory traversal attacks
	if err := validatePath(path); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}

	file, err := os.Create(path) // #nosec G304 - path is validated by validatePath
	if err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			return
		}
	}()

	writer := bufio.NewWriter(file)
	defer func() {
		if err := writer.Flush(); err != nil {
			return
		}
	}()

	// Write header comment
	fmt.Fprintf(writer, "# go-tor configuration file\n")
	fmt.Fprintf(writer, "# Generated automatically - edit with care\n\n")

	// Network settings
	fmt.Fprintf(writer, "# Network Settings\n")
	fmt.Fprintf(writer, "SocksPort %d\n", cfg.SocksPort)
	fmt.Fprintf(writer, "ControlPort %d\n", cfg.ControlPort)
	fmt.Fprintf(writer, "DataDirectory %s\n\n", cfg.DataDirectory)

	// Circuit settings
	fmt.Fprintf(writer, "# Circuit Settings\n")
	fmt.Fprintf(writer, "CircuitBuildTimeout %s\n", formatDuration(cfg.CircuitBuildTimeout))
	fmt.Fprintf(writer, "MaxCircuitDirtiness %s\n", formatDuration(cfg.MaxCircuitDirtiness))
	fmt.Fprintf(writer, "NewCircuitPeriod %s\n", formatDuration(cfg.NewCircuitPeriod))
	fmt.Fprintf(writer, "NumEntryGuards %d\n\n", cfg.NumEntryGuards)

	// Path selection
	fmt.Fprintf(writer, "# Path Selection\n")
	fmt.Fprintf(writer, "UseEntryGuards %s\n", formatBool(cfg.UseEntryGuards))
	fmt.Fprintf(writer, "UseBridges %s\n", formatBool(cfg.UseBridges))
	for _, bridge := range cfg.BridgeAddresses {
		fmt.Fprintf(writer, "Bridge %s\n", bridge)
	}
	for _, node := range cfg.ExcludeNodes {
		fmt.Fprintf(writer, "ExcludeNodes %s\n", node)
	}
	for _, node := range cfg.ExcludeExitNodes {
		fmt.Fprintf(writer, "ExcludeExitNodes %s\n", node)
	}
	fmt.Fprintf(writer, "\n")

	// Network behavior
	fmt.Fprintf(writer, "# Network Behavior\n")
	fmt.Fprintf(writer, "ConnLimit %d\n", cfg.ConnLimit)
	fmt.Fprintf(writer, "DormantTimeout %s\n\n", formatDuration(cfg.DormantTimeout))

	// Logging
	fmt.Fprintf(writer, "# Logging\n")
	fmt.Fprintf(writer, "LogLevel %s\n\n", cfg.LogLevel)

	// Pluggable Transports
	if len(cfg.ClientTransports) > 0 || len(cfg.ServerTransports) > 0 || cfg.TransportProxy != "" {
		fmt.Fprintf(writer, "# Pluggable Transports\n")

		// Client transports
		for _, ct := range cfg.ClientTransports {
			fmt.Fprintf(writer, "ClientTransportPlugin %s exec %s", ct.Name, ct.BinaryPath)
			for k, v := range ct.Options {
				fmt.Fprintf(writer, " %s=%s", k, v)
			}
			fmt.Fprintf(writer, "\n")
		}

		// Server transports
		for _, st := range cfg.ServerTransports {
			if st.BinaryPath != "" {
				fmt.Fprintf(writer, "ServerTransportPlugin %s exec %s\n", st.Name, st.BinaryPath)
			}
			if st.BindAddr != "" {
				fmt.Fprintf(writer, "ServerTransportListenAddr %s %s\n", st.Name, st.BindAddr)
			}
			if len(st.Options) > 0 {
				fmt.Fprintf(writer, "ServerTransportOptions %s", st.Name)
				for k, v := range st.Options {
					fmt.Fprintf(writer, " %s=%s", k, v)
				}
				fmt.Fprintf(writer, "\n")
			}
		}

		// Transport proxy
		if cfg.TransportProxy != "" {
			fmt.Fprintf(writer, "TransportProxy %s\n", cfg.TransportProxy)
		}
		fmt.Fprintf(writer, "\n")
	}

	return writer.Flush()
}

// formatDuration formats a duration for writing to config file
func formatDuration(d time.Duration) string {
	if d%(24*time.Hour) == 0 && d >= 24*time.Hour {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	if d%time.Hour == 0 && d >= time.Hour {
		return fmt.Sprintf("%dh", d/time.Hour)
	}
	if d%time.Minute == 0 && d >= time.Minute {
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return fmt.Sprintf("%ds", d/time.Second)
}

// formatBool formats a boolean for writing to config file
func formatBool(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// parseClientTransportPlugin parses a ClientTransportPlugin directive.
// Format: transport exec path [options]
// Example: obfs4 exec /usr/bin/obfs4proxy
func parseClientTransportPlugin(value string) (ClientTransportConfig, error) {
	parts := strings.Fields(value)
	if len(parts) < 3 {
		return ClientTransportConfig{}, fmt.Errorf("invalid format, expected: transport exec path")
	}

	if parts[1] != "exec" {
		return ClientTransportConfig{}, fmt.Errorf("only 'exec' is supported, got: %s", parts[1])
	}

	config := ClientTransportConfig{
		Name:       parts[0],
		BinaryPath: parts[2],
		Options:    make(map[string]string),
	}

	// Parse any additional options (key=value format)
	for i := 3; i < len(parts); i++ {
		kv := strings.SplitN(parts[i], "=", 2)
		if len(kv) == 2 {
			config.Options[kv[0]] = kv[1]
		}
	}

	return config, nil
}

// parseServerTransportPlugin parses a ServerTransportPlugin directive.
// Format: transport exec path
// Example: obfs4 exec /usr/bin/obfs4proxy
func parseServerTransportPlugin(value string) (ServerTransportConfig, error) {
	parts := strings.Fields(value)
	if len(parts) < 3 {
		return ServerTransportConfig{}, fmt.Errorf("invalid format, expected: transport exec path")
	}

	if parts[1] != "exec" {
		return ServerTransportConfig{}, fmt.Errorf("only 'exec' is supported, got: %s", parts[1])
	}

	return ServerTransportConfig{
		Name:       parts[0],
		BinaryPath: parts[2],
		Options:    make(map[string]string),
	}, nil
}

// parseServerTransportListenAddr sets the bind address for a server transport.
// Format: transport address:port
// Example: obfs4 0.0.0.0:9443
func parseServerTransportListenAddr(cfg *Config, value string) error {
	parts := strings.Fields(value)
	if len(parts) < 2 {
		return fmt.Errorf("invalid format, expected: transport address:port")
	}

	transportName := parts[0]
	bindAddr := parts[1]

	// Find the existing server transport and set its bind address
	for i := range cfg.ServerTransports {
		if cfg.ServerTransports[i].Name == transportName {
			cfg.ServerTransports[i].BindAddr = bindAddr
			return nil
		}
	}

	// If transport doesn't exist yet, create it with just the bind address
	// The binary path should be set by ServerTransportPlugin
	cfg.ServerTransports = append(cfg.ServerTransports, ServerTransportConfig{
		Name:     transportName,
		BindAddr: bindAddr,
		Options:  make(map[string]string),
	})

	return nil
}

// parseServerTransportOptions sets options for a server transport.
// Format: transport key=value key=value...
// Example: obfs4 iat-mode=1 drbg-seed=abc123
func parseServerTransportOptions(cfg *Config, value string) error {
	parts := strings.Fields(value)
	if len(parts) < 2 {
		return fmt.Errorf("invalid format, expected: transport key=value...")
	}

	transportName := parts[0]

	// Find the existing server transport and set its options
	for i := range cfg.ServerTransports {
		if cfg.ServerTransports[i].Name == transportName {
			for j := 1; j < len(parts); j++ {
				kv := strings.SplitN(parts[j], "=", 2)
				if len(kv) == 2 {
					cfg.ServerTransports[i].Options[kv[0]] = kv[1]
				}
			}
			return nil
		}
	}

	// If transport doesn't exist yet, create it with just the options
	transport := ServerTransportConfig{
		Name:    transportName,
		Options: make(map[string]string),
	}

	for j := 1; j < len(parts); j++ {
		kv := strings.SplitN(parts[j], "=", 2)
		if len(kv) == 2 {
			transport.Options[kv[0]] = kv[1]
		}
	}

	cfg.ServerTransports = append(cfg.ServerTransports, transport)
	return nil
}
