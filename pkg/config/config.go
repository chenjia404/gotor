// Package config provides configuration management for the Tor client.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/opd-ai/go-tor/pkg/autoconfig"
)

// DoS* Enabled 取值对齐 C Tor（0|1|auto）。auto 且无共识 DoS* 参数时视为关。
const (
	DoSEnabledAuto = -1
	DoSEnabledOff  = 0
	DoSEnabledOn   = 1
)

// Config represents the Tor client configuration
type Config struct {
	// Network settings
	SocksPort         int    // SOCKS5 proxy port (default: 9050)
	SocksListenAddr   string // SOCKS 绑定地址（默认 127.0.0.1；兼容 SocksPort addr:port）
	ControlPort       int    // Control protocol port (default: 9051)
	ControlListenAddr string // Control 绑定地址（默认 127.0.0.1；兼容 ControlPort addr:port）
	ControlPassword   string // 明文控制口令（非 C Tor 标准；优先于空哈希时使用）
	// HashedControlPassword 为 C Tor 标准 `16:...` 哈希；与 CookieAuthentication 可并存
	HashedControlPassword  string
	CookieAuthentication   bool   // 启用 control_auth_cookie
	CookieAuthFile         string // 可选 cookie 路径；空则 DataDirectory/control_auth_cookie
	DataDirectory          string // Directory for persistent state
	CacheDirectory         string // 目录缓存（共识/microdesc）；空则等于 DataDirectory
	PidFile                string // 启动写 PID、停止删除
	RunAsDaemon            bool   // Unix 后台化；Windows 仅警告
	ClientOnly             bool   // 禁止作为中继/出口运行
	DisableNetwork         bool   // 起监听但不拉共识/不建电路
	HTTPTunnelPort         int    // HTTP CONNECT 隧道端口（0=关闭）
	HTTPTunnelListenAddr   string // HTTPTunnelPort 绑定地址
	DNSPort                int    // UDP DNS 端口（0=关闭）
	DNSPortListenAddr      string // DNSPort 绑定地址
	ControlSocket          string // Control 的 unix socket 路径
	SocksUnixPath          string // SocksPort unix:/path
	UnixSocksGroupWritable bool   // unix SOCKS 用 0660；默认 false 即 0600
	// AllowUnauthenticatedControl 允许无 cookie/口令时接受空 AUTHENTICATE。
	// 仅库 DefaultConfig() 为 true；CLI / DefaultCLIConfig 必须为 false。
	AllowUnauthenticatedControl   bool
	ClientUseIPv4                 bool // 是否使用 IPv4 连接 OR
	ClientUseIPv6                 bool // 是否使用 IPv6 连接 OR
	ClientPreferIPv6ORPort        bool // 优先 IPv6 ORPort
	MapAddress                    []MapAddressEntry
	AutomapHostsOnResolve         bool
	AutomapHostsSuffixes          []string
	VirtualAddrNetworkIPv4        string
	VirtualAddrNetworkIPv6        string
	ClientOnionAuthDir            string
	SafeSocks                     bool
	TestSocks                     bool
	ClientRejectInternalAddresses bool
	ReducedCircuitPadding         bool
	ConnectionPadding             string // 0 / 1 / auto
	SocksTimeout                  time.Duration
	FallbackDirs                  []string
	UseDefaultFallbackDirs        bool
	AvoidDiskWrites               bool
	TransPort                     int // 非 0 时拒绝启动（未实现）
	NATDPort                      int // 非 0 时拒绝启动（未实现）

	// Circuit settings
	CircuitBuildTimeout time.Duration // Max time to build a circuit (default: 60s)
	MaxCircuitDirtiness time.Duration // Max time to use a circuit (default: 10m)
	NewCircuitPeriod    time.Duration // How often to rotate circuits (default: 30s)
	NumEntryGuards      int           // Number of entry guards to use (default: 3)

	// Path selection
	UseEntryGuards   bool          // Whether to use entry guards (default: true)
	UseBridges       bool          // Whether to use bridges (default: false)
	BridgeAddresses  []string      // Bridge addresses if UseBridges is true (raw bridge lines)
	Bridges          []*BridgeInfo // Parsed bridge information (populated after LoadFromFile)
	ExcludeNodes     []string      // Nodes to exclude from path selection
	ExcludeExitNodes []string      // Exit nodes to exclude
	ExitNodes        []string      // 仅允许的出口（C Tor ExitNodes）
	EntryNodes       []string      // 仅允许的入口
	StrictNodes      bool          // StrictNodes：名单无法满足时失败而非放宽

	// Network behavior
	ConnLimit      int           // Max concurrent connections (default: 1000)
	DormantTimeout time.Duration // Time before entering dormant mode (default: 24h)

	// DoS* 官方键（C Tor dos.c）。Enabled：-1=auto（无共识参数则关）、0=关、1=开。
	// 不改 ConnLimit 语义：全局仍由 OR 监听的 maxConnections 管。
	DoSCircuitCreationEnabled        int           // auto/0/1
	DoSCircuitCreationMinConnections int           // 默认 3
	DoSCircuitCreationRate           int           // 电路/秒，默认 3
	DoSCircuitCreationBurst          int           // 默认 90
	DoSCircuitCreationDefenseTime    time.Duration // 默认 1h
	DoSConnectionEnabled             int           // auto/0/1
	DoSConnectionMaxConcurrentCount  int           // 每 IP 并发 OR，默认 100
	DoSRefuseSingleHopClient         bool          // 默认 false

	// Relay / OR（中继）设置；ORPort>0 时 gotor 以中继模式启动 OR 监听
	ORPort                  int    // OR 监听端口（0=不启用中继）
	ORListenAddr            string // 绑定地址，默认 0.0.0.0
	Nickname                string // 中继昵称
	ContactInfo             string // ContactInfo
	RelayAddress            string // Address（对外宣告的 IPv4/主机名）
	ExitRelay               bool   // ExitRelay
	PublishServerDescriptor bool   // 是否尝试发布描述符（首轮可仅本地生成）
	AssumeReachable         bool   // AssumeReachable
	RelayBandwidthRate      int64  // 字节/秒，0=不限
	RelayBandwidthBurst     int64  // 突发字节，0=不限
	// ExitPolicyLines 为 torrc 中按顺序出现的 ExitPolicy 规则行（不含关键字）
	ExitPolicyLines                 []string
	IPv6Exit                        bool // IPv6Exit
	ReduceExitPolicy                bool // ReduceExitPolicy（启用精简默认出口策略）
	ExitPolicyRejectPrivate         bool // 默认 true：拒绝 RFC1918/环回/链路本地/CGN 等
	ExitPolicyRejectLocalInterfaces bool // 默认 true：拒绝本机网卡地址（C Tor 0.4.9）
	DirPort                         int  // 目录缓存 HTTP 端口（0=不监听明文 DirPort）
	DirListenAddr                   string
	DirCache                        bool     // 是否作为目录缓存（出口中继常见；BEGIN_DIR）
	MyFamily                        []string // MyFamily 指纹/昵称
	FamilyIDs                       []string // FamilyID（Desc=4）

	// Onion service settings
	OnionServices []OnionServiceConfig

	// Pluggable Transport settings (Phase 11.1.3)
	ClientTransports []ClientTransportConfig // Client-side pluggable transports
	ServerTransports []ServerTransportConfig // Server-side pluggable transports (for bridge relays)
	TransportProxy   string                  // Upstream proxy for PT connections (SOCKS5 URL)

	// Logging
	LogLevel string // Log level: debug, info, warn, error (default: info)
	LogFile  string // Log notice file PATH 时的文件路径；空表示 stdout

	// Monitoring and observability (Phase 9.1)
	MetricsPort   int  // HTTP metrics server port (default: 0 = disabled)
	EnableMetrics bool // Enable HTTP metrics endpoint (default: false)

	// Performance tuning (Phase 8.3)
	EnableConnectionPooling  bool          // Enable connection pooling for relay connections
	ConnectionPoolMaxIdle    int           // Max idle connections per relay (default: 5)
	ConnectionPoolMaxLife    time.Duration // Max lifetime for pooled connections (default: 10m)
	EnableCircuitPrebuilding bool          // Enable circuit prebuilding
	CircuitPoolMinSize       int           // Minimum circuits to prebuild (default: 2)
	CircuitPoolMaxSize       int           // Maximum circuits in pool (default: 10)
	EnableBufferPooling      bool          // Enable buffer pooling for cell operations (default: true)

	// Circuit isolation (backward compatible - disabled by default)
	IsolationLevel        string // Isolation level: "none", "destination", "credential", "port", "session" (default: "none")
	IsolateDestinations   bool   // Isolate circuits by destination host:port (default: false)
	IsolateSOCKSAuth      bool   // Isolate circuits by SOCKS5 username (default: false)
	IsolateClientPort     bool   // Isolate circuits by client source port (default: false)
	IsolateClientProtocol bool   // Isolate circuits by protocol (default: false)

	// Circuit padding for traffic analysis resistance (Phase 2.1)
	EnableCircuitPadding bool          // Enable circuit padding (default: true)
	PaddingStrategy      string        // Padding strategy: "none", "fixed", "random", "adaptive" (default: "random")
	PaddingMinInterval   time.Duration // Minimum interval between padding cells (default: 3s)
	PaddingMaxInterval   time.Duration // Maximum interval between padding cells (default: 10s)
	PaddingIdleTimeout   time.Duration // Time circuit must be idle before padding (default: 1s)
	PaddingDummyTraffic  bool          // Use dummy RELAY_DATA instead of PADDING cells (default: false)
	PaddingBurstSize     int           // Number of padding cells per burst (default: 1)

	// Rate limiting configuration (Phase 2.3)
	EnableRateLimiting            bool    // Enable rate limiting (default: true)
	SOCKSConnectionsPerSecond     float64 // Max SOCKS connections per second (default: 100)
	SOCKSConnectionsBurst         int     // Burst capacity for SOCKS connections (default: 50)
	CircuitCreationsPerSecond     float64 // Circuit creation rate limit per second (default: 10, 0 = unlimited)
	CircuitCreationsBurst         int     // Circuit creation burst capacity (default: 5)
	MaxConcurrentConnections      int     // Max concurrent SOCKS connections (default: 1000)
	StreamBufferHighWaterMark     int     // Stream buffer high water mark for backpressure (default: 65536 bytes)
	StreamBufferLowWaterMark      int     // Stream buffer low water mark for backpressure (default: 16384 bytes)
	EnablePerClientRateLimiting   bool    // Enable per-client rate limiting (default: false)
	PerClientConnectionsPerSecond float64 // Per-client connection rate (default: 10)
	PerClientConnectionsBurst     int     // Per-client burst capacity (default: 5)
	RateLimitCleanupInterval      int     // Cleanup interval for per-client limiters in seconds (default: 300)

	// Guard persistence configuration (Phase 2.4)
	GuardStateBackupCount      int // Number of guard state backup files to retain (default: 3)
	GuardStateSnapshotInterval int // Interval between automatic guard state snapshots in seconds (default: 300)
	GuardStateLockTimeout      int // Timeout for acquiring guard state file lock in seconds (default: 10)

	// Distributed tracing configuration (Phase 3.4)
	EnableTracing     bool          // Enable distributed tracing (default: false)
	TracingEndpoint   string        // Collector endpoint for OTLP (default: "localhost:4317")
	TracingSampleRate float64       // Sampling rate 0.0 to 1.0 (default: 1.0 = sample all)
	TracingExporter   string        // Exporter type: "otlp", "stdout", "noop" (default: "noop")
	TracingInsecure   bool          // Disable TLS for OTLP exporter (default: false)
	TracingTimeout    time.Duration // Export timeout duration (default: 10s)

	// Memory pressure monitoring configuration (AUDIT LOW-007)
	EnableMemoryMonitoring    bool   // Enable memory pressure monitoring (default: false for embedded)
	MemoryHighWaterMark       uint64 // Heap allocation threshold in bytes for degraded status (default: 100MB)
	MemoryCriticalMark        uint64 // Heap allocation threshold in bytes for unhealthy status (default: 200MB)
	MemoryMaxGoroutines       int    // Maximum goroutine count threshold (default: 10000)
	MemoryCheckInterval       int    // Interval between memory checks in seconds (default: 30)
	MemoryTriggerGCOnCritical bool   // Trigger GC when critical memory pressure is detected (default: true)

	// Crash recovery checkpointing configuration (AUDIT LOW-008)
	EnableCrashRecovery         bool   // Enable crash recovery checkpointing (default: true)
	CrashRecoveryCheckpointPath string // Path to checkpoint file (default: "<DataDirectory>/checkpoint.json")
	CrashRecoveryInterval       int    // Interval between checkpoints in seconds (default: 60)
	CrashRecoveryBackupCount    int    // Number of checkpoint backup files to retain (default: 2)

	// Profiling configuration (Phase 3.8)
	EnableProfiling     bool   // Enable pprof HTTP endpoints (default: false - security sensitive)
	ProfilingPort       int    // Port for pprof endpoints (default: 0 = use metrics port)
	ProfilingPath       string // Path prefix for pprof endpoints (default: "/debug/pprof")
	EnableCPUProfiling  bool   // Enable CPU profiling capability (default: true when profiling enabled)
	EnableHeapProfiling bool   // Enable heap profiling capability (default: true when profiling enabled)
	EnableMutexProfile  bool   // Enable mutex contention profiling (default: false - high overhead)
	EnableBlockProfile  bool   // Enable blocking profiling (default: false - high overhead)
	MutexProfileRate    int    // Mutex profiling sample rate (default: 0 = disabled)
	BlockProfileRate    int    // Block profiling sample rate in nanoseconds (default: 0 = disabled)
}

// MapAddressEntry 是 C Tor MapAddress 的一条 from→to 映射。
type MapAddressEntry struct {
	From string
	To   string
}

// OnionServiceConfig represents configuration for a single onion service
type OnionServiceConfig struct {
	ServiceDir  string            // Directory for service keys and state
	VirtualPort int               // Virtual port for the onion service
	TargetAddr  string            // Target address (localhost:port)
	MaxStreams  int               // Max concurrent streams (default: 0 = unlimited)
	ClientAuth  map[string]string // Client authorization keys
}

// ClientTransportConfig represents configuration for a client-side pluggable transport.
// This is used for connecting through censorship-resistant transports like obfs4 or meek.
type ClientTransportConfig struct {
	// Name is the transport method name (e.g., "obfs4", "meek", "snowflake")
	Name string

	// BinaryPath is the path to the PT executable
	BinaryPath string

	// Options contains PT-specific configuration options
	// For obfs4: cert, iat-mode
	// For meek: url, front
	Options map[string]string
}

// ServerTransportConfig represents configuration for a server-side pluggable transport.
// This is used for bridge relays to accept incoming PT connections.
type ServerTransportConfig struct {
	// Name is the transport method name
	Name string

	// BinaryPath is the path to the PT executable
	BinaryPath string

	// BindAddr is the address:port where the PT should listen
	// Format: "address:port" or "address:port#options"
	BindAddr string

	// Options contains PT-specific server options
	Options map[string]string
}

// DefaultConfig returns a configuration with sensible defaults.
// It automatically detects the appropriate data directory for the current platform
// and uses ports that work without special privileges.
func DefaultConfig() *Config {
	// Auto-detect data directory for current platform
	dataDir, err := autoconfig.GetDefaultDataDir()
	if err != nil {
		// Fallback to current directory if auto-detection fails
		dataDir = "./go-tor-data"
	}

	// Auto-select available ports for true zero-configuration
	// If default ports (9050, 9051) are in use, find alternatives
	socksPort := autoconfig.FindAvailablePort(9050)   // Standard Tor SOCKS port
	controlPort := autoconfig.FindAvailablePort(9051) // Standard Tor control port

	// Ensure SocksPort and ControlPort are different
	if controlPort == socksPort {
		controlPort = autoconfig.FindAvailablePort(controlPort + 1)
	}

	return &Config{
		SocksPort:                       socksPort,
		SocksListenAddr:                 "127.0.0.1",
		ControlPort:                     controlPort,
		ControlListenAddr:               "127.0.0.1",
		ControlPassword:                 "", // No authentication by default
		HashedControlPassword:           "",
		CookieAuthentication:            false,
		CookieAuthFile:                  "",
		AllowUnauthenticatedControl:     true, // 库路径：兼容既有无认证测试
		DataDirectory:                   dataDir,
		CacheDirectory:                  "",
		ClientUseIPv4:                   true,
		ClientUseIPv6:                   true,
		ClientPreferIPv6ORPort:          false,
		UseDefaultFallbackDirs:          true,
		ConnectionPadding:               "auto",
		VirtualAddrNetworkIPv4:          "127.192.0.0/10",
		VirtualAddrNetworkIPv6:          "[FE80::]/10",
		AutomapHostsSuffixes:            []string{".onion", ".exit"},
		CircuitBuildTimeout:             60 * time.Second,
		MaxCircuitDirtiness:             10 * time.Minute,
		NewCircuitPeriod:                30 * time.Second,
		NumEntryGuards:                  3,
		UseEntryGuards:                  true,
		UseBridges:                      false,
		BridgeAddresses:                 []string{},
		ExcludeNodes:                    []string{},
		ExcludeExitNodes:                []string{},
		ExitNodes:                       []string{},
		EntryNodes:                      []string{},
		StrictNodes:                     false,
		ConnLimit:                       1000,
		DoSCircuitCreationEnabled:        DoSEnabledAuto,
		DoSCircuitCreationMinConnections: 3,
		DoSCircuitCreationRate:           3,
		DoSCircuitCreationBurst:          90,
		DoSCircuitCreationDefenseTime:    time.Hour,
		DoSConnectionEnabled:             DoSEnabledAuto,
		DoSConnectionMaxConcurrentCount:  100,
		DoSRefuseSingleHopClient:         false,
		DormantTimeout:                  24 * time.Hour,
		ORPort:                          0,
		ORListenAddr:                    "0.0.0.0",
		Nickname:                        "",
		ContactInfo:                     "",
		RelayAddress:                    "",
		ExitRelay:                       false,
		PublishServerDescriptor:         true,
		AssumeReachable:                 false,
		RelayBandwidthRate:              0,
		RelayBandwidthBurst:             0,
		ExitPolicyLines:                 nil,
		IPv6Exit:                        false,
		ReduceExitPolicy:                false,
		ExitPolicyRejectPrivate:         true,
		ExitPolicyRejectLocalInterfaces: true,
		DirPort:                         0,
		DirListenAddr:                   "0.0.0.0",
		DirCache:                        true, // C Tor：中继默认开目录缓存
		MyFamily:                        nil,
		FamilyIDs:                       nil,
		OnionServices:                   []OnionServiceConfig{},
		ClientTransports:                []ClientTransportConfig{},
		ServerTransports:                []ServerTransportConfig{},
		TransportProxy:                  "",
		LogLevel:                        "info",
		LogFile:                         "",
		// Monitoring defaults (Phase 9.1)
		MetricsPort:   0,     // Disabled by default
		EnableMetrics: false, // Disabled by default
		// Performance tuning defaults (Phase 8.3)
		EnableConnectionPooling:  true,
		ConnectionPoolMaxIdle:    5,
		ConnectionPoolMaxLife:    10 * time.Minute,
		EnableCircuitPrebuilding: true,
		CircuitPoolMinSize:       2,
		CircuitPoolMaxSize:       10,
		EnableBufferPooling:      true,
		// Circuit isolation defaults (backward compatible - disabled by default)
		IsolationLevel:        "none",
		IsolateDestinations:   false,
		IsolateSOCKSAuth:      false,
		IsolateClientPort:     false,
		IsolateClientProtocol: false,
		// Circuit padding defaults (Phase 2.1 - enabled by default for traffic analysis resistance)
		EnableCircuitPadding: true,
		PaddingStrategy:      "random",
		PaddingMinInterval:   3 * time.Second,
		PaddingMaxInterval:   10 * time.Second,
		PaddingIdleTimeout:   time.Second,
		PaddingDummyTraffic:  false,
		PaddingBurstSize:     1,
		// Rate limiting defaults (Phase 2.3 - enabled by default for resource protection)
		EnableRateLimiting:            true,
		SOCKSConnectionsPerSecond:     100.0,
		SOCKSConnectionsBurst:         50,
		CircuitCreationsPerSecond:     10.0,
		CircuitCreationsBurst:         5,
		MaxConcurrentConnections:      1000,
		StreamBufferHighWaterMark:     65536,
		StreamBufferLowWaterMark:      16384,
		EnablePerClientRateLimiting:   false,
		PerClientConnectionsPerSecond: 10.0,
		PerClientConnectionsBurst:     5,
		RateLimitCleanupInterval:      300,
		// Guard persistence defaults (Phase 2.4)
		GuardStateBackupCount:      3,
		GuardStateSnapshotInterval: 300, // 5 minutes
		GuardStateLockTimeout:      10,
		// Distributed tracing defaults (Phase 3.4 - disabled by default)
		EnableTracing:     false,
		TracingEndpoint:   "localhost:4317",
		TracingSampleRate: 1.0,
		TracingExporter:   "noop",
		TracingInsecure:   false,
		TracingTimeout:    10 * time.Second,
		// Memory pressure monitoring defaults (AUDIT LOW-007 - disabled by default for embedded)
		EnableMemoryMonitoring:    false,
		MemoryHighWaterMark:       100 * 1024 * 1024, // 100 MB
		MemoryCriticalMark:        200 * 1024 * 1024, // 200 MB
		MemoryMaxGoroutines:       10000,
		MemoryCheckInterval:       30,
		MemoryTriggerGCOnCritical: true,
		// Crash recovery checkpointing defaults (AUDIT LOW-008 - enabled by default)
		EnableCrashRecovery:         true,
		CrashRecoveryCheckpointPath: "", // Will be set to DataDirectory/checkpoint.json if empty
		CrashRecoveryInterval:       60, // 1 minute
		CrashRecoveryBackupCount:    2,
		// Profiling defaults (Phase 3.8 - disabled by default for security)
		EnableProfiling:     false,
		ProfilingPort:       0, // 0 = use metrics port
		ProfilingPath:       "/debug/pprof",
		EnableCPUProfiling:  true, // Enabled when profiling is enabled
		EnableHeapProfiling: true, // Enabled when profiling is enabled
		EnableMutexProfile:  false,
		EnableBlockProfile:  false,
		MutexProfileRate:    0, // Disabled by default (high overhead)
		BlockProfileRate:    0, // Disabled by default (high overhead)
	}
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.SocksPort < 0 || c.SocksPort > 65535 {
		return fmt.Errorf("invalid SocksPort: %d", c.SocksPort)
	}
	if c.ControlPort < 0 || c.ControlPort > 65535 {
		return fmt.Errorf("invalid ControlPort: %d", c.ControlPort)
	}
	if c.MetricsPort < 0 || c.MetricsPort > 65535 {
		return fmt.Errorf("invalid MetricsPort: %d", c.MetricsPort)
	}
	if c.HTTPTunnelPort < 0 || c.HTTPTunnelPort > 65535 {
		return fmt.Errorf("invalid HTTPTunnelPort: %d", c.HTTPTunnelPort)
	}
	if c.DNSPort < 0 || c.DNSPort > 65535 {
		return fmt.Errorf("invalid DNSPort: %d", c.DNSPort)
	}

	// Check for port conflicts between enabled services
	// Build a map of used ports to detect conflicts
	usedPorts := make(map[int]string)

	// SocksPort is always enabled if non-zero
	if c.SocksPort > 0 {
		usedPorts[c.SocksPort] = "SocksPort"
	}

	// ControlPort is always enabled if non-zero
	if c.ControlPort > 0 {
		if existing, exists := usedPorts[c.ControlPort]; exists {
			return fmt.Errorf("port conflict: ControlPort (%d) conflicts with %s", c.ControlPort, existing)
		}
		usedPorts[c.ControlPort] = "ControlPort"
	}

	// MetricsPort is enabled when non-zero or when EnableMetrics is true
	if c.MetricsPort > 0 || c.EnableMetrics {
		if c.MetricsPort > 0 {
			if existing, exists := usedPorts[c.MetricsPort]; exists {
				return fmt.Errorf("port conflict: MetricsPort (%d) conflicts with %s", c.MetricsPort, existing)
			}
			usedPorts[c.MetricsPort] = "MetricsPort"
		}
	}
	if c.CircuitBuildTimeout <= 0 {
		return fmt.Errorf("CircuitBuildTimeout must be positive")
	}
	if c.MaxCircuitDirtiness <= 0 {
		return fmt.Errorf("MaxCircuitDirtiness must be positive")
	}
	if c.NumEntryGuards < 1 {
		return fmt.Errorf("NumEntryGuards must be at least 1")
	}
	if c.ConnLimit < 1 {
		return fmt.Errorf("ConnLimit must be at least 1")
	}
	if err := validateDoSFields(c); err != nil {
		return err
	}
	if c.ORPort < 0 || c.ORPort > 65535 {
		return fmt.Errorf("invalid ORPort: %d", c.ORPort)
	}
	if c.DirPort < 0 || c.DirPort > 65535 {
		return fmt.Errorf("invalid DirPort: %d", c.DirPort)
	}
	if c.ExitRelay && c.ORPort == 0 {
		return fmt.Errorf("ExitRelay 1 需要 ORPort > 0")
	}

	// Validate log level
	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if !validLogLevels[c.LogLevel] {
		return fmt.Errorf("invalid LogLevel: %s (must be debug, info, warn, or error)", c.LogLevel)
	}

	// Validate onion service configs
	for i, os := range c.OnionServices {
		if os.VirtualPort < 1 || os.VirtualPort > 65535 {
			return fmt.Errorf("onion service %d: invalid VirtualPort: %d", i, os.VirtualPort)
		}
		if os.TargetAddr == "" {
			return fmt.Errorf("onion service %d: TargetAddr is required", i)
		}
		if os.ServiceDir == "" {
			return fmt.Errorf("onion service %d: ServiceDir is required", i)
		}
	}

	// Validate performance tuning settings
	if c.ConnectionPoolMaxIdle < 0 {
		return fmt.Errorf("ConnectionPoolMaxIdle must be non-negative")
	}
	if c.ConnectionPoolMaxLife < 0 {
		return fmt.Errorf("ConnectionPoolMaxLife must be non-negative")
	}
	if c.CircuitPoolMinSize < 0 {
		return fmt.Errorf("CircuitPoolMinSize must be non-negative")
	}
	if c.CircuitPoolMaxSize < c.CircuitPoolMinSize {
		return fmt.Errorf("CircuitPoolMaxSize must be >= CircuitPoolMinSize")
	}

	// Validate circuit isolation settings
	validIsolationLevels := map[string]bool{
		"none":        true,
		"destination": true,
		"credential":  true,
		"port":        true,
		"session":     true,
	}
	if !validIsolationLevels[c.IsolationLevel] {
		return fmt.Errorf("invalid IsolationLevel: %s (must be none, destination, credential, port, or session)", c.IsolationLevel)
	}

	// Validate padding configuration (Phase 2.1)
	validPaddingStrategies := map[string]bool{
		"none":     true,
		"fixed":    true,
		"random":   true,
		"adaptive": true,
	}
	if !validPaddingStrategies[c.PaddingStrategy] {
		return fmt.Errorf("invalid PaddingStrategy: %s (must be none, fixed, random, or adaptive)", c.PaddingStrategy)
	}
	if c.PaddingMinInterval < 0 {
		return fmt.Errorf("PaddingMinInterval must be non-negative")
	}
	if c.PaddingMaxInterval < 0 {
		return fmt.Errorf("PaddingMaxInterval must be non-negative")
	}
	// PaddingMaxInterval must be >= PaddingMinInterval, or both must be zero
	if (c.PaddingMaxInterval == 0 && c.PaddingMinInterval > 0) || (c.PaddingMaxInterval > 0 && c.PaddingMaxInterval < c.PaddingMinInterval) {
		return fmt.Errorf("PaddingMaxInterval must be >= PaddingMinInterval (or both zero)")
	}
	if c.PaddingIdleTimeout < 0 {
		return fmt.Errorf("PaddingIdleTimeout must be non-negative")
	}
	if c.PaddingBurstSize < 0 {
		return fmt.Errorf("PaddingBurstSize must be non-negative")
	}

	// Validate rate limiting configuration (Phase 2.3)
	if c.EnableRateLimiting {
		if c.SOCKSConnectionsPerSecond <= 0 {
			return fmt.Errorf("SOCKSConnectionsPerSecond must be positive when rate limiting is enabled")
		}
		if c.SOCKSConnectionsBurst <= 0 {
			return fmt.Errorf("SOCKSConnectionsBurst must be positive when rate limiting is enabled")
		}
		if c.CircuitCreationsPerSecond <= 0 {
			return fmt.Errorf("CircuitCreationsPerSecond must be positive when rate limiting is enabled")
		}
		if c.CircuitCreationsBurst <= 0 {
			return fmt.Errorf("CircuitCreationsBurst must be positive when rate limiting is enabled")
		}
	}
	if c.MaxConcurrentConnections < 0 {
		return fmt.Errorf("MaxConcurrentConnections must be non-negative")
	}
	if c.StreamBufferHighWaterMark < 0 {
		return fmt.Errorf("StreamBufferHighWaterMark must be non-negative")
	}
	if c.StreamBufferLowWaterMark < 0 {
		return fmt.Errorf("StreamBufferLowWaterMark must be non-negative")
	}
	if c.StreamBufferLowWaterMark > c.StreamBufferHighWaterMark {
		return fmt.Errorf("StreamBufferLowWaterMark must be <= StreamBufferHighWaterMark")
	}
	if c.EnablePerClientRateLimiting {
		if c.PerClientConnectionsPerSecond <= 0 {
			return fmt.Errorf("PerClientConnectionsPerSecond must be positive when per-client rate limiting is enabled")
		}
		if c.PerClientConnectionsBurst <= 0 {
			return fmt.Errorf("PerClientConnectionsBurst must be positive when per-client rate limiting is enabled")
		}
	}
	if c.RateLimitCleanupInterval < 0 {
		return fmt.Errorf("RateLimitCleanupInterval must be non-negative")
	}

	// Validate guard persistence configuration (Phase 2.4)
	if c.GuardStateBackupCount < 0 {
		return fmt.Errorf("GuardStateBackupCount must be non-negative")
	}
	if c.GuardStateSnapshotInterval < 0 {
		return fmt.Errorf("GuardStateSnapshotInterval must be non-negative")
	}
	if c.GuardStateLockTimeout < 0 {
		return fmt.Errorf("GuardStateLockTimeout must be non-negative")
	}

	// Validate distributed tracing configuration (Phase 3.4)
	validTracingExporters := map[string]bool{
		"otlp":   true,
		"stdout": true,
		"noop":   true,
	}
	if !validTracingExporters[c.TracingExporter] {
		return fmt.Errorf("invalid TracingExporter: %s (must be otlp, stdout, or noop)", c.TracingExporter)
	}
	if c.TracingSampleRate < 0 || c.TracingSampleRate > 1 {
		return fmt.Errorf("TracingSampleRate must be between 0.0 and 1.0")
	}
	if c.TracingTimeout < 0 {
		return fmt.Errorf("TracingTimeout must be non-negative")
	}

	// Validate memory pressure monitoring configuration (AUDIT LOW-007)
	if c.EnableMemoryMonitoring {
		if c.MemoryHighWaterMark == 0 {
			return fmt.Errorf("MemoryHighWaterMark must be positive when memory monitoring is enabled")
		}
		if c.MemoryCriticalMark == 0 {
			return fmt.Errorf("MemoryCriticalMark must be positive when memory monitoring is enabled")
		}
		if c.MemoryCriticalMark <= c.MemoryHighWaterMark {
			return fmt.Errorf("MemoryCriticalMark must be greater than MemoryHighWaterMark")
		}
		if c.MemoryMaxGoroutines <= 0 {
			return fmt.Errorf("MemoryMaxGoroutines must be positive when memory monitoring is enabled")
		}
		if c.MemoryCheckInterval <= 0 {
			return fmt.Errorf("MemoryCheckInterval must be positive when memory monitoring is enabled")
		}
	}

	// Validate crash recovery configuration (AUDIT LOW-008)
	if c.EnableCrashRecovery {
		if c.CrashRecoveryInterval <= 0 {
			return fmt.Errorf("CrashRecoveryInterval must be positive when crash recovery is enabled")
		}
		if c.CrashRecoveryBackupCount < 0 {
			return fmt.Errorf("CrashRecoveryBackupCount must be non-negative")
		}
	}

	return nil
}

// Clone creates a deep copy of the configuration
func (c *Config) Clone() *Config {
	clone := *c
	clone.BridgeAddresses = append([]string{}, c.BridgeAddresses...)

	// Deep copy parsed bridges
	clone.Bridges = make([]*BridgeInfo, len(c.Bridges))
	for i, bridge := range c.Bridges {
		if bridge != nil {
			bridgeCopy := *bridge
			// Deep copy the parameters map
			bridgeCopy.Parameters = make(map[string]string, len(bridge.Parameters))
			for k, v := range bridge.Parameters {
				bridgeCopy.Parameters[k] = v
			}
			clone.Bridges[i] = &bridgeCopy
		}
	}

	clone.ExcludeNodes = append([]string{}, c.ExcludeNodes...)
	clone.ExcludeExitNodes = append([]string{}, c.ExcludeExitNodes...)
	clone.ExitNodes = append([]string{}, c.ExitNodes...)
	clone.EntryNodes = append([]string{}, c.EntryNodes...)
	clone.ExitPolicyLines = append([]string{}, c.ExitPolicyLines...)
	clone.MyFamily = append([]string{}, c.MyFamily...)
	clone.FamilyIDs = append([]string{}, c.FamilyIDs...)
	clone.MapAddress = append([]MapAddressEntry{}, c.MapAddress...)
	clone.AutomapHostsSuffixes = append([]string{}, c.AutomapHostsSuffixes...)
	clone.FallbackDirs = append([]string{}, c.FallbackDirs...)
	clone.OnionServices = make([]OnionServiceConfig, len(c.OnionServices))
	copy(clone.OnionServices, c.OnionServices)
	return &clone
}

// DefaultCLIConfig 给 ParseCLI / gotor 二进制使用，对齐 C Tor 0.4.9：
// SocksPort=9050、ControlPort=0（默认不开放控制口），不自动抢下一个空闲端口；
// DataDirectory 为 ~/.tor（Windows: %APPDATA%\tor）；CacheDirectory 默认等于 DataDirectory。
// 不得替代 DefaultConfig()：库测试依赖自动选端口与 ~/.config/go-tor。
func DefaultCLIConfig() *Config {
	cfg := DefaultConfig()
	cfg.SocksPort = 9050
	cfg.ControlPort = 0
	cfg.AllowUnauthenticatedControl = false
	cfg.DataDirectory = defaultTorDataDir()
	if cfg.CacheDirectory == "" {
		cfg.CacheDirectory = cfg.DataDirectory
	}
	if cfg.SocksTimeout == 0 {
		cfg.SocksTimeout = 120 * time.Second
	}
	// 默认不当出口；库 DefaultConfig() 同样为 false，此处显式固定以免日后被改。
	cfg.ExitRelay = false
	return cfg
}

func defaultTorDataDir() string {
	if runtime.GOOS == "windows" {
		if app := os.Getenv("APPDATA"); app != "" {
			return filepath.Join(app, "tor")
		}
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, "AppData", "Roaming", "tor")
		}
		return filepath.Join(".", "tor")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".tor")
	}
	return filepath.Join(".", ".tor")
}

func validateDoSFields(c *Config) error {
	if c.DoSCircuitCreationEnabled != DoSEnabledAuto &&
		c.DoSCircuitCreationEnabled != DoSEnabledOff &&
		c.DoSCircuitCreationEnabled != DoSEnabledOn {
		return fmt.Errorf("DoSCircuitCreationEnabled must be auto, 0, or 1")
	}
	if c.DoSConnectionEnabled != DoSEnabledAuto &&
		c.DoSConnectionEnabled != DoSEnabledOff &&
		c.DoSConnectionEnabled != DoSEnabledOn {
		return fmt.Errorf("DoSConnectionEnabled must be auto, 0, or 1")
	}
	if c.DoSCircuitCreationMinConnections < 1 {
		return fmt.Errorf("DoSCircuitCreationMinConnections must be at least 1")
	}
	if c.DoSCircuitCreationRate < 1 {
		return fmt.Errorf("DoSCircuitCreationRate must be at least 1")
	}
	if c.DoSCircuitCreationBurst < 1 {
		return fmt.Errorf("DoSCircuitCreationBurst must be at least 1")
	}
	if c.DoSCircuitCreationBurst < c.DoSCircuitCreationRate {
		return fmt.Errorf("DoSCircuitCreationBurst must be >= DoSCircuitCreationRate")
	}
	if c.DoSCircuitCreationDefenseTime < 0 {
		return fmt.Errorf("DoSCircuitCreationDefenseTimePeriod must be non-negative")
	}
	if c.DoSConnectionMaxConcurrentCount < 1 {
		return fmt.Errorf("DoSConnectionMaxConcurrentCount must be at least 1")
	}
	return nil
}

// FormatDoSEnabled 把 auto/0/1 写成官方 torrc 词。
func FormatDoSEnabled(v int) string {
	switch v {
	case DoSEnabledOn:
		return "1"
	case DoSEnabledOff:
		return "0"
	default:
		return "auto"
	}
}

// GetCheckpointPath returns the resolved checkpoint file path.
// If CrashRecoveryCheckpointPath is empty, it returns the default path
// based on the DataDirectory.
func (c *Config) GetCheckpointPath() string {
	if c.CrashRecoveryCheckpointPath != "" {
		return c.CrashRecoveryCheckpointPath
	}
	return filepath.Join(c.DataDirectory, "checkpoint.json")
}
