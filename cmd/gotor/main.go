// gotor — 纯 Go Tor 客户端，兼容常用 torrc 与 C Tor 风格 CLI。
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/opd-ai/go-tor/pkg/client"
	"github.com/opd-ai/go-tor/pkg/config"
	"github.com/opd-ai/go-tor/pkg/logger"
	"github.com/opd-ai/go-tor/pkg/relay"
)

var (
	version   = "0.1.0-dev"
	buildTime = "unknown"
)

func main() {
	res, err := config.ParseCLI(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "gotor: %v\n", err)
		os.Exit(1)
	}

	if res.ShowHelp {
		printHelp()
		os.Exit(0)
	}
	if res.ShowVersion {
		fmt.Println(config.VersionString())
		os.Exit(0)
	}
	if res.ListTorrcOpts {
		for _, o := range config.KnownTorrcOptions() {
			fmt.Println(o)
		}
		os.Exit(0)
	}
	if res.ListDeprecated {
		for _, o := range config.DeprecatedTorrcOptions() {
			fmt.Println(o)
		}
		os.Exit(0)
	}
	if res.ListModules {
		fmt.Print(config.FormatModules())
		os.Exit(0)
	}
	if res.NTService {
		fmt.Fprintln(os.Stderr, "gotor: --service / --nt-service 未实现（不会作为 Windows NT 服务安装）")
		os.Exit(1)
	}
	if res.HashPassword {
		pw := res.HashPasswordArg
		if pw == "" {
			fmt.Fprint(os.Stderr, "Enter password: ")
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			pw = strings.TrimRight(line, "\r\n")
		}
		h, err := config.HashControlPassword(pw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "hash-password: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(h)
		os.Exit(0)
	}

	cfg := res.Config
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "invalid configuration: %v\n", err)
		os.Exit(1)
	}
	if err := cfg.CheckDropInConstraints(); err != nil {
		fmt.Fprintf(os.Stderr, "gotor: %v\n", err)
		os.Exit(1)
	}

	if res.VerifyConfig {
		fmt.Println("Configuration was valid")
		os.Exit(0)
	}
	if res.DumpConfig != "" {
		fmt.Print(config.DumpConfig(cfg, res.DumpConfig))
		os.Exit(0)
	}
	if res.Keygen {
		if err := runKeygen(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if res.ListFingerprint {
		if err := printFingerprint(cfg, res.FingerprintType); err != nil {
			fmt.Fprintf(os.Stderr, "list-fingerprint: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	level, err := logger.ParseLevel(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid log level: %v\n", err)
		os.Exit(1)
	}
	out := os.Stdout
	if cfg.LogFile != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.LogFile), 0o700); err != nil {
			fmt.Fprintf(os.Stderr, "log file dir: %v\n", err)
			os.Exit(1)
		}
		f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304
		if err != nil {
			fmt.Fprintf(os.Stderr, "open log file: %v\n", err)
			os.Exit(1)
		}
		defer func() { _ = f.Close() }()
		out = f
	}
	log := logger.New(level, out)

	if err := maybeDaemonize(cfg, log); err != nil {
		fmt.Fprintf(os.Stderr, "RunAsDaemon: %v\n", err)
		os.Exit(1)
	}

	if res.ConfigFile == "" {
		log.Info("zero-config mode (no torrc found)", "data_directory", cfg.DataDirectory)
	} else if res.ReadStdin {
		log.Info("loaded torrc from stdin")
	} else {
		log.Info("loaded torrc", "path", res.ConfigFile)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = logger.WithContext(ctx, log)

	if err := run(ctx, cfg, log); err != nil {
		log.Error("application error", "error", err)
		os.Exit(1)
	}
	log.Info("shutdown complete")
}

func runKeygen(cfg *config.Config) error {
	keysDir := filepath.Join(cfg.DataDirectory, "keys")
	if _, err := os.Stat(filepath.Join(keysDir, "ed25519_identity_secret_key")); err == nil {
		fmt.Println("Identity keys already exist in", keysDir)
		return printFingerprint(cfg, "rsa")
	}
	keys, err := relay.GenerateRelayKeys()
	if err != nil {
		return err
	}
	if err := keys.SaveKeys(keysDir); err != nil { // #nosec G304 -- DataDirectory 由操作者配置
		return err
	}
	fmt.Println("Generated identity keys in", keysDir)
	return printFingerprint(cfg, "rsa")
}

func printFingerprint(cfg *config.Config, kind string) error {
	keysDir := filepath.Join(cfg.DataDirectory, "keys")
	keys, err := relay.LoadKeys(keysDir)
	if err != nil {
		// 对齐 C Tor：无身份钥时报错退出，不静默生成以免改写 DataDirectory
		return fmt.Errorf("DataDirectory/keys 中没有身份钥（可用 --keygen 生成）: %w", err)
	}
	nick := cfg.Nickname
	if nick == "" {
		nick = "Unnamed"
	}
	switch kind {
	case "ed25519":
		fmt.Printf("%s %s\n", nick, strings.ToUpper(keys.Ed25519Fingerprint()))
	default:
		fp := strings.ToUpper(keys.Fingerprint())
		fmt.Printf("%s %s\n", nick, fp)
	}
	return nil
}

func run(ctx context.Context, cfg *config.Config, log *logger.Logger) error {
	log.Info("starting gotor", "compat", config.VersionString(), "build_time", buildTime)

	var relaySrv *relay.Server
	if cfg.ORPort > 0 && !cfg.ClientOnly {
		var err error
		relaySrv, err = relay.NewServerFromConfig(cfg, log)
		if err != nil {
			return fmt.Errorf("create relay: %w", err)
		}
		if err := relaySrv.Start(ctx); err != nil {
			return fmt.Errorf("start relay ORPort: %w", err)
		}
		log.Info("relay OR listening",
			"port", cfg.ORPort,
			"nickname", cfg.Nickname,
			"fingerprint", relaySrv.Fingerprint())
		defer func() { _ = relaySrv.Stop() }()
	}

	torClient, err := client.New(cfg, log)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	start := time.Now()
	if err := torClient.Start(ctx); err != nil {
		_ = torClient.Stop()
		return fmt.Errorf("start client: %w", err)
	}
	if relaySrv != nil && cfg.PublishServerDescriptor && !cfg.DisableNetwork {
		if !cfg.AssumeReachable {
			hop := relaySrv.TestingHop()
			relaySrv.SetORPortProber(func(pctx context.Context) error {
				return torClient.ProbeORPortViaCircuit(pctx, hop)
			})
			if err := relaySrv.StartReachability(ctx); err != nil {
				log.Error("ORPort self-test not started", "error", err)
			}
		} else {
			log.Info("AssumeReachable: skipped ORPort circuit self-test")
		}
	}
	stats := torClient.GetStats()
	log.Info("client listeners ready",
		"bootstrap", time.Since(start).Round(time.Second),
		"circuits", stats.ActiveCircuits,
		"socks", fmt.Sprintf("%s:%d", cfg.SocksListenAddr, stats.SocksPort),
		"disable_network", cfg.DisableNetwork)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		log.Info("signal received", "signal", sig.String())
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = shutdownCtx
	return torClient.Stop()
}

func printHelp() {
	fmt.Printf(`gotor — 纯 Go Tor 客户端（C Tor 0.4.9.x drop-in）

用法:
  gotor [选项] [Key Value ...]

选项:
  -f, --torrc-file, --config PATH   加载 torrc（-f - 从 stdin）
  --defaults-torrc PATH             先加载默认配置（未指定时尝试 /etc/tor/torrc-defaults）
  --allow-missing-torrc             主 torrc 缺失时继续
  --ignore-missing-torrc            同上
  --hash-password [PASSWORD]        生成 HashedControlPassword（16:...）
  --verify-config                   校验配置后退出（不启动网络）
  --dump-config [short|full]        打印配置后退出
  --quiet / --hush                  降低日志级别
  --list-torrc-options              列出已识别的 torrc 键
  --list-deprecated-options         列出弃用键
  --list-modules                    列出可选模块
  --list-fingerprint [rsa|ed25519]  打印 nickname + fingerprint
  --keygen                          在 DataDirectory/keys 生成身份钥
  --service / --nt-service          Windows 服务（未实现，明确退出）
  --version                         输出 C Tor 风格版本行
  -h, --help                        显示帮助

遗留选项: -socks-port, -control-port, -data-dir, -log-level, -metrics-port
--dbg-* 会被忽略。

无 -f 时依次尝试: /etc/tor/torrc、~/.torrc，然后 ./torrc（便利，不覆盖 C Tor 顺序）。

示例:
  gotor -f /etc/tor/torrc
  gotor SocksPort 9150 ControlPort 9151
  gotor --hash-password mysecret
  gotor ORPort 9001 Nickname gotorRelay ExitRelay 0
  gotor ORPort 9001 ExitRelay 1 ReduceExitPolicy 1 SocksPort 0
`)
}

func maybeDaemonize(cfg *config.Config, log *logger.Logger) error {
	if !cfg.RunAsDaemon {
		return nil
	}
	if runtime.GOOS == "windows" {
		log.Warn("RunAsDaemon 在 Windows 上不受支持，将以前台继续运行")
		return nil
	}
	return daemonizeUnix(cfg)
}
