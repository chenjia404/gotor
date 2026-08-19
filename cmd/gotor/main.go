// gotor — 纯 Go Tor 客户端，兼容常用 torrc 与 C Tor 风格 CLI。
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/opd-ai/go-tor/pkg/client"
	"github.com/opd-ai/go-tor/pkg/config"
	"github.com/opd-ai/go-tor/pkg/logger"
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
		fmt.Printf("gotor version %s (built %s)\n", version, buildTime)
		fmt.Println("Pure Go Tor client (torrc-compatible)")
		os.Exit(0)
	}
	if res.ListTorrcOpts {
		for _, o := range config.KnownTorrcOptions() {
			fmt.Println(o)
		}
		os.Exit(0)
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

	if res.ConfigFile == "" {
		log.Info("zero-config mode (no torrc found)", "data_directory", cfg.DataDirectory)
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

func run(ctx context.Context, cfg *config.Config, log *logger.Logger) error {
	log.Info("starting gotor", "version", version, "build_time", buildTime)
	torClient, err := client.New(cfg, log)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	start := time.Now()
	if err := torClient.Start(ctx); err != nil {
		return fmt.Errorf("start client: %w", err)
	}
	stats := torClient.GetStats()
	log.Info("connected to Tor network",
		"bootstrap", time.Since(start).Round(time.Second),
		"circuits", stats.ActiveCircuits,
		"socks", fmt.Sprintf("%s:%d", cfg.SocksListenAddr, stats.SocksPort))

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
	fmt.Printf(`gotor — 纯 Go Tor 客户端（torrc 兼容）

用法:
  gotor [选项] [Key Value ...]

选项:
  -f, --config PATH          加载 torrc（亦支持 -config）
  --defaults-torrc PATH      先加载默认配置再加载 -f
  --hash-password [PASSWORD] 生成 HashedControlPassword（16:...）
  --list-torrc-options       列出已识别的 torrc 键
  --version                  显示版本
  -h, --help                 显示帮助

遗留选项（兼容旧脚本）:
  -socks-port, -control-port, -data-dir, -log-level, -metrics-port

无 -f 时依次尝试: ./torrc, ~/.torrc, /etc/tor/torrc；皆无则零配置启动。

示例:
  gotor -f /etc/tor/torrc
  gotor SocksPort 9150 ControlPort 9151
  gotor --hash-password mysecret
`)
}
