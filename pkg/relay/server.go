// Package relay — 中继服务高层封装（ORPort + 密钥 + 生命周期）。
package relay

import (
	"context"
	"fmt"
	"net"
	"path/filepath"

	"github.com/opd-ai/go-tor/pkg/config"
	"github.com/opd-ai/go-tor/pkg/logger"
)

// Server 是非出口中继（middle/guard 候选）运行时。
type Server struct {
	cfg      *config.Config
	keys     *RelayKeys
	listener *ORListener
	logger   *logger.Logger
}

// NewServerFromConfig 从 torrc 配置创建中继；ORPort 必须 > 0。
func NewServerFromConfig(cfg *config.Config, log *logger.Logger) (*Server, error) {
	if cfg == nil || cfg.ORPort <= 0 {
		return nil, fmt.Errorf("ORPort must be > 0 to start relay")
	}
	if log == nil {
		log = logger.NewDefault()
	}
	if cfg.ExitRelay {
		log.Warn("ExitRelay 1 暂不支持完整出口；本进程仅作为非出口中继运行")
	}

	keysDir := filepath.Join(cfg.DataDirectory, "keys")
	keys, err := LoadKeys(keysDir)
	if err != nil {
		log.Info("generating new relay keys", "dir", keysDir)
		keys, err = GenerateRelayKeys()
		if err != nil {
			return nil, fmt.Errorf("generate relay keys: %w", err)
		}
		if err := keys.SaveKeys(keysDir); err != nil {
			return nil, fmt.Errorf("save relay keys: %w", err)
		}
	}

	addr := cfg.ORListenAddr
	if addr == "" {
		addr = "0.0.0.0"
	}
	listen := net.JoinHostPort(addr, fmt.Sprintf("%d", cfg.ORPort))
	orCfg := DefaultORListenerConfig(listen, keys)
	if cfg.ConnLimit > 0 {
		orCfg.MaxConnections = cfg.ConnLimit
	}
	ln, err := NewORListener(orCfg, log)
	if err != nil {
		return nil, err
	}

	s := &Server{cfg: cfg, keys: keys, listener: ln, logger: log.Component("relay")}
	s.logger.Info("relay configured",
		"nickname", cfg.Nickname,
		"or_listen", listen,
		"fingerprint", keys.Fingerprint(),
		"ed25519", keys.Ed25519Fingerprint(),
		"publish", cfg.PublishServerDescriptor)
	return s, nil
}

// Start 开始监听 OR 连接。
func (s *Server) Start(ctx context.Context) error {
	if s == nil || s.listener == nil {
		return fmt.Errorf("relay server not initialized")
	}
	return s.listener.Start(ctx)
}

// Stop 停止监听。
func (s *Server) Stop() error {
	if s == nil || s.listener == nil {
		return nil
	}
	return s.listener.Stop()
}

// Keys 返回中继密钥（只读使用）。
func (s *Server) Keys() *RelayKeys {
	if s == nil {
		return nil
	}
	return s.keys
}

// Fingerprint 返回 RSA 指纹十六进制。
func (s *Server) Fingerprint() string {
	if s == nil || s.keys == nil {
		return ""
	}
	return s.keys.Fingerprint()
}
