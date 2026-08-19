// Package relay — 中继服务高层封装（ORPort + 密钥 + 生命周期）。
package relay

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"github.com/opd-ai/go-tor/pkg/config"
	"github.com/opd-ai/go-tor/pkg/logger"
)

// Server 是中继运行时（非出口或出口）。
type Server struct {
	cfg       *config.Config
	keys      *RelayKeys
	listener  *ORListener
	publisher *ScheduledPublisher
	dirCache  *DirCacheServer
	policy    *ExitPolicy
	startedAt time.Time
	logger    *logger.Logger
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
		log.Info("ExitRelay 1：启用出口（按 ExitPolicy / ReduceExitPolicy）")
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

	policy := NewExitPolicyFromOptions(ExitPolicyOptions{
		ExitRelay:             cfg.ExitRelay,
		Lines:                 cfg.ExitPolicyLines,
		Reduce:                cfg.ReduceExitPolicy,
		IPv6Exit:              cfg.IPv6Exit,
		RejectPrivate:         cfg.ExitPolicyRejectPrivate,
		RejectLocalInterfaces: cfg.ExitPolicyRejectLocalInterfaces,
	}, log)

	addr := cfg.ORListenAddr
	if addr == "" {
		addr = "0.0.0.0"
	}
	listen := net.JoinHostPort(addr, fmt.Sprintf("%d", cfg.ORPort))
	orCfg := DefaultORListenerConfig(listen, keys)
	orCfg.ExitPolicy = policy
	if cfg.ConnLimit > 0 {
		orCfg.MaxConnections = cfg.ConnLimit
	}
	ln, err := NewORListener(orCfg, log)
	if err != nil {
		return nil, err
	}
	if ln.circuitHandler != nil && ln.circuitHandler.exits != nil {
		ln.circuitHandler.exits.SetBandwidthLimit(cfg.RelayBandwidthRate, cfg.RelayBandwidthBurst)
		if cfg.ConnLimit > 0 {
			ln.circuitHandler.exits.SetMaxExitConns(cfg.ConnLimit)
		}
	}

	s := &Server{cfg: cfg, keys: keys, listener: ln, policy: policy, logger: log.Component("relay")}
	cacheDir := cfg.CacheDirectory
	if cacheDir == "" {
		cacheDir = cfg.DataDirectory
	}
	if cfg.DirCache || cfg.DirPort > 0 {
		s.dirCache = NewDirCacheServer(cacheDir, log)
		if ln.circuitHandler != nil && ln.circuitHandler.exits != nil {
			dc := s.dirCache
			ln.circuitHandler.exits.SetDirDial(dc.Dial)
		}
	}
	s.logger.Info("relay configured",
		"nickname", cfg.Nickname,
		"or_listen", listen,
		"exit", cfg.ExitRelay,
		"exit_announce", policy.WouldAnnounceExit(),
		"fingerprint", keys.Fingerprint(),
		"ed25519", keys.Ed25519Fingerprint(),
		"publish", cfg.PublishServerDescriptor)
	return s, nil
}

// Start 开始监听 OR 连接；若 PublishServerDescriptor 则向目录权威发布描述符。
func (s *Server) Start(ctx context.Context) error {
	if s == nil || s.listener == nil {
		return fmt.Errorf("relay server not initialized")
	}
	if err := s.listener.Start(ctx); err != nil {
		return err
	}
	s.startedAt = time.Now()
	if s.dirCache != nil && s.cfg != nil && s.cfg.DirPort > 0 {
		daddr := s.cfg.DirListenAddr
		if daddr == "" {
			daddr = "0.0.0.0"
		}
		if err := s.dirCache.Listen(net.JoinHostPort(daddr, fmt.Sprintf("%d", s.cfg.DirPort))); err != nil {
			s.logger.Error("DirPort listen failed", "error", err)
		}
	}
	if s.cfg != nil && s.cfg.PublishServerDescriptor {
		if err := s.startPublisher(ctx); err != nil {
			s.logger.Error("descriptor publisher not started", "error", err)
		}
	}
	return nil
}

func (s *Server) startPublisher(ctx context.Context) error {
	if s.cfg.RelayAddress == "" {
		return fmt.Errorf("Address is required to publish a server descriptor")
	}
	pcfg := DefaultPublisherConfig()
	pcfg.Authorities = DefaultDirectoryAuthorities()
	pub := NewDescriptorPublisher(pcfg, s.logger)
	sched := NewScheduledPublisher(pub, pcfg.PublishInterval, func() (*ServerDescriptor, *ExtraInfoDescriptor, error) {
		dcfg := &DescriptorConfig{
			Nickname:        s.cfg.Nickname,
			Address:         s.cfg.RelayAddress,
			ORPort:          uint16(s.cfg.ORPort),
			DirPort:         uint16(s.cfg.DirPort),
			Contact:         s.cfg.ContactInfo,
			Family:          append([]string(nil), s.cfg.MyFamily...),
			BandwidthAvg:    uint64(s.cfg.RelayBandwidthRate),
			BandwidthBurst:  uint64(s.cfg.RelayBandwidthBurst),
			Uptime:          int(time.Since(s.startedAt).Seconds()),
			ExitPolicyLines: s.policy.DescriptorLines(),
			IPv6Policy:      s.policy.IPv6PolicyLine(),
		}
		desc, err := GenerateServerDescriptor(s.keys, dcfg)
		if err != nil {
			return nil, nil, err
		}
		extra, err := GenerateExtraInfo(s.keys, desc, nil)
		if err != nil {
			s.logger.Warn("extra-info generation failed", "error", err)
			return desc, nil, nil
		}
		return desc, extra, nil
	}, s.logger)
	s.publisher = sched
	s.logger.Info("publishing server descriptor to directory authorities",
		"nickname", s.cfg.Nickname,
		"address", s.cfg.RelayAddress,
		"orport", s.cfg.ORPort,
		"authorities", len(pcfg.Authorities))
	return sched.Start(ctx)
}

// Stop 停止监听与描述符发布。
func (s *Server) Stop() error {
	if s == nil {
		return nil
	}
	if s.publisher != nil {
		s.publisher.Stop()
		s.publisher = nil
	}
	if s.dirCache != nil {
		_ = s.dirCache.Close()
		s.dirCache = nil
	}
	if s.listener == nil {
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
