// Package relay — 中继服务高层封装（ORPort + 密钥 + 生命周期）。
package relay

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"github.com/opd-ai/go-tor/pkg/config"
	"github.com/opd-ai/go-tor/pkg/datadir"
	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/logger"
)

// Server 是中继运行时（非出口或出口）。
type Server struct {
	cfg       *config.Config
	keys      *RelayKeys
	listener  *ORListener
	publisher *ScheduledPublisher
	reach     *Reachability
	dirCache  *DirCacheServer
	policy    *ExitPolicy
	bwHist    *BandwidthHistory
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

	bwHist := NewBandwidthHistory()
	if cfg.DataDirectory != "" && !cfg.AvoidDiskWrites {
		bwHist.SetStatePath(filepath.Join(cfg.DataDirectory, datadir.StateFileName))
		if err := bwHist.Load(); err != nil {
			log.Warn("bandwidth history load failed", "error", err)
		}
	}
	ln.SetBandwidthHistory(bwHist)
	ln.SetDoS(NewDoSGuardFromConfig(cfg))
	s := &Server{cfg: cfg, keys: keys, listener: ln, policy: policy, bwHist: bwHist, logger: log.Component("relay")}
	s.reach = NewReachability(ReachabilityConfig{
		AssumeReachable: cfg.AssumeReachable,
		DisableNetwork:  cfg.DisableNetwork,
		Address:         cfg.RelayAddress,
		ORPort:          cfg.ORPort,
		Publish:         cfg.PublishServerDescriptor,
	}, s.logger)
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
			ORPort:          portToUint16(s.cfg.ORPort),
			DirPort:         portToUint16(s.cfg.DirPort),
			Contact:         s.cfg.ContactInfo,
			Family:          append([]string(nil), s.cfg.MyFamily...),
			BandwidthAvg:    nonNegUint64(s.cfg.RelayBandwidthRate),
			BandwidthBurst:  nonNegUint64(s.cfg.RelayBandwidthBurst),
			Uptime:          int(time.Since(s.startedAt).Seconds()),
			ExitPolicyLines: s.policy.DescriptorLines(),
			IPv6Policy:      s.policy.IPv6PolicyLine(),
		}
		var stats map[string]string
		if s.bwHist != nil {
			_ = s.bwHist.Persist()
			stats = s.bwHist.StatsMap()
		}
		desc, extra, err := GenerateDescriptorPair(s.keys, dcfg, stats)
		if err != nil {
			return nil, nil, err
		}
		return desc, extra, nil
	}, s.logger)
	s.publisher = sched
	sched.SetPublishGate(s.reach.CanPublish)
	s.reach.SetOnReachable(func() {
		sched.TriggerNow(ctx)
	})
	s.logger.Info("publishing server descriptor to directory authorities",
		"nickname", s.cfg.Nickname,
		"orport", s.cfg.ORPort,
		"authorities", len(pcfg.Authorities),
		"assume_reachable", s.cfg.AssumeReachable,
		"self_test_required", s.reach.ShouldProbe())
	return sched.Start(ctx)
}

// SetORPortProber 注入经客户端电路的 ORPort 探测（main 在 client.Start 之后调用）。
func (s *Server) SetORPortProber(p ORPortProber) {
	if s == nil || s.reach == nil {
		return
	}
	s.reach.SetProber(p)
}

// StartReachability 启动 self-test 循环。AssumeReachable 时只放行发布、不探测。
func (s *Server) StartReachability(ctx context.Context) error {
	if s == nil || s.reach == nil {
		return fmt.Errorf("relay reachability not initialized")
	}
	return s.reach.Start(ctx)
}

// TestingHop 返回 EXTEND2 到本 ORPort 所需的末跳身份。
func (s *Server) TestingHop() *directory.Relay {
	if s == nil || s.keys == nil || s.cfg == nil {
		return nil
	}
	return s.keys.TestingHop(s.cfg.Nickname, s.cfg.RelayAddress, s.cfg.ORPort)
}

// ReachabilityStatus 返回 self-test 快照（无 Running / 共识含义）。
func (s *Server) ReachabilityStatus() ReachabilityStatus {
	if s == nil || s.reach == nil {
		return ReachabilityStatus{}
	}
	return s.reach.Status()
}

// Stop 停止监听与描述符发布。
func (s *Server) Stop() error {
	if s == nil {
		return nil
	}
	if s.reach != nil {
		s.reach.Stop()
	}
	if s.bwHist != nil {
		_ = s.bwHist.Persist()
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

func portToUint16(p int) uint16 {
	if p <= 0 {
		return 0
	}
	if p > 65535 {
		return 65535
	}
	// #nosec G115 -- 已限制在 0..65535
	return uint16(p)
}

func nonNegUint64(v int64) uint64 {
	if v <= 0 {
		return 0
	}
	// #nosec G115 -- 负值已归零
	return uint64(v)
}
