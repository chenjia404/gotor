// Package onion - Onion Service Server Implementation
// This file implements the server/hosting side of onion services (Phase 7.4)
package onion

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/circuit"
	"github.com/opd-ai/go-tor/pkg/crypto"
	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/logger"
	"github.com/opd-ai/go-tor/pkg/path"
	"golang.org/x/crypto/curve25519"
)

// Service represents an onion service (hidden service) that can be hosted
type Service struct {
	mu sync.RWMutex

	// Identity
	identityKey ed25519.PrivateKey // 64-byte Ed25519 private key
	publicKey   ed25519.PublicKey  // 32-byte Ed25519 public key
	address     *Address           // Derived .onion address
	ntorKey     []byte             // 32-byte Curve25519 ntor private key for rendezvous

	// Configuration
	config *ServiceConfig

	// State
	descriptor      *Descriptor
	introPoints     []*ServiceIntroPoint
	publishedHSDirs []*HSDirectory
	lastPublish     time.Time
	running         bool
	startTime       time.Time
	ctx             context.Context
	cancel          context.CancelFunc
	logger          *logger.Logger
	introManager    *IntroPointManager // Manages intro point lifecycle

	// Circuit building
	rendezvousBuilder *RendezvousCircuitBuilder // Builds circuits to rendezvous points
	circuitGetter     CircuitGetter             // Gets circuits by ID for sending cells

	// Connections
	pendingIntros      map[string]*PendingIntro // cookie -> intro
	rendezvousCircuits map[string]uint32        // cookie -> circuit ID
	streamManager      *ServiceStreamManager    // Manages incoming streams

	// Persistence
	persistence   *ServicePersistence // Handles state persistence
	createdAt     time.Time           // Service creation timestamp
	descriptorRev uint64              // Descriptor revision counter
}

// CircuitGetter provides access to circuits by ID
type CircuitGetter interface {
	GetCircuit(id uint32) (CircuitInterface, error)
}

// MetricsCollector defines the interface for collecting onion service metrics
type MetricsCollector interface {
	RecordOnionServiceStream(created bool)
	RecordOnionServiceStreamData(bytes int64)
	RecordOnionServiceDescriptorPublish(success bool)
	RecordOnionServiceIntroEstablish(success bool)
	RecordOnionServiceIntroReceived()
	RecordOnionServiceRendezvous(success bool)
	SetOnionServiceIntroPoints(count int64)
	RecordOnionServiceDuration(duration time.Duration)
}

// ServiceConfig contains configuration for hosting an onion service
type ServiceConfig struct {
	// Service identity (if nil, generates new identity)
	PrivateKey ed25519.PrivateKey

	// Service ports (map virtual port -> local target)
	// e.g., 80 -> "localhost:8080"
	Ports map[int]string

	// Number of introduction points (default: 3, min: 1, max: 10)
	NumIntroPoints int

	// Descriptor lifetime (default: 3 hours)
	DescriptorLifetime time.Duration

	// Directory to store persistent state
	DataDirectory string

	// Circuit builder for establishing introduction point circuits (optional)
	// If nil, uses placeholder circuits for testing
	CircuitBuilder *circuit.Builder

	// Path selector for choosing introduction point paths (optional)
	// If nil, uses placeholder circuits for testing
	PathSelector *path.Selector

	// Metrics collector (optional)
	// If nil, metrics are not collected
	Metrics MetricsCollector

	// AllowPlaceholderIntros 仅单测：无 CircuitBuilder 时使用占位电路（生产必须 false）
	AllowPlaceholderIntros bool

	// Begindir 用于匿名上传描述符（POST /tor/hs/3/publish）
	Begindir *BegindirFetcher

	// NetworkRelays 共识节点（选引言点 / BEGIN_DIR 路径）
	NetworkRelays []*directory.Relay
}

// ServiceIntroPoint represents an introduction point for this service
type ServiceIntroPoint struct {
	Relay         *HSDirectory // The relay acting as intro point
	CircuitID     uint32       // Circuit to the intro point
	AuthPrivate   ed25519.PrivateKey
	AuthPublic    ed25519.PublicKey
	EncKey        []byte // Curve25519 private (b)
	Established   bool
	CreatedAt     time.Time
	RendCircNonce []byte // last-hop circ_nonce for ESTABLISH_INTRO MAC
}

// PendingIntro represents a pending introduction request
type PendingIntro struct {
	Cookie          []byte // Rendezvous cookie
	RendezvousPoint string // Rendezvous point fingerprint
	ClientOnionKey  []byte // Client's ephemeral X (32 bytes)
	IntroAuthKey    []byte // Intro point AUTH_KEY (Ed25519, 32 bytes) for hs-ntor
	ReceivedAt      time.Time
}

// NewService creates a new onion service
func NewService(config *ServiceConfig, log *logger.Logger) (*Service, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	if log == nil {
		log = logger.NewDefault()
	}

	// Generate or load identity key
	var privateKey ed25519.PrivateKey
	var publicKey ed25519.PublicKey
	var ntorKey []byte
	var persistence *ServicePersistence
	var loadedState *ServiceState

	if len(config.PrivateKey) > 0 {
		// Use provided key
		if len(config.PrivateKey) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid private key size: %d, expected %d",
				len(config.PrivateKey), ed25519.PrivateKeySize)
		}
		privateKey = config.PrivateKey
		publicKey = privateKey.Public().(ed25519.PublicKey)

		// Generate new ntor key (not persisted yet)
		ntorKeyPair, err := crypto.GenerateNtorKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate ntor key: %w", err)
		}
		ntorKey = ntorKeyPair.Private[:]
	} else if config.DataDirectory != "" {
		// Try to load from persistent storage
		var err error
		persistence, err = NewServicePersistence(config.DataDirectory, log)
		if err != nil {
			return nil, fmt.Errorf("failed to create persistence: %w", err)
		}

		if persistence.KeysExist() {
			// Load existing keys
			log.Info("Loading existing service keys from storage",
				"directory", config.DataDirectory)

			privateKey, err = persistence.LoadIdentityKey()
			if err != nil {
				return nil, fmt.Errorf("failed to load identity key: %w", err)
			}

			ntorKey, err = persistence.LoadNtorKey()
			if err != nil {
				return nil, fmt.Errorf("failed to load ntor key: %w", err)
			}

			publicKey = privateKey.Public().(ed25519.PublicKey)

			// Try to load state if it exists
			if persistence.StateExists() {
				loadedState, err = persistence.LoadState()
				if err != nil {
					log.Warn("Failed to load service state, starting fresh", "error", err)
					loadedState = nil
				} else {
					log.Info("Loaded service state from storage",
						"last_publish", loadedState.LastDescriptorPublish,
						"revision", loadedState.DescriptorRevision,
						"intro_points_cached", len(loadedState.IntroPointCache))
				}
			}
		} else {
			// Generate new keys and save
			log.Info("Generating new service keys",
				"directory", config.DataDirectory)

			publicKey, privateKey, err = ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return nil, fmt.Errorf("failed to generate identity key: %w", err)
			}

			ntorKeyPair, err := crypto.GenerateNtorKeyPair()
			if err != nil {
				return nil, fmt.Errorf("failed to generate ntor key: %w", err)
			}
			ntorKey = ntorKeyPair.Private[:]

			// Save keys to disk
			if err := persistence.SaveIdentityKey(privateKey); err != nil {
				return nil, fmt.Errorf("failed to save identity key: %w", err)
			}

			if err := persistence.SaveNtorKey(ntorKey); err != nil {
				return nil, fmt.Errorf("failed to save ntor key: %w", err)
			}
		}
	} else {
		// Generate new identity (no persistence)
		var err error
		publicKey, privateKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate identity key: %w", err)
		}

		ntorKeyPair, err := crypto.GenerateNtorKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate ntor key: %w", err)
		}
		ntorKey = ntorKeyPair.Private[:]
	}

	// Derive onion address from public key
	addr, err := addressFromPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address: %w", err)
	}

	// Set defaults
	if config.NumIntroPoints == 0 {
		config.NumIntroPoints = 3
	}
	if config.NumIntroPoints < 1 {
		config.NumIntroPoints = 1
	}
	if config.NumIntroPoints > 10 {
		config.NumIntroPoints = 10
	}

	if config.DescriptorLifetime == 0 {
		config.DescriptorLifetime = 3 * time.Hour
	}

	if config.Ports == nil {
		config.Ports = make(map[int]string)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Initialize creation time and descriptor revision
	createdAt := time.Now()
	descriptorRev := uint64(1)

	if loadedState != nil {
		// Use loaded state
		createdAt = loadedState.CreatedAt
		descriptorRev = loadedState.DescriptorRevision
	}

	service := &Service{
		identityKey:        privateKey,
		publicKey:          publicKey,
		address:            addr,
		ntorKey:            ntorKey,
		config:             config,
		introPoints:        make([]*ServiceIntroPoint, 0, config.NumIntroPoints),
		publishedHSDirs:    make([]*HSDirectory, 0),
		pendingIntros:      make(map[string]*PendingIntro),
		rendezvousCircuits: make(map[string]uint32),
		ctx:                ctx,
		cancel:             cancel,
		logger:             log.Component("onion-service"),
		persistence:        persistence,
		createdAt:          createdAt,
		descriptorRev:      descriptorRev,
	}

	// If we have loaded state with cached intro points, we could restore them here
	// For now, we'll just track the state for metrics and optimization
	if loadedState != nil {
		service.lastPublish = loadedState.LastDescriptorPublish
	}

	// Initialize introduction point manager
	service.introManager = NewIntroPointManager(service, log)

	// Initialize stream manager for handling incoming connections
	service.streamManager = NewServiceStreamManager(service, log)

	// Initialize rendezvous circuit builder if we have circuit builder and path selector
	if config.CircuitBuilder != nil && config.PathSelector != nil {
		service.rendezvousBuilder = NewRendezvousCircuitBuilder(
			config.CircuitBuilder,
			config.PathSelector,
			log,
		)
	}

	return service, nil
}

// addressFromPublicKey derives a v3 onion address from an Ed25519 public key
func addressFromPublicKey(pubkey ed25519.PublicKey) (*Address, error) {
	if len(pubkey) != 32 {
		return nil, fmt.Errorf("invalid public key length: %d", len(pubkey))
	}

	// Compute checksum
	checksum := computeV3Checksum(pubkey, V3Version)

	// Construct: pubkey || checksum || version
	data := make([]byte, 0, V3PubkeyLen+V3ChecksumLen+1)
	data = append(data, pubkey...)
	data = append(data, checksum...)
	data = append(data, V3Version)

	// Encode to base32
	encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	encoded := strings.ToLower(encoder.EncodeToString(data))

	return &Address{
		Version: V3,
		Pubkey:  pubkey,
		Raw:     encoded + V3Suffix,
	}, nil
}

// GetAddress returns the onion address of this service
func (s *Service) GetAddress() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.address.String()
}

// Start starts the onion service
func (s *Service) Start(ctx context.Context, hsdirs []*HSDirectory) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("service already running")
	}
	s.running = true
	s.startTime = time.Now()
	s.mu.Unlock()

	s.logger.Info("Starting onion service",
		"address", s.address.String(),
		"intro_points", s.config.NumIntroPoints)

	// Step 1: Select and establish introduction points
	if err := s.establishIntroductionPoints(ctx, hsdirs); err != nil {
		s.running = false
		return fmt.Errorf("failed to establish introduction points: %w", err)
	}

	// Step 2: Create descriptor
	if err := s.createDescriptor(); err != nil {
		s.running = false
		return fmt.Errorf("failed to create descriptor: %w", err)
	}

	// Step 3: Publish descriptor to HSDirs
	if err := s.publishDescriptor(ctx, hsdirs); err != nil {
		s.running = false
		return fmt.Errorf("failed to publish descriptor: %w", err)
	}

	// Step 4: Start background tasks
	go s.maintenanceLoop(ctx, hsdirs)
	go s.introManager.StartHealthChecking(ctx)

	s.logger.Info("Onion service started successfully",
		"address", s.address.String())

	return nil
}

// Stop stops the onion service
func (s *Service) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.logger.Info("Stopping onion service", "address", s.address.String())

	// Record service duration
	if s.config.Metrics != nil && !s.startTime.IsZero() {
		s.config.Metrics.RecordOnionServiceDuration(time.Since(s.startTime))
	}

	// Stop health checking
	s.introManager.StopHealthChecking()

	// Close all active streams
	if s.streamManager != nil {
		s.streamManager.CloseAll()
	}

	// Cancel context to stop background tasks
	s.cancel()

	// Clean up introduction points
	for _, intro := range s.introPoints {
		// Unregister from health monitoring
		s.introManager.UnregisterIntroPoint(intro.CircuitID)
		// In a full implementation, we would:
		// 1. Send INTRO_ESTABLISHED teardown
		// 2. Close circuits
		_ = intro
	}

	s.running = false
	s.logger.Info("Onion service stopped", "address", s.address.String())

	// Save state before stopping (if persistence is enabled)
	if err := s.saveState(); err != nil {
		s.logger.Warn("Failed to save service state on stop", "error", err)
	}

	return nil
}

// saveState persists the current service state to disk
func (s *Service) saveState() error {
	if s.persistence == nil {
		return nil // No persistence configured
	}

	// Build intro point cache
	introCache := make([]IntroPointState, 0, len(s.introPoints))
	for _, intro := range s.introPoints {
		if intro.Established {
			fingerprint := ""
			if intro.Relay != nil && intro.Relay.Fingerprint != "" {
				fingerprint = intro.Relay.Fingerprint
			}

			introCache = append(introCache, IntroPointState{
				Fingerprint: fingerprint,
				AuthKeyHex:  fmt.Sprintf("%x", intro.AuthPublic),
				EncKeyHex:   fmt.Sprintf("%x", intro.EncKey),
				CreatedAt:   intro.CreatedAt,
			})
		}
	}

	state := &ServiceState{
		OnionAddress:          s.address.String(),
		CreatedAt:             s.createdAt,
		LastStarted:           s.startTime,
		IntroPointCache:       introCache,
		LastDescriptorPublish: s.lastPublish,
		DescriptorRevision:    s.descriptorRev,
	}

	if err := s.persistence.SaveState(state); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	s.logger.Debug("Service state saved",
		"intro_points", len(introCache),
		"revision", s.descriptorRev)

	return nil
}

// establishIntroductionPoints selects and establishes circuits to introduction points
func (s *Service) establishIntroductionPoints(ctx context.Context, hsdirs []*HSDirectory) error {
	s.logger.Info("Establishing introduction points", "count", s.config.NumIntroPoints)

	if len(hsdirs) < s.config.NumIntroPoints {
		return fmt.Errorf("not enough relays available: need %d, have %d",
			s.config.NumIntroPoints, len(hsdirs))
	}

	// Select introduction points (use first N relays for Phase 7.4)
	// In production, we would:
	// 1. Filter relays with appropriate flags
	// 2. Randomly select from filtered set
	// 3. Ensure geographical and network diversity
	selectedRelays := hsdirs[:s.config.NumIntroPoints]

	for i, relay := range selectedRelays {
		intro, err := s.establishIntroductionPoint(ctx, relay)
		if err != nil {
			s.logger.Warn("Failed to establish introduction point",
				"relay", relay.Fingerprint,
				"error", err)
			continue
		}

		s.introPoints = append(s.introPoints, intro)
		s.logger.Debug("Introduction point established",
			"index", i,
			"relay", relay.Fingerprint,
			"circuit", intro.CircuitID)
	}

	if len(s.introPoints) == 0 {
		return fmt.Errorf("failed to establish any introduction points")
	}

	s.logger.Info("Introduction points established", "count", len(s.introPoints))
	return nil
}

// establishIntroductionPoint establishes a single introduction point
func (s *Service) establishIntroductionPoint(ctx context.Context, relay *HSDirectory) (*ServiceIntroPoint, error) {
	s.logger.Debug("Establishing introduction point", "relay", relay.Fingerprint)

	keys, err := GenerateEstablishIntroKeys()
	if err != nil {
		return nil, fmt.Errorf("generate intro keys: %w", err)
	}

	if s.config.CircuitBuilder == nil || s.config.PathSelector == nil {
		if !s.config.AllowPlaceholderIntros {
			return nil, fmt.Errorf("circuit builder/path selector required for hosting (no placeholder)")
		}
		intro := &ServiceIntroPoint{
			Relay:       relay,
			CircuitID:   uint32(3000 + len(s.introPoints)),
			AuthPrivate: keys.AuthPrivate,
			AuthPublic:  keys.AuthPublic,
			EncKey:      keys.EncPrivate,
			Established: false,
			CreatedAt:   time.Now(),
		}
		s.logger.Debug("placeholder intro (test mode)", "relay", relay.Fingerprint)
		return intro, nil
	}

	circ, err := s.introManager.BuildIntroCircuitWithRetry(ctx, relay)
	if err != nil {
		return nil, fmt.Errorf("build intro circuit: %w", err)
	}

	hops := circ.GetHops()
	var circNonce []byte
	if len(hops) > 0 && hops[len(hops)-1] != nil {
		circNonce = append([]byte(nil), hops[len(hops)-1].RendCircNonce...)
	}
	if len(circNonce) != 20 {
		return nil, fmt.Errorf("intro circuit missing rend_circ_nonce (got %d bytes)", len(circNonce))
	}

	if err := s.sendEstablishIntro(ctx, circ, keys, circNonce); err != nil {
		s.introManager.RecordFailure(circ.ID)
		if s.config.Metrics != nil {
			s.config.Metrics.RecordOnionServiceIntroEstablish(false)
		}
		return nil, fmt.Errorf("ESTABLISH_INTRO: %w", err)
	}
	s.introManager.RegisterIntroPoint(circ.ID)
	s.introManager.RecordSuccess(circ.ID)
	if s.config.Metrics != nil {
		s.config.Metrics.RecordOnionServiceIntroEstablish(true)
		s.config.Metrics.SetOnionServiceIntroPoints(int64(len(s.introPoints) + 1))
	}

	intro := &ServiceIntroPoint{
		Relay:         relay,
		CircuitID:     circ.ID,
		AuthPrivate:   keys.AuthPrivate,
		AuthPublic:    keys.AuthPublic,
		EncKey:        keys.EncPrivate,
		Established:   true,
		CreatedAt:     time.Now(),
		RendCircNonce: circNonce,
	}
	s.logger.Info("Introduction point established",
		"relay", relay.Fingerprint,
		"circuit", circ.ID)
	return intro, nil
}

// createDescriptor creates the onion service descriptor
func (s *Service) createDescriptor() error {
	s.logger.Debug("Creating service descriptor")

	// Calculate blinded public key for current time period
	timePeriod := GetTimePeriod(time.Now())
	blindedPubkey := ComputeBlindedPubkey(s.publicKey, timePeriod)
	descriptorID := computeDescriptorID(blindedPubkey)

	// Build introduction points list
	introPoints := make([]IntroductionPoint, 0, len(s.introPoints))
	for _, serviceIntro := range s.introPoints {
		if !serviceIntro.Established {
			continue
		}
		linkSpecs := []LinkSpecifier{}
		onionKey := make([]byte, 32)
		if serviceIntro.Relay != nil && serviceIntro.Relay.Relay != nil {
			ok, specs, err := linkSpecsForRelay(serviceIntro.Relay)
			if err == nil {
				onionKey = ok
				linkSpecs = specs
			}
		}
		encPub := serviceIntro.EncKey
		if len(serviceIntro.EncKey) == 32 {
			if p, err := curve25519.X25519(serviceIntro.EncKey, curve25519.Basepoint); err == nil {
				encPub = p
			}
		}
		intro := IntroductionPoint{
			LinkSpecifiers: linkSpecs,
			OnionKey:       onionKey,
			AuthKey:        append([]byte(nil), serviceIntro.AuthPublic...),
			EncKey:         encPub,
			EncKeyCert:     nil,
			LegacyKeyID:    make([]byte, 20),
		}
		introPoints = append(introPoints, intro)
	}

	// Use the tracked descriptor revision counter
	// This ensures monotonically increasing revisions across restarts
	s.mu.RLock()
	revisionCounter := s.descriptorRev
	s.mu.RUnlock()

	now := time.Now()
	desc := &Descriptor{
		Version:         3,
		Address:         s.address,
		IntroPoints:     introPoints,
		DescriptorID:    descriptorID,
		BlindedPubkey:   blindedPubkey,
		RevisionCounter: revisionCounter,
		CreatedAt:       now,
		Lifetime:        s.config.DescriptorLifetime,
	}

	// Sign the descriptor
	if err := s.signDescriptor(desc); err != nil {
		return fmt.Errorf("failed to sign descriptor: %w", err)
	}

	s.mu.Lock()
	s.descriptor = desc
	s.mu.Unlock()

	s.logger.Info("Descriptor created",
		"descriptor_id", fmt.Sprintf("%x", descriptorID[:8]),
		"intro_points", len(introPoints),
		"lifetime", s.config.DescriptorLifetime)

	return nil
}

// signDescriptor 密封描述符（双层加密）并以 type-8 致盲证书链签名。
func (s *Service) signDescriptor(desc *Descriptor) error {
	if desc == nil {
		return fmt.Errorf("descriptor is nil")
	}
	period := GetTimePeriod(time.Now())
	if len(desc.BlindedPubkey) != 32 {
		desc.BlindedPubkey = ComputeBlindedPubkey(s.identityKey.Public().(ed25519.PublicKey), period)
	}
	blindedMat, err := DeriveBlindedSigningMaterial(s.identityKey, period)
	if err != nil {
		return fmt.Errorf("blinded signing material: %w", err)
	}

	// 1) 描述符签名密钥（引言点 auth-key/enc-key-cert 需用其签名）
	signingPub, signingPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("generate descriptor signing key: %w", err)
	}
	expires := time.Now().Add(desc.Lifetime)
	if desc.Lifetime <= 0 {
		expires = time.Now().Add(3 * time.Hour)
	}

	introPlain, err := encodeIntroPointsPlaintext(desc.IntroPoints, signingPriv, expires)
	if err != nil {
		return fmt.Errorf("encode intro plaintext: %w", err)
	}
	subcred := ComputeHSSubcredential(s.identityKey.Public().(ed25519.PublicKey), desc.BlindedPubkey)
	superBlob, err := SealDescriptorLayers(desc.BlindedPubkey, subcred, desc.RevisionCounter, introPlain)
	if err != nil {
		return fmt.Errorf("seal layers: %w", err)
	}
	desc.SuperencryptedBlob = superBlob

	// 2) type-8 证书（由致盲身份密钥签发）
	cert, err := buildType8SigningKeyCert(blindedMat, signingPub, expires)
	if err != nil {
		return fmt.Errorf("type8 cert: %w", err)
	}
	desc.DescriptorSigningKeyCert = cert

	// 3) 编码并签名
	encoded, err := EncodeDescriptor(desc)
	if err != nil {
		return fmt.Errorf("encode descriptor: %w", err)
	}
	desc.Signature = ed25519.Sign(signingPriv, HSDescriptorSignedMaterial(encoded))
	encoded, err = EncodeDescriptor(desc)
	if err != nil {
		return fmt.Errorf("encode signed descriptor: %w", err)
	}
	desc.RawDescriptor = encoded
	return nil
}

// uploadDescriptor 经 BEGIN_DIR 匿名上传描述符（禁止明文 DirPort）。
func (s *Service) publishDescriptor(ctx context.Context, hsdirs []*HSDirectory) error {
	s.logger.Info("Publishing descriptor to HSDirs")

	s.mu.RLock()
	desc := s.descriptor
	s.mu.RUnlock()

	if desc == nil {
		return fmt.Errorf("no descriptor to publish")
	}

	// Select responsible HSDirs using HSDir protocol
	hsdir := NewHSDir(s.logger)

	// Publish to both replicas
	published := 0
	for replica := 0; replica < 2; replica++ {
		selectedHSDirs := hsdir.SelectHSDirs(desc.DescriptorID, hsdirs, replica)

		for _, targetHSDir := range selectedHSDirs {
			if err := s.uploadDescriptor(ctx, targetHSDir, desc, replica); err != nil {
				s.logger.Warn("Failed to publish to HSDir",
					"hsdir", targetHSDir.Fingerprint,
					"replica", replica,
					"error", err)
				continue
			}
			published++
			s.logger.Debug("Descriptor published",
				"hsdir", targetHSDir.Fingerprint,
				"replica", replica)
		}
	}

	if published == 0 {
		if s.config.Metrics != nil {
			s.config.Metrics.RecordOnionServiceDescriptorPublish(false)
		}
		return fmt.Errorf("failed to publish descriptor to any HSDir")
	}

	s.mu.Lock()
	s.lastPublish = time.Now()
	s.descriptorRev++ // Increment revision counter on each publish
	s.mu.Unlock()

	if s.config.Metrics != nil {
		s.config.Metrics.RecordOnionServiceDescriptorPublish(true)
	}

	s.logger.Info("Descriptor published successfully",
		"hsdirs", published,
		"revision", s.descriptorRev)

	// Save state after successful publish
	if err := s.saveState(); err != nil {
		s.logger.Warn("Failed to save state after descriptor publish", "error", err)
	}

	return nil
}

// uploadDescriptor 经 BEGIN_DIR 匿名上传描述符（禁止明文 DirPort）。
func (s *Service) uploadDescriptor(ctx context.Context, hsdir *HSDirectory, desc *Descriptor, replica int) error {
	s.logger.Debug("Uploading descriptor to HSDir",
		"hsdir", hsdir.Fingerprint,
		"replica", replica,
		"descriptor_size", len(desc.RawDescriptor))

	if s.config.Begindir == nil {
		if s.config.AllowPlaceholderIntros {
			s.logger.Debug("skip upload in placeholder test mode", "hsdir", hsdir.Fingerprint)
			return nil
		}
		return fmt.Errorf("BEGIN_DIR uploader not configured")
	}
	relay := hsdir.Relay
	if relay == nil || !relay.HasNtorKeys() {
		return fmt.Errorf("HSDir %s missing relay microdesc keys for BEGIN_DIR", hsdir.Fingerprint)
	}
	if err := s.config.Begindir.Post(ctx, relay, "/tor/hs/3/publish", desc.RawDescriptor); err != nil {
		return err
	}
	s.logger.Info("Successfully uploaded descriptor via BEGIN_DIR",
		"hsdir", hsdir.Fingerprint,
		"replica", replica)
	return nil
}

// maintenanceLoop handles periodic tasks
func (s *Service) maintenanceLoop(ctx context.Context, hsdirs []*HSDirectory) {
	// Refresh descriptor every hour or 2/3 of lifetime, whichever is shorter
	refreshInterval := s.config.DescriptorLifetime * 2 / 3
	if refreshInterval > time.Hour {
		refreshInterval = time.Hour
	}

	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.logger.Debug("Running maintenance tasks")

			// Check for unhealthy or stale introduction points
			s.rotateUnhealthyIntroPoints(ctx, hsdirs)

			// Re-publish descriptor
			if err := s.createDescriptor(); err != nil {
				s.logger.Error("Failed to refresh descriptor", "error", err)
			} else if err := s.publishDescriptor(ctx, hsdirs); err != nil {
				s.logger.Error("Failed to re-publish descriptor", "error", err)
			} else {
				s.logger.Info("Descriptor refreshed and re-published")
			}
		}
	}
}

// rotateUnhealthyIntroPoints replaces unhealthy or stale introduction points
func (s *Service) rotateUnhealthyIntroPoints(ctx context.Context, hsdirs []*HSDirectory) {
	// Get unhealthy and stale intro points
	unhealthy := s.introManager.GetUnhealthyIntroPoints()
	stale := s.introManager.GetStaleIntroPoints()

	// Combine into set of intro points to replace
	toReplace := make(map[uint32]bool)
	for _, id := range unhealthy {
		toReplace[id] = true
	}
	for _, id := range stale {
		toReplace[id] = true
	}

	if len(toReplace) == 0 {
		return
	}

	s.logger.Info("Rotating introduction points",
		"unhealthy", len(unhealthy),
		"stale", len(stale),
		"total_to_replace", len(toReplace))

	s.mu.Lock()
	defer s.mu.Unlock()

	// Remove unhealthy/stale intro points
	newIntroPoints := make([]*ServiceIntroPoint, 0, len(s.introPoints))
	for _, intro := range s.introPoints {
		if toReplace[intro.CircuitID] {
			s.logger.Info("Removing introduction point",
				"circuit", intro.CircuitID,
				"relay", intro.Relay.Fingerprint)
			s.introManager.UnregisterIntroPoint(intro.CircuitID)
		} else {
			newIntroPoints = append(newIntroPoints, intro)
		}
	}
	s.introPoints = newIntroPoints

	// Establish new introduction points to maintain desired count
	needed := s.config.NumIntroPoints - len(s.introPoints)
	if needed <= 0 {
		return
	}

	s.logger.Info("Establishing replacement introduction points", "needed", needed)

	// Select relays for new intro points (simplified - use first available)
	availableRelays := hsdirs
	for i := 0; i < needed && i < len(availableRelays); i++ {
		relay := availableRelays[i]
		intro, err := s.establishIntroductionPoint(ctx, relay)
		if err != nil {
			s.logger.Warn("Failed to establish replacement intro point",
				"relay", relay.Fingerprint,
				"error", err)
			continue
		}
		s.introPoints = append(s.introPoints, intro)
	}

	s.logger.Info("Introduction point rotation complete",
		"current_count", len(s.introPoints),
		"target_count", s.config.NumIntroPoints)
}

// HandleIntroduce2 handles an INTRODUCE2 cell from an introduction point
func (s *Service) HandleIntroduce2(introCircuitID uint32, introduce2Data []byte) error {
	s.logger.Info("Received INTRODUCE2 cell",
		"circuit", introCircuitID,
		"size", len(introduce2Data))

	// Find the introduction point for this circuit
	s.mu.RLock()
	var introPoint *ServiceIntroPoint
	for _, ip := range s.introPoints {
		if ip.CircuitID == introCircuitID {
			introPoint = ip
			break
		}
	}
	s.mu.RUnlock()

	if introPoint == nil {
		return fmt.Errorf("no introduction point found for circuit %d", introCircuitID)
	}

	// Parse and decrypt INTRODUCE2 cell（hs-ntor）
	timePeriod := GetTimePeriod(time.Now())
	blinded := ComputeBlindedPubkey(s.publicKey, timePeriod)
	subcred := ComputeHSSubcredential(s.publicKey, blinded)
	request, err := ParseIntroduce2(introduce2Data, introPoint.EncKey, subcred)
	if err != nil {
		return fmt.Errorf("failed to parse INTRODUCE2: %w", err)
	}

	s.logger.Debug("INTRODUCE2 parsed successfully",
		"cookie", fmt.Sprintf("%x", request.RendezvousCookie[:16]),
		"link_specs", len(request.LinkSpecifiers))

	// Extract rendezvous point address from link specifiers
	rendezvousAddr, err := LinkSpecifierToAddress(request.LinkSpecifiers)
	if err != nil {
		s.logger.Warn("Could not extract rendezvous address", "error", err)
		// Continue anyway - we'll store what we have
		rendezvousAddr = "unknown"
	}

	cookieStr := fmt.Sprintf("%x", request.RendezvousCookie)

	// Store pending introduction
	s.mu.Lock()
	s.pendingIntros[cookieStr] = &PendingIntro{
		Cookie:          request.RendezvousCookie,
		RendezvousPoint: rendezvousAddr,
		ClientOnionKey:  request.ClientOnionKey,
		IntroAuthKey:    append([]byte(nil), request.IntroAuthKey...),
		ReceivedAt:      time.Now(),
	}
	s.mu.Unlock()

	s.logger.Debug("INTRODUCE2 request stored",
		"cookie", cookieStr[:16],
		"rendezvous", rendezvousAddr)

	// Build circuit to rendezvous point if we have a rendezvous builder
	if s.rendezvousBuilder != nil {
		s.logger.Info("Building rendezvous circuit",
			"cookie", cookieStr[:16],
			"rendezvous", rendezvousAddr)

		// Build circuit asynchronously to avoid blocking
		go func() {
			ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
			defer cancel()

			circ, err := s.rendezvousBuilder.BuildRendezvousCircuit(
				ctx,
				request.LinkSpecifiers,
				25*time.Second,
			)
			if err != nil {
				s.logger.Error("Failed to build rendezvous circuit",
					"cookie", cookieStr[:16],
					"error", err)
				if s.config.Metrics != nil {
					s.config.Metrics.RecordOnionServiceRendezvous(false)
				}
				// Remove pending intro on failure
				s.mu.Lock()
				delete(s.pendingIntros, cookieStr)
				s.mu.Unlock()
				return
			}

			s.logger.Info("Rendezvous circuit built successfully",
				"cookie", cookieStr[:16],
				"circuit_id", circ.ID)

			// Store circuit ID and read hs-ntor keys under lock
			s.mu.Lock()
			s.rendezvousCircuits[cookieStr] = circ.ID
			pending := s.pendingIntros[cookieStr]
			var introAuth, clientX []byte
			if pending != nil {
				introAuth = append([]byte(nil), pending.IntroAuthKey...)
				clientX = append([]byte(nil), pending.ClientOnionKey...)
			}
			s.mu.Unlock()

			if len(introAuth) != 32 || len(clientX) != 32 {
				s.logger.Error("missing hs-ntor keys for RENDEZVOUS1",
					"cookie", cookieStr[:16],
					"auth_len", len(introAuth),
					"x_len", len(clientX))
				if s.config.Metrics != nil {
					s.config.Metrics.RecordOnionServiceRendezvous(false)
				}
				s.mu.Lock()
				delete(s.pendingIntros, cookieStr)
				delete(s.rendezvousCircuits, cookieStr)
				s.mu.Unlock()
				return
			}

			s.logger.Info("Sending RENDEZVOUS1 cell (hs-ntor)",
				"cookie", cookieStr[:16],
				"circuit_id", circ.ID)

			keyMaterial, err := SendRendezvous1(
				circ,
				circ.ID,
				request.RendezvousCookie,
				clientX,
				s.ntorKey,
				introAuth,
			)
			if err != nil {
				s.logger.Error("Failed to send RENDEZVOUS1",
					"cookie", cookieStr[:16],
					"error", err)
				if s.config.Metrics != nil {
					s.config.Metrics.RecordOnionServiceRendezvous(false)
				}
				// Clean up on failure
				s.mu.Lock()
				delete(s.pendingIntros, cookieStr)
				delete(s.rendezvousCircuits, cookieStr)
				s.mu.Unlock()
				return
			}

			s.logger.Info("RENDEZVOUS1 sent successfully",
				"cookie", cookieStr[:16],
				"key_material_len", len(keyMaterial))

			if s.config.Metrics != nil {
				s.config.Metrics.RecordOnionServiceRendezvous(true)
			}

			// Task 9.3.1: Set up relay cell handler for incoming streams
			// Start monitoring the rendezvous circuit for RELAY_BEGIN cells
			s.logger.Info("Starting stream handler for rendezvous circuit",
				"circuit_id", circ.ID)

			go s.handleRendezvousCircuitCells(circ)
		}()
	} else {
		s.logger.Warn("Rendezvous circuit builder not configured, circuit not built",
			"cookie", cookieStr[:16])
	}

	return nil
}

// GetStats returns statistics about the service
func (s *Service) GetStats() ServiceStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	activeStreams := 0
	if s.streamManager != nil {
		activeStreams = s.streamManager.GetActiveStreamCount()
	}

	return ServiceStats{
		Address:            s.address.String(),
		Running:            s.running,
		IntroPoints:        len(s.introPoints),
		DescriptorAge:      time.Since(s.lastPublish),
		PendingIntros:      len(s.pendingIntros),
		PublishedHSDirs:    len(s.publishedHSDirs),
		RendezvousCircuits: len(s.rendezvousCircuits),
		ActiveStreams:      activeStreams,
	}
}

// ServiceStats contains statistics about a running service
type ServiceStats struct {
	Address            string
	Running            bool
	IntroPoints        int
	DescriptorAge      time.Duration
	PendingIntros      int
	PublishedHSDirs    int
	RendezvousCircuits int
	ActiveStreams      int
}

// buildIntroCircuit builds a 3-hop circuit to the introduction point relay
// sendEstablishIntro sends an ESTABLISH_INTRO cell to the introduction point
func (s *Service) sendEstablishIntro(ctx context.Context, circ *circuit.Circuit, keys *EstablishIntroKeys, circNonce []byte) error {
	payload, err := BuildEstablishIntroPayload(keys.AuthPublic, keys.AuthPrivate, circNonce)
	if err != nil {
		return err
	}
	relayCell, err := NewEstablishIntroRelayCell(payload)
	if err != nil {
		return fmt.Errorf("create ESTABLISH_INTRO cell: %w", err)
	}
	if err := circ.SendRelayCell(relayCell); err != nil {
		return fmt.Errorf("send ESTABLISH_INTRO: %w", err)
	}
	waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := s.waitForIntroEstablished(waitCtx, circ); err != nil {
		return fmt.Errorf("INTRO_ESTABLISHED: %w", err)
	}
	return nil
}

// waitForIntroEstablished waits for an INTRO_ESTABLISHED acknowledgment
func (s *Service) waitForIntroEstablished(ctx context.Context, circ *circuit.Circuit) error {
	// Wait for INTRO_ESTABLISHED relay cell from the introduction point
	// Per rend-spec-v3.txt §3.1.1, the relay responds with INTRO_ESTABLISHED
	relayCell, err := circ.ReceiveRelayCell(ctx)
	if err != nil {
		return fmt.Errorf("failed to receive INTRO_ESTABLISHED: %w", err)
	}

	// Validate that we received the correct cell type
	if relayCell.Command != cell.RelayIntroEstdAck {
		return fmt.Errorf("expected INTRO_ESTABLISHED (39) but got relay command %d", relayCell.Command)
	}

	s.logger.Debug("Received INTRO_ESTABLISHED acknowledgment",
		"circuit_id", circ.ID,
		"stream_id", relayCell.StreamID)

	return nil
}

// handleRendezvousCircuitCells monitors a rendezvous circuit for incoming relay cells
// and dispatches them to the stream manager (Task 9.3.1)
func (s *Service) handleRendezvousCircuitCells(circ CircuitInterface) {
	s.logger.Info("Starting rendezvous circuit relay cell handler",
		"circuit_id", circ.GetID())

	for {
		// Receive relay cell with timeout
		ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
		relayCell, err := circ.ReceiveRelayCell(ctx)
		cancel()

		if err != nil {
			// Check if service is shutting down
			select {
			case <-s.ctx.Done():
				s.logger.Debug("Service context cancelled, stopping relay handler",
					"circuit_id", circ.GetID())
				return
			default:
			}

			s.logger.Debug("Error receiving relay cell",
				"circuit_id", circ.GetID(),
				"error", err)
			continue
		}

		// Dispatch based on relay command
		switch relayCell.Command {
		case cell.RelayBegin:
			// Handle RELAY_BEGIN - client initiating new stream
			s.logger.Info("Received RELAY_BEGIN on rendezvous circuit",
				"circuit_id", circ.GetID(),
				"stream_id", relayCell.StreamID)

			if err := s.streamManager.HandleRelayBegin(
				circ.GetID(),
				relayCell.StreamID,
				relayCell.Data,
				circ,
			); err != nil {
				s.logger.Error("Failed to handle RELAY_BEGIN",
					"circuit_id", circ.GetID(),
					"stream_id", relayCell.StreamID,
					"error", err)
			}

		case cell.RelayData:
			// Handle RELAY_DATA - client sending data on stream
			s.logger.Debug("Received RELAY_DATA on rendezvous circuit",
				"circuit_id", circ.GetID(),
				"stream_id", relayCell.StreamID,
				"data_len", len(relayCell.Data))

			if err := s.streamManager.HandleRelayData(
				relayCell.StreamID,
				relayCell.Data,
			); err != nil {
				s.logger.Error("Failed to handle RELAY_DATA",
					"stream_id", relayCell.StreamID,
					"error", err)
			}

		case cell.RelayEnd:
			// Handle RELAY_END - client closing stream
			s.logger.Info("Received RELAY_END on rendezvous circuit",
				"circuit_id", circ.GetID(),
				"stream_id", relayCell.StreamID)

			if err := s.streamManager.HandleRelayEnd(relayCell.StreamID); err != nil {
				s.logger.Error("Failed to handle RELAY_END",
					"stream_id", relayCell.StreamID,
					"error", err)
			}

		case cell.RelaySendme:
			// Handle SENDME for flow control
			s.logger.Debug("Received SENDME on rendezvous circuit",
				"circuit_id", circ.GetID(),
				"stream_id", relayCell.StreamID)
			// Flow control handling would go here

		default:
			s.logger.Warn("Unexpected relay command on rendezvous circuit",
				"circuit_id", circ.GetID(),
				"command", relayCell.Command,
				"stream_id", relayCell.StreamID)
		}
	}
}
