// Package path provides path selection algorithms for Tor circuits.
// This package implements guard, middle, and exit node selection.
package path

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"

	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/logger"
)

// ExitTarget 描述出口流的目的。IP 为 nil 表示主机名或预建，走 IPv4 / 未知地址策略。
// IPv6 字面量必须按 p6 选路，缺 p6 的 exit 不得入选。
type ExitTarget struct {
	Port int
	IP   net.IP
}

func (t ExitTarget) String() string {
	if t.IP != nil {
		return net.JoinHostPort(t.IP.String(), fmt.Sprintf("%d", t.Port))
	}
	return fmt.Sprintf("*:%d", t.Port)
}

// Path represents a selected path through the Tor network
type Path struct {
	Guard  *directory.Relay
	Middle *directory.Relay
	Exit   *directory.Relay
}

// Selector provides path selection for Tor circuits
type Selector struct {
	logger            *logger.Logger
	dirClient         *directory.Client
	guardManager      *GuardManager
	diversityAnalyzer *DiversityAnalyzer
	biasDetector      *BiasDetector
	mu                sync.RWMutex
	guards            []*directory.Relay
	relays            []*directory.Relay
}

// NewSelector creates a new path selector
func NewSelector(dirClient *directory.Client, log *logger.Logger) *Selector {
	if log == nil {
		log = logger.NewDefault()
	}

	return &Selector{
		logger:            log.Component("path"),
		dirClient:         dirClient,
		diversityAnalyzer: NewDiversityAnalyzer(log),
		biasDetector:      NewBiasDetector(DefaultThresholds()),
		guards:            make([]*directory.Relay, 0),
		relays:            make([]*directory.Relay, 0),
	}
}

// NewSelectorWithGuards creates a new path selector with guard persistence
func NewSelectorWithGuards(dirClient *directory.Client, guardMgr *GuardManager, log *logger.Logger) *Selector {
	if log == nil {
		log = logger.NewDefault()
	}

	return &Selector{
		logger:            log.Component("path"),
		dirClient:         dirClient,
		guardManager:      guardMgr,
		diversityAnalyzer: NewDiversityAnalyzer(log),
		biasDetector:      NewBiasDetector(DefaultThresholds()),
		guards:            make([]*directory.Relay, 0),
		relays:            make([]*directory.Relay, 0),
	}
}

// UpdateConsensus fetches and updates the network consensus
func (s *Selector) UpdateConsensus(ctx context.Context) error {
	s.logger.Info("Updating network consensus")

	relays, err := s.dirClient.FetchConsensus(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch consensus: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Filter relays for guards (must be Guard, Running, Valid, Stable)
	guards := make([]*directory.Relay, 0)
	allRelays := make([]*directory.Relay, 0)

	for _, relay := range relays {
		if !relay.IsRunning() || !relay.IsValid() {
			continue // Skip non-running or invalid relays
		}

		allRelays = append(allRelays, relay)

		if relay.IsGuard() && relay.IsStable() {
			guards = append(guards, relay)
		}
	}

	s.guards = guards
	s.relays = allRelays

	s.logger.Info("Consensus updated",
		"total_relays", len(allRelays),
		"guard_relays", len(guards))

	return nil
}

// GetRelays returns all relays from the current consensus (for event publishing)
func (s *Selector) GetRelays() []*directory.Relay {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Return a copy to avoid race conditions
	relays := make([]*directory.Relay, len(s.relays))
	copy(relays, s.relays)
	return relays
}

// SelectPath 按 IPv4/主机名端口选一条三跳路径。
func (s *Selector) SelectPath(exitPort int) (*Path, error) {
	return s.SelectPathFor(ExitTarget{Port: exitPort})
}

// SelectPathFor 按目的地址族选路。IPv6 字面量只接受 p6 放行该端口的 exit。
func (s *Selector) SelectPathFor(target ExitTarget) (*Path, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.guards) == 0 || len(s.relays) == 0 {
		return nil, fmt.Errorf("no relays available, call UpdateConsensus first")
	}

	// Try up to 5 times to find a path with at least medium diversity
	const maxAttempts = 5
	var bestPath *Path
	var bestScore *PathScore

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Select guard
		guard, err := s.selectGuard()
		if err != nil {
			return nil, fmt.Errorf("failed to select guard: %w", err)
		}

		// Select exit (must allow the target and not be the guard)
		exit, err := s.selectExitFor(target, guard)
		if err != nil {
			return nil, fmt.Errorf("failed to select exit: %w", err)
		}

		// Select middle (must not be guard or exit)
		middle, err := s.selectMiddle(guard, exit)
		if err != nil {
			return nil, fmt.Errorf("failed to select middle: %w", err)
		}

		path := &Path{
			Guard:  guard,
			Middle: middle,
			Exit:   exit,
		}

		// Analyze diversity of this path
		score := s.diversityAnalyzer.AnalyzePath(path)

		// If this is our first path or a better path, save it
		if bestPath == nil || score.Overall > bestScore.Overall {
			bestPath = path
			bestScore = score
		}

		// If we found a path with at least medium diversity, use it
		if score.Level >= DiversityMedium {
			s.logger.Info("Path selected",
				"guard", guard.Nickname,
				"middle", middle.Nickname,
				"exit", exit.Nickname,
				"diversity", score.Level.String(),
				"score", score.Overall,
				"attempt", attempt+1)
			return path, nil
		}

		s.logger.Debug("Path diversity below threshold, retrying",
			"diversity", score.Level.String(),
			"score", score.Overall,
			"attempt", attempt+1)
	}

	// Use the best path we found, even if diversity is low
	s.logger.Info("Path selected (best of attempts)",
		"guard", bestPath.Guard.Nickname,
		"middle", bestPath.Middle.Nickname,
		"exit", bestPath.Exit.Nickname,
		"diversity", bestScore.Level.String(),
		"score", bestScore.Overall)

	return bestPath, nil
}

// selectGuard selects a guard relay, preferring persistent guards
// Avoids guards that appear to be biased based on path bias detection
func (s *Selector) selectGuard() (*directory.Relay, error) {
	if len(s.guards) == 0 {
		return nil, fmt.Errorf("no guard relays available")
	}

	// If we have a guard manager, try to use persistent guards first
	if s.guardManager != nil {
		persistentGuards := s.guardManager.GetGuards()

		// Try to find a persistent guard that's still in the current consensus and not biased
		for _, pGuard := range persistentGuards {
			for _, relay := range s.guards {
				if relay.Fingerprint == pGuard.Fingerprint {
					// Check if this guard is biased
					if s.biasDetector != nil && s.biasDetector.IsBiased(relay.Fingerprint) {
						s.logger.Warn("Skipping biased persistent guard",
							"nickname", relay.Nickname,
							"fingerprint", relay.Fingerprint)
						continue
					}

					s.logger.Debug("Using persistent guard", "nickname", relay.Nickname)
					return relay, nil
				}
			}
		}

		// If no persistent guards are available, select a new one and persist it
		s.logger.Debug("No persistent guards available, selecting new guard")
	}

	// Filter out biased guards
	availableGuards := s.guards
	if s.biasDetector != nil {
		filtered := make([]*directory.Relay, 0, len(s.guards))
		for _, guard := range s.guards {
			if !s.biasDetector.IsBiased(guard.Fingerprint) {
				filtered = append(filtered, guard)
			}
		}

		if len(filtered) > 0 {
			availableGuards = filtered
			s.logger.Debug("Filtered biased guards",
				"total", len(s.guards),
				"available", len(filtered))
		} else {
			s.logger.Warn("All guards appear biased, using all guards")
		}
	}

	// Select a random guard from available guards (bandwidth-weighted)
	idx, err := weightedRandomIndex(availableGuards)
	if err != nil {
		return nil, err
	}

	guard := availableGuards[idx]

	// Add to persistent guards if we have a guard manager
	if s.guardManager != nil {
		if err := s.guardManager.AddGuard(guard); err != nil {
			s.logger.Warn("Failed to persist guard", "error", err)
		} else if err := s.guardManager.Save(); err != nil {
			s.logger.Warn("Failed to save guard state", "error", err)
		}
	}

	return guard, nil
}

// ConfirmGuard marks a guard as confirmed after successful use
func (s *Selector) ConfirmGuard(fingerprint string) {
	if s.guardManager != nil {
		if err := s.guardManager.ConfirmGuard(fingerprint); err != nil {
			s.logger.Warn("Failed to confirm guard", "error", err)
			return
		}
		if err := s.guardManager.Save(); err != nil {
			s.logger.Warn("Failed to save guard state after confirmation", "error", err)
		}
	}
}

// selectExit 按 IPv4/主机名端口选 exit（兼容现有单测）。
func (s *Selector) selectExit(port int, avoid *directory.Relay) (*directory.Relay, error) {
	return s.selectExitFor(ExitTarget{Port: port}, avoid)
}

// selectExitFor 选允许该目标的 exit，并避开与 guard 同 family / 同 /16。
func (s *Selector) selectExitFor(target ExitTarget, avoid *directory.Relay) (*directory.Relay, error) {
	// Select exit that's not the guard and doesn't share family/subnet
	exits := make([]*directory.Relay, 0)

	for _, relay := range s.relays {
		// Skip family/subnet checks if no relay to avoid
		if avoid != nil {
			// Skip if same relay
			if relay.Fingerprint == avoid.Fingerprint {
				continue
			}

			// Skip if in same family (bidirectional family relationship)
			if relay.InSameFamily(avoid) {
				s.logger.Debug("Skipping exit in same family as guard",
					"exit", relay.Nickname, "guard", avoid.Nickname)
				continue
			}

			// Skip if in same /16 subnet
			if relay.InSameSubnet(avoid) {
				s.logger.Debug("Skipping exit in same subnet as guard",
					"exit", relay.Nickname, "guard", avoid.Nickname,
					"subnet", relay.Address[:strings.LastIndex(relay.Address, ".")])
				continue
			}
		}

		// 有策略时按地址族+端口过滤；否则退回 Exit flag（path-spec §2.2）
		if relay.AllowsExitTarget(target.Port, target.IP) {
			exits = append(exits, relay)
		}
	}

	if len(exits) == 0 {
		return nil, fmt.Errorf("no suitable exit relays available for %s (family/subnet/policy constraints)", target)
	}

	idx, err := weightedRandomIndex(exits)
	if err != nil {
		return nil, err
	}

	return exits[idx], nil
}

// selectMiddle selects a middle relay that is neither guard nor exit
// Ensures the middle relay doesn't share family or subnet with guard or exit (path-spec.txt §2.2.1)
func (s *Selector) selectMiddle(guard, exit *directory.Relay) (*directory.Relay, error) {
	candidates := make([]*directory.Relay, 0)

	for _, relay := range s.relays {
		// Skip family/subnet checks if no guard or exit to avoid
		if guard != nil && relay.Fingerprint == guard.Fingerprint {
			continue
		}
		if exit != nil && relay.Fingerprint == exit.Fingerprint {
			continue
		}

		// Skip if in same family as guard
		if guard != nil && relay.InSameFamily(guard) {
			s.logger.Debug("Skipping middle in same family as guard",
				"middle", relay.Nickname, "guard", guard.Nickname)
			continue
		}

		// Skip if in same family as exit
		if exit != nil && relay.InSameFamily(exit) {
			s.logger.Debug("Skipping middle in same family as exit",
				"middle", relay.Nickname, "exit", exit.Nickname)
			continue
		}

		// Skip if in same /16 subnet as guard
		if guard != nil && relay.InSameSubnet(guard) {
			s.logger.Debug("Skipping middle in same subnet as guard",
				"middle", relay.Nickname, "guard", guard.Nickname)
			continue
		}

		// Skip if in same /16 subnet as exit
		if exit != nil && relay.InSameSubnet(exit) {
			s.logger.Debug("Skipping middle in same subnet as exit",
				"middle", relay.Nickname, "exit", exit.Nickname)
			continue
		}

		candidates = append(candidates, relay)
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("no suitable middle relays available (family/subnet constraints)")
	}

	idx, err := weightedRandomIndex(candidates)
	if err != nil {
		return nil, err
	}

	return candidates[idx], nil
}

// randomIndex returns a cryptographically random index in [0, max)
func randomIndex(max int) (int, error) {
	if max <= 0 {
		return 0, fmt.Errorf("max must be positive")
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, fmt.Errorf("failed to generate random number: %w", err)
	}

	return int(n.Int64()), nil
}

// weightedRandomIndex returns a weighted random index based on relay bandwidths
// Implements bandwidth-weighted selection per path-spec.txt §2.2
// If all relays have zero bandwidth, falls back to uniform random selection
func weightedRandomIndex(relays []*directory.Relay) (int, error) {
	if len(relays) == 0 {
		return 0, fmt.Errorf("empty relay list")
	}

	// Calculate total bandwidth
	var totalBandwidth uint64
	for _, relay := range relays {
		totalBandwidth += relay.Bandwidth
	}

	// Fallback to uniform random if no bandwidth info available
	if totalBandwidth == 0 {
		return randomIndex(len(relays))
	}

	// Generate random value in [0, totalBandwidth)
	randVal, err := rand.Int(rand.Reader, big.NewInt(int64(totalBandwidth)))
	if err != nil {
		return 0, fmt.Errorf("failed to generate random number: %w", err)
	}

	// Select relay based on weighted probability
	var cumulative uint64
	target := randVal.Uint64()

	for i, relay := range relays {
		cumulative += relay.Bandwidth
		if cumulative > target {
			return i, nil
		}
	}

	// Fallback to last relay (should not happen due to rounding)
	return len(relays) - 1, nil
}

// GetDiversityStats returns statistics about path diversity analysis
func (s *Selector) GetDiversityStats() DiversityStats {
	if s.diversityAnalyzer == nil {
		return DiversityStats{}
	}
	return s.diversityAnalyzer.GetStats()
}

// RecordCircuitOutcome records the outcome of a circuit for path bias detection
func (s *Selector) RecordCircuitOutcome(circuitID uint32, guardFingerprint string, outcome CircuitOutcome) []BiasAlert {
	if s.biasDetector == nil {
		return nil
	}
	alerts := s.biasDetector.RecordOutcome(circuitID, guardFingerprint, outcome)

	// Log any new alerts
	for _, alert := range alerts {
		s.logger.Warn("Path bias detected",
			"type", alert.Type,
			"guard", alert.Fingerprint,
			"message", alert.Message)
	}

	return alerts
}

// GetBiasStats returns overall bias detection statistics
func (s *Selector) GetBiasStats() BiasStats {
	if s.biasDetector == nil {
		return BiasStats{}
	}
	return s.biasDetector.GetStats()
}

// GetBiasAlerts returns recent bias alerts
func (s *Selector) GetBiasAlerts(limit int) []BiasAlert {
	if s.biasDetector == nil {
		return nil
	}
	return s.biasDetector.GetAlerts(limit)
}

// IsGuardBiased checks if a guard appears to be biased
func (s *Selector) IsGuardBiased(fingerprint string) bool {
	if s.biasDetector == nil {
		return false
	}
	return s.biasDetector.IsBiased(fingerprint)
}
