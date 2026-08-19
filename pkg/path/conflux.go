package path

import (
	"crypto/subtle"
	"fmt"

	"github.com/opd-ai/go-tor/pkg/directory"
)

// PathAdvertisesConflux 表示三条 hop 都宣告了 Conflux（1 或 2）且 FlowCtrl=2。
// 缺宣告时不得建套；建套失败也不得把单电路标成 Conflux。
func PathAdvertisesConflux(p *Path) bool {
	if p == nil || p.Guard == nil || p.Middle == nil || p.Exit == nil {
		return false
	}
	return confluxHopOK(p.Guard) && confluxHopOK(p.Middle) && confluxHopOK(p.Exit)
}

func confluxHopOK(r *directory.Relay) bool {
	return r.AdvertisesConflux() && r.RequestCongestionControl()
}

func relayIdentity(r *directory.Relay) string {
	if r == nil {
		return ""
	}
	if hex := r.GetFingerprintHex(); hex != "" {
		return hex
	}
	return r.Fingerprint
}

func sameRelayIdentity(a, b *directory.Relay) bool {
	if a == nil || b == nil {
		return false
	}
	if len(a.IdentityKey) == 32 && len(b.IdentityKey) == 32 &&
		subtle.ConstantTimeCompare(a.IdentityKey, b.IdentityKey) == 1 {
		return true
	}
	ia, ib := relayIdentity(a), relayIdentity(b)
	return ia != "" && ia == ib
}

func (s *Selector) sharesFamilyOrSubnet(r *directory.Relay, others ...*directory.Relay) bool {
	if r == nil {
		return false
	}
	for _, o := range others {
		if o != nil && (s.sameFamily(r, o) || r.InSameSubnet(o)) {
			return true
		}
	}
	return false
}

func identityIn(r *directory.Relay, others ...*directory.Relay) bool {
	for _, o := range others {
		if sameRelayIdentity(r, o) {
			return true
		}
	}
	return false
}

// SelectConfluxPath 选一条三跳均宣告 Conflux 且 FlowCtrl=2 的路径，供第一腿使用。
// 选不出合格 hop 时返回错误，调用方应回退普通 SelectPath，且不得标成 Conflux。
func (s *Selector) SelectConfluxPath(exitPort int) (*Path, error) {
	return s.SelectConfluxPathFor(ExitTarget{Port: exitPort})
}

// SelectConfluxPathFor 与 SelectConfluxPath 相同，但按目的地址族过滤 exit。
func (s *Selector) SelectConfluxPathFor(target ExitTarget) (*Path, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.guards) == 0 || len(s.relays) == 0 {
		return nil, fmt.Errorf("no relays available, call UpdateConsensus first")
	}

	guard, err := s.selectConfluxGuardFrom(nil)
	if err != nil {
		return nil, err
	}
	exit, err := s.selectConfluxExit(target, guard)
	if err != nil {
		return nil, err
	}
	middle, err := s.selectConfluxMiddle(&Path{Guard: guard, Exit: exit}, guard, exit)
	if err != nil {
		return nil, err
	}
	p := &Path{Guard: guard, Middle: middle, Exit: exit}
	if !PathAdvertisesConflux(p) {
		return nil, fmt.Errorf("constructed path missing Conflux advertisement")
	}
	s.logger.Info("Conflux first path selected",
		"guard", guard.Nickname,
		"middle", middle.Nickname,
		"exit", exit.Nickname)
	return p, nil
}

func (s *Selector) selectConfluxGuardFrom(first *Path) (*directory.Relay, error) {
	candidates := make([]*directory.Relay, 0)
	for _, relay := range s.guards {
		if !confluxHopOK(relay) {
			continue
		}
		if first != nil && (identityIn(relay, first.Guard, first.Middle, first.Exit) ||
			s.sharesFamilyOrSubnet(relay, first.Guard, first.Middle, first.Exit)) {
			continue
		}
		candidates = append(candidates, relay)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no distinct Conflux-capable guard")
	}
	idx, err := weightedRandomIndex(candidates)
	if err != nil {
		return nil, err
	}
	return candidates[idx], nil
}

func (s *Selector) selectConfluxExit(target ExitTarget, avoid *directory.Relay) (*directory.Relay, error) {
	exits := make([]*directory.Relay, 0)
	for _, relay := range s.relays {
		if !confluxHopOK(relay) {
			continue
		}
		if avoid != nil && (sameRelayIdentity(relay, avoid) || s.sameFamily(relay, avoid) || relay.InSameSubnet(avoid)) {
			continue
		}
		if relay.AllowsExitTarget(target.Port, target.IP) {
			exits = append(exits, relay)
		}
	}
	if len(exits) == 0 {
		return nil, fmt.Errorf("no Conflux-capable exit for %s", target)
	}
	idx, err := weightedRandomIndex(exits)
	if err != nil {
		return nil, err
	}
	return exits[idx], nil
}

// SelectConfluxSecondPath 选第二条腿：同一 Exit，不同 Guard/Middle。
// 第二腿 Guard/Middle 不得与第一腿 Guard/Middle 同身份、同 family 或同 /16。
// first 的三条 hop 必须已宣告 Conflux；否则返回错误，调用方应保持单电路。
func (s *Selector) SelectConfluxSecondPath(first *Path) (*Path, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !PathAdvertisesConflux(first) {
		return nil, fmt.Errorf("first path does not advertise Conflux on all hops")
	}
	if len(s.relays) == 0 {
		return nil, fmt.Errorf("no relays available, call UpdateConsensus first")
	}

	exit := first.Exit
	guard, err := s.selectConfluxGuardFrom(first)
	if err != nil {
		return nil, err
	}
	middle, err := s.selectConfluxMiddle(first, guard, exit)
	if err != nil {
		return nil, err
	}

	second := &Path{Guard: guard, Middle: middle, Exit: exit}
	if !PathAdvertisesConflux(second) {
		return nil, fmt.Errorf("second path missing Conflux advertisement")
	}
	if sameRelayIdentity(second.Guard, first.Guard) || sameRelayIdentity(second.Middle, first.Middle) ||
		sameRelayIdentity(second.Guard, first.Middle) || sameRelayIdentity(second.Middle, first.Guard) ||
		sameRelayIdentity(second.Guard, second.Middle) || sameRelayIdentity(second.Guard, exit) ||
		sameRelayIdentity(second.Middle, exit) {
		return nil, fmt.Errorf("second path shares a hop identity")
	}

	s.logger.Info("Conflux second path selected",
		"guard", guard.Nickname,
		"middle", middle.Nickname,
		"exit", exit.Nickname)
	return second, nil
}

func (s *Selector) selectConfluxMiddle(first *Path, guard, exit *directory.Relay) (*directory.Relay, error) {
	candidates := make([]*directory.Relay, 0)
	for _, relay := range s.relays {
		if !confluxHopOK(relay) {
			continue
		}
		if identityIn(relay, first.Guard, first.Middle, first.Exit, guard, exit) {
			continue
		}
		if first != nil && s.sharesFamilyOrSubnet(relay, first.Guard, first.Middle) {
			continue
		}
		// 单条腿内部仍遵守 path-spec family/subnet，避免与本腿 Guard/Exit 共享瓶颈。
		if guard != nil && (s.sameFamily(relay, guard) || relay.InSameSubnet(guard)) {
			continue
		}
		if exit != nil && (s.sameFamily(relay, exit) || relay.InSameSubnet(exit)) {
			continue
		}
		candidates = append(candidates, relay)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no distinct Conflux-capable middle for second leg")
	}
	idx, err := weightedRandomIndex(candidates)
	if err != nil {
		return nil, err
	}
	return candidates[idx], nil
}
