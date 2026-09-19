package relay

import (
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
)

const (
	rendCookieLen   = 20
	unjoinedRendTTL = 10 * time.Minute // 对齐客户端 MaxCircuitDirtiness / 长 HS 等待窗
	maxUnjoinedRend = 128
)

// handleEstablishRendezvous 接受 ESTABLISH_RENDEZVOUS cookie 并回 RENDEZVOUS_ESTABLISHED。
// 对照 rend-spec-v3 §3.3 与 C Tor rend_mid_establish_rendezvous（须为末端跳）；未宣告 HSRend=*。
func (h *ForwardingHandler) handleEstablishRendezvous(circ *ServerCircuit, clientConn net.Conn, payload []byte) error {
	if circ == nil {
		return fmt.Errorf("nil circuit")
	}
	if err := h.rejectIfExtended(circ, clientConn, "ESTABLISH_RENDEZVOUS"); err != nil {
		return err
	}
	h.reapExpiredRend()
	if len(payload) < rendCookieLen {
		h.logger.Warn("ESTABLISH_RENDEZVOUS cookie too short", "circuit_id", circ.CircuitID, "len", len(payload))
		return h.destroyHSCircuit(circ, clientConn, fmt.Sprintf("rendezvous cookie length %d", len(payload)))
	}
	cookie := append([]byte(nil), payload[:rendCookieLen]...)
	if err := h.registerRend(circ, clientConn, cookie); err != nil {
		return h.destroyHSCircuit(circ, clientConn, err.Error())
	}
	h.addHSStat(func(s *HSRelayStats) { s.EstRend++ })
	return sendRelayToClient(circ, clientConn, 0, cell.RelayRendezvousEstablished, nil)
}

func (h *ForwardingHandler) registerRend(circ *ServerCircuit, conn net.Conn, cookie []byte) error {
	if circ == nil || len(cookie) != rendCookieLen {
		return fmt.Errorf("invalid rendezvous cookie")
	}
	key := hex.EncodeToString(cookie)
	h.hsMu.Lock()
	defer h.hsMu.Unlock()
	circ.mu.Lock()
	if len(circ.introAuth) > 0 {
		circ.mu.Unlock()
		return fmt.Errorf("circuit already introduction")
	}
	if len(circ.rendCookie) > 0 {
		circ.mu.Unlock()
		return fmt.Errorf("rendezvous already established")
	}
	circ.rendCookie = append([]byte(nil), cookie...)
	circ.mu.Unlock()
	if existing, ok := h.rendByCookie[key]; ok && existing.circ != nil && existing.circ.CircuitID != circ.CircuitID {
		circ.mu.Lock()
		circ.rendCookie = nil
		circ.mu.Unlock()
		return fmt.Errorf("rendezvous cookie already in use")
	}
	if len(h.rendByCookie) >= maxUnjoinedRend {
		circ.mu.Lock()
		circ.rendCookie = nil
		circ.mu.Unlock()
		return fmt.Errorf("too many unjoined rendezvous circuits")
	}
	h.rendByCookie[key] = &hsRoleSlot{circ: circ, conn: conn, created: h.now()}
	return nil
}

func (h *ForwardingHandler) handleRendezvous1(circ *ServerCircuit, clientConn net.Conn, payload []byte) error {
	if circ == nil {
		return fmt.Errorf("nil circuit")
	}
	if err := h.rejectIfExtended(circ, clientConn, "RENDEZVOUS1"); err != nil {
		return err
	}
	h.reapExpiredRend()
	if len(payload) < rendCookieLen {
		return h.destroyHSCircuit(circ, clientConn, "RENDEZVOUS1 cookie too short")
	}
	cookie := payload[:rendCookieLen]
	handshake := append([]byte(nil), payload[rendCookieLen:]...)
	key := hex.EncodeToString(cookie)
	// cookie 一次性取出：并发 RENDEZVOUS1 不能各发一格 RENDEZVOUS2。
	h.hsMu.Lock()
	slot := h.rendByCookie[key]
	if slot != nil {
		delete(h.rendByCookie, key)
	}
	h.hsMu.Unlock()
	if slot == nil || slot.circ == nil || slot.conn == nil {
		return h.destroyHSCircuit(circ, clientConn, "RENDEZVOUS1 cookie not recognized")
	}
	if slot.circ.CircuitID == circ.CircuitID {
		return h.destroyHSCircuit(circ, clientConn, "RENDEZVOUS1 on rendezvous circuit")
	}
	circ.mu.RLock()
	occupied := circ.joinedCirc != nil || len(circ.introAuth) > 0 || len(circ.rendCookie) > 0
	circ.mu.RUnlock()
	if occupied {
		h.restoreRend(key, slot)
		return h.destroyHSCircuit(circ, clientConn, "RENDEZVOUS1 on occupied circuit")
	}
	if err := sendRelayToClient(slot.circ, slot.conn, 0, cell.RelayRendezvous2, handshake); err != nil {
		h.restoreRend(key, slot)
		return h.destroyHSCircuit(circ, clientConn, "RENDEZVOUS2 send failed")
	}
	joinHSCircuits(circ, clientConn, slot.circ, slot.conn)
	h.addHSStat(func(s *HSRelayStats) { s.RendJoined++ })
	return nil
}

func (h *ForwardingHandler) reapExpiredRend() {
	if h == nil {
		return
	}
	now := h.now()
	h.hsMu.Lock()
	var dead []*hsRoleSlot
	for key, slot := range h.rendByCookie {
		if slot == nil || now.Sub(slot.created) < unjoinedRendTTL {
			continue
		}
		delete(h.rendByCookie, key)
		dead = append(dead, slot)
		h.hsStats.RendExpired++
	}
	h.hsMu.Unlock()
	for _, slot := range dead {
		if slot.circ == nil {
			continue
		}
		h.logger.Info("unjoined rendezvous expired", "circuit_id", slot.circ.CircuitID)
		_ = h.closeHSCircuit(slot.circ, slot.conn, "unjoined rendezvous expired", cell.DestroyReasonTimeout)
	}
}

func (h *ForwardingHandler) restoreRend(key string, slot *hsRoleSlot) {
	if h == nil || slot == nil || key == "" {
		return
	}
	h.hsMu.Lock()
	if h.rendByCookie[key] == nil {
		h.rendByCookie[key] = slot
	}
	h.hsMu.Unlock()
}

func joinHSCircuits(a *ServerCircuit, aConn net.Conn, b *ServerCircuit, bConn net.Conn) {
	if a == nil || b == nil {
		return
	}
	a.mu.Lock()
	a.joinedCirc = b
	a.joinedConn = bConn
	a.mu.Unlock()
	b.mu.Lock()
	b.joinedCirc = a
	b.joinedConn = aConn
	b.mu.Unlock()
}

func (h *ForwardingHandler) forgetHS(circ *ServerCircuit) {
	if h == nil || circ == nil {
		return
	}
	circ.mu.Lock()
	auth := append([]byte(nil), circ.introAuth...)
	cookie := append([]byte(nil), circ.rendCookie...)
	circ.mu.Unlock()
	h.hsMu.Lock()
	if len(auth) == ed25519AuthKeyLen {
		delete(h.introByAuth, hex.EncodeToString(auth))
	}
	if len(cookie) == rendCookieLen {
		delete(h.rendByCookie, hex.EncodeToString(cookie))
	}
	h.hsMu.Unlock()

	circ.mu.Lock()
	peer := circ.joinedCirc
	peerConn := circ.joinedConn
	circ.joinedCirc = nil
	circ.joinedConn = nil
	circ.mu.Unlock()
	if peer == nil {
		return
	}
	peer.mu.Lock()
	peer.joinedCirc = nil
	peer.joinedConn = nil
	peer.mu.Unlock()
	if peerConn != nil && h.circuits != nil {
		_ = h.circuits.sendDestroyCell(peerConn, peer.CircuitID, cell.DestroyReasonDestroyed)
	}
	if h.circuits != nil {
		h.circuits.CloseCircuit(peer.CircuitID)
	}
}
