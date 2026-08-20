package relay

import (
	"fmt"
	"net"

	"github.com/opd-ai/go-tor/pkg/cell"
)

const rendCookieLen = 20

// handleEstablishRendezvous 接受 ESTABLISH_RENDEZVOUS cookie 并回 RENDEZVOUS_ESTABLISHED。
// 对照 rend-spec-v3 §3.3；未宣告 HSRend=*。本切片不处理 RENDEZVOUS1。
func (h *ForwardingHandler) handleEstablishRendezvous(circ *ServerCircuit, clientConn net.Conn, payload []byte) error {
	if circ == nil {
		return fmt.Errorf("nil circuit")
	}
	if len(payload) < rendCookieLen {
		h.logger.Warn("ESTABLISH_RENDEZVOUS cookie too short", "circuit_id", circ.CircuitID, "len", len(payload))
		return h.destroyHSCircuit(circ, clientConn, fmt.Sprintf("rendezvous cookie length %d", len(payload)))
	}
	cookie := append([]byte(nil), payload[:rendCookieLen]...)
	circ.mu.Lock()
	if len(circ.rendCookie) > 0 {
		circ.mu.Unlock()
		h.logger.Warn("ESTABLISH_RENDEZVOUS on circuit that already has a cookie", "circuit_id", circ.CircuitID)
		return h.destroyHSCircuit(circ, clientConn, "rendezvous already established")
	}
	circ.rendCookie = cookie
	circ.mu.Unlock()
	return sendRelayToClient(circ, clientConn, 0, cell.RelayRendezvousEstablished, nil)
}
