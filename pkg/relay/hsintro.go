package relay

import (
	"fmt"
	"net"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/onion"
)

// handleEstablishIntro 校验 ESTABLISH_INTRO 并回 INTRO_ESTABLISHED。
// 对照 rend-spec-v3 §3.1.1；未宣告 HSIntro=*。
func (h *ForwardingHandler) handleEstablishIntro(circ *ServerCircuit, clientConn net.Conn, payload []byte) error {
	if circ == nil {
		return fmt.Errorf("nil circuit")
	}
	circ.mu.Lock()
	nonce := append([]byte(nil), circ.circNonce...)
	already := len(circ.introAuth) > 0
	circ.mu.Unlock()
	if already {
		return h.destroyHSCircuit(circ, clientConn, "intro already established")
	}
	if len(nonce) != 20 {
		h.logger.Warn("ESTABLISH_INTRO without circ_nonce", "circuit_id", circ.CircuitID)
		return h.destroyHSCircuit(circ, clientConn, "missing rend_circ_nonce")
	}
	if err := onion.VerifyEstablishIntroPayload(payload, nonce); err != nil {
		h.logger.Warn("ESTABLISH_INTRO verify failed", "circuit_id", circ.CircuitID, "error", err)
		return h.destroyHSCircuit(circ, clientConn, err.Error())
	}
	if len(payload) < 35 {
		return h.destroyHSCircuit(circ, clientConn, "ESTABLISH_INTRO too short")
	}
	auth := append([]byte(nil), payload[3:35]...)
	circ.mu.Lock()
	if len(circ.introAuth) > 0 {
		circ.mu.Unlock()
		return h.destroyHSCircuit(circ, clientConn, "intro already established")
	}
	circ.introAuth = auth
	circ.mu.Unlock()
	// INTRO_ESTABLISHED 可为空扩展；StreamID=0。
	return sendRelayToClient(circ, clientConn, 0, cell.RelayIntroEstablished, nil)
}

func (h *ForwardingHandler) rejectHSControlStream(circ *ServerCircuit, clientConn net.Conn, cmd string) error {
	h.logger.Warn("HS control cell must use StreamID=0", "circuit_id", circ.CircuitID, "cmd", cmd)
	return h.destroyHSCircuit(circ, clientConn, cmd+" stream_id != 0")
}

func (h *ForwardingHandler) destroyHSCircuit(circ *ServerCircuit, clientConn net.Conn, reason string) error {
	if circ == nil {
		return fmt.Errorf("%s", reason)
	}
	if clientConn != nil {
		_ = h.circuits.sendDestroyCell(clientConn, circ.CircuitID, cell.DestroyReasonProtocol)
	}
	h.circuits.CloseCircuit(circ.CircuitID)
	return fmt.Errorf("%s", reason)
}

func sendRelayToClient(circ *ServerCircuit, clientConn net.Conn, streamID uint16, cmd byte, data []byte) error {
	if circ == nil || clientConn == nil || circ.crypto == nil {
		return fmt.Errorf("cannot send relay reply")
	}
	rc, err := cell.NewRelayCell(streamID, cmd, data)
	if err != nil {
		return err
	}
	circ.mu.Lock()
	defer circ.mu.Unlock()
	enc, err := circ.crypto.originateRelay(rc)
	if err != nil {
		return err
	}
	c := &cell.Cell{CircID: circ.CircuitID, Command: cell.CmdRelay, Payload: enc}
	return c.Encode(clientConn)
}
