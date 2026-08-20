package relay

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/onion"
)

const (
	maxIntroduce1Len        = 490
	introAckSuccess         = 0
	introAckNotRecognized   = 1
	introAckBadFormat       = 2
	introAckCantRelay       = 3
	introduce1LegacyKeyLen  = 20
	introduce1AuthKeyTypeV3 = 0x02
	ed25519AuthKeyLen       = 32
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
	if err := h.registerIntro(circ, clientConn, auth); err != nil {
		return h.destroyHSCircuit(circ, clientConn, err.Error())
	}
	// INTRO_ESTABLISHED 可为空扩展；StreamID=0。
	return sendRelayToClient(circ, clientConn, 0, cell.RelayIntroEstablished, nil)
}

func (h *ForwardingHandler) registerIntro(circ *ServerCircuit, conn net.Conn, auth []byte) error {
	if circ == nil || len(auth) != ed25519AuthKeyLen {
		return fmt.Errorf("invalid intro auth")
	}
	key := hex.EncodeToString(auth)
	h.hsMu.Lock()
	defer h.hsMu.Unlock()
	circ.mu.Lock()
	alreadyRend := len(circ.rendCookie) > 0
	circ.mu.Unlock()
	if alreadyRend {
		return fmt.Errorf("circuit already rendezvous")
	}
	if existing, ok := h.introByAuth[key]; ok && existing.circ != nil && existing.circ.CircuitID != circ.CircuitID {
		return fmt.Errorf("intro auth already in use")
	}
	circ.mu.Lock()
	if len(circ.introAuth) > 0 {
		circ.mu.Unlock()
		return fmt.Errorf("intro already established")
	}
	circ.introAuth = append([]byte(nil), auth...)
	circ.mu.Unlock()
	h.introByAuth[key] = &hsRoleSlot{circ: circ, conn: conn}
	return nil
}

func (h *ForwardingHandler) handleIntroduce1(circ *ServerCircuit, clientConn net.Conn, payload []byte) error {
	if circ == nil {
		return fmt.Errorf("nil circuit")
	}
	auth, ok := parseIntroduce1AuthKey(payload)
	if !ok {
		return sendRelayToClient(circ, clientConn, 0, cell.RelayIntroduceAck, introAckPayload(introAckBadFormat))
	}
	h.hsMu.Lock()
	slot := h.introByAuth[hex.EncodeToString(auth)]
	h.hsMu.Unlock()
	if slot == nil || slot.circ == nil || slot.conn == nil {
		return sendRelayToClient(circ, clientConn, 0, cell.RelayIntroduceAck, introAckPayload(introAckNotRecognized))
	}
	if err := sendRelayToClient(slot.circ, slot.conn, 0, cell.RelayIntroduce2, payload); err != nil {
		h.logger.Warn("INTRODUCE2 relay failed", "circuit_id", slot.circ.CircuitID, "error", err)
		return sendRelayToClient(circ, clientConn, 0, cell.RelayIntroduceAck, introAckPayload(introAckCantRelay))
	}
	return sendRelayToClient(circ, clientConn, 0, cell.RelayIntroduceAck, introAckPayload(introAckSuccess))
}

func parseIntroduce1AuthKey(p []byte) ([]byte, bool) {
	if len(p) < introduce1LegacyKeyLen+3+ed25519AuthKeyLen+1 || len(p) > maxIntroduce1Len {
		return nil, false
	}
	for i := 0; i < introduce1LegacyKeyLen; i++ {
		if p[i] != 0 {
			return nil, false
		}
	}
	if p[introduce1LegacyKeyLen] != introduce1AuthKeyTypeV3 {
		return nil, false
	}
	alen := int(binary.BigEndian.Uint16(p[introduce1LegacyKeyLen+1 : introduce1LegacyKeyLen+3]))
	off := introduce1LegacyKeyLen + 3
	if alen != ed25519AuthKeyLen || off+alen >= len(p) {
		return nil, false
	}
	auth := p[off : off+alen]
	off += alen
	nExt := int(p[off])
	off++
	for i := 0; i < nExt; i++ {
		if off+2 > len(p) {
			return nil, false
		}
		extLen := int(p[off+1])
		off += 2 + extLen
		if off > len(p) {
			return nil, false
		}
	}
	return auth, true
}

func introAckPayload(status uint16) []byte {
	out := make([]byte, 3)
	binary.BigEndian.PutUint16(out[:2], status)
	return out
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
