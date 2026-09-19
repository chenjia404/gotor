package relay

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"time"

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

func (h *ForwardingHandler) now() time.Time {
	if h != nil && h.nowFn != nil {
		return h.nowFn()
	}
	return time.Now()
}

// SetIntroDoSParams 注入共识 HiddenServiceEnableIntroDoS*（无 ESTABLISH_INTRO 扩展时用）。
func (h *ForwardingHandler) SetIntroDoSParams(p onion.IntroDoSParams) {
	if h == nil {
		return
	}
	h.hsMu.Lock()
	h.introDoSCons = p
	h.hsMu.Unlock()
}

type introDoSBucket struct {
	enabled bool
	rate    float64
	burst   float64
	tokens  float64
	last    time.Time
}

func newIntroDoSBucket(p onion.IntroDoSParams, now time.Time) *introDoSBucket {
	ok, rate, burst := p.Effective()
	if !ok {
		return nil
	}
	return &introDoSBucket{
		enabled: true,
		rate:    float64(rate),
		burst:   float64(burst),
		tokens:  float64(burst),
		last:    now,
	}
}

func (s *hsRoleSlot) allowIntro2(now time.Time) bool {
	if s == nil || s.introDoS == nil || !s.introDoS.enabled {
		return true
	}
	b := s.introDoS
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// handleEstablishIntro 校验 ESTABLISH_INTRO 并回 INTRO_ESTABLISHED。
// 对照 rend-spec-v3 §3.1.1；未宣告 HSIntro=*。
func (h *ForwardingHandler) handleEstablishIntro(circ *ServerCircuit, clientConn net.Conn, payload []byte) error {
	if circ == nil {
		return fmt.Errorf("nil circuit")
	}
	if err := h.rejectIfExtended(circ, clientConn, "ESTABLISH_INTRO"); err != nil {
		return err
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
	ext := onion.ParseEstablishIntroDoSExtension(payload)
	if err := h.registerIntro(circ, clientConn, auth, ext); err != nil {
		return h.destroyHSCircuit(circ, clientConn, err.Error())
	}
	h.addHSStat(func(s *HSRelayStats) { s.EstIntro++ })
	// INTRO_ESTABLISHED 可为空扩展；StreamID=0。
	return sendRelayToClient(circ, clientConn, 0, cell.RelayIntroEstablished, nil)
}

func (h *ForwardingHandler) registerIntro(circ *ServerCircuit, conn net.Conn, auth []byte, ext onion.IntroDoSExtension) error {
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
	dos := onion.ResolveIntroDoS(ext, h.introDoSCons)
	h.introByAuth[key] = &hsRoleSlot{circ: circ, conn: conn, introDoS: newIntroDoSBucket(dos, h.now())}
	return nil
}

func (h *ForwardingHandler) handleIntroduce1(circ *ServerCircuit, clientConn net.Conn, payload []byte) error {
	if circ == nil {
		return fmt.Errorf("nil circuit")
	}
	if err := h.rejectIfExtended(circ, clientConn, "INTRODUCE1"); err != nil {
		return err
	}
	auth, ok := parseIntroduce1AuthKey(payload)
	if !ok {
		return sendRelayToClient(circ, clientConn, 0, cell.RelayIntroduceAck, introAckPayload(introAckBadFormat))
	}
	h.hsMu.Lock()
	slot := h.introByAuth[hex.EncodeToString(auth)]
	limited := slot != nil && !slot.allowIntro2(h.now())
	h.hsMu.Unlock()
	if slot == nil || slot.circ == nil || slot.conn == nil {
		return sendRelayToClient(circ, clientConn, 0, cell.RelayIntroduceAck, introAckPayload(introAckNotRecognized))
	}
	if limited {
		// C Tor hs_dos_can_send_intro2 失败时发 UNKNOWN_ID（NOT_RECOGNIZED），不转发 INTRODUCE2。
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

func (h *ForwardingHandler) rejectIfExtended(circ *ServerCircuit, clientConn net.Conn, cmd string) error {
	if circ == nil {
		return fmt.Errorf("nil circuit")
	}
	circ.mu.RLock()
	extended := circ.didExtend
	circ.mu.RUnlock()
	if !extended {
		return nil
	}
	// C Tor rend_mid / hs intro：n_chan 已存在则不是末端跳，DESTROY。
	return h.destroyHSCircuit(circ, clientConn, cmd+" on extended circuit")
}

func (h *ForwardingHandler) destroyHSCircuit(circ *ServerCircuit, clientConn net.Conn, reason string) error {
	return h.closeHSCircuit(circ, clientConn, reason, cell.DestroyReasonProtocol)
}

func (h *ForwardingHandler) closeHSCircuit(circ *ServerCircuit, clientConn net.Conn, reason string, dest byte) error {
	if circ == nil {
		return fmt.Errorf("%s", reason)
	}
	if clientConn != nil && h.circuits != nil {
		_ = h.circuits.sendDestroyCell(clientConn, circ.CircuitID, dest)
	}
	if h.circuits != nil {
		h.circuits.CloseCircuit(circ.CircuitID)
	}
	return fmt.Errorf("%s", reason)
}

func (h *ForwardingHandler) addHSStat(fn func(*HSRelayStats)) {
	if h == nil || fn == nil {
		return
	}
	h.hsMu.Lock()
	fn(&h.hsStats)
	h.hsMu.Unlock()
}

// HSRelayStats 是中继侧 intro/rend 内存计数（不写 extra-info hidserv-*）。
type HSRelayStats struct {
	EstIntro    uint64
	EstRend     uint64
	RendJoined  uint64
	RendExpired uint64
}

// HSStats 返回 intro/rend 计数快照。未宣告 HS*。
func (h *ForwardingHandler) HSStats() HSRelayStats {
	if h == nil {
		return HSRelayStats{}
	}
	h.hsMu.Lock()
	defer h.hsMu.Unlock()
	return h.hsStats
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
