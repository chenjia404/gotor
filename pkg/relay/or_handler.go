package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/logger"
	"github.com/opd-ai/go-tor/pkg/security"
)

// AUTH_CHALLENGE 方法（tor-spec negotiating-channels）。
const (
	authMethodRSASHA256TLSSecret   uint16 = 1 // 已过时，仍宣告以免旧发起方无法选方法
	authMethodEd25519SHA256RFC5705 uint16 = 3 // LinkAuth=3
	authChallengeLen                      = 32
)

// ServerORConnection holds server-side OR connection state
// This extends the basic ORConnection with protocol state
type ServerORConnection struct {
	conn              net.Conn
	remoteAddr        string
	negotiatedVersion int
	authenticated     bool
	circIDLen         int // VERSIONS 后按协商版本：v≥4 为 4，否则为 2
}

// LinkProtocolHandler handles the server-side link protocol handshake
// Following tor-spec.txt §1-2 (server-side)
type LinkProtocolHandler struct {
	keys      *RelayKeys
	logger    *logger.Logger
	circIDLen int // 协商前为 2（CIRCID_LEN(v_in=0)=2）；VERSIONS 后再切 4
}

// NewLinkProtocolHandler creates a new link protocol handler
func NewLinkProtocolHandler(keys *RelayKeys, log *logger.Logger) *LinkProtocolHandler {
	if log == nil {
		log = logger.NewDefault()
	}
	return &LinkProtocolHandler{
		keys:      keys,
		logger:    log,
		circIDLen: 2, // VERSIONS 按 v=0，必须用 2 字节 CircID
	}
}

// HandleConnection 做应答方 link 握手（tor-spec negotiating-channels）。
//
// 顺序：收 VERSIONS（CircID=2）→ 发 VERSIONS（仍 2）→ 协商后切 4 字节
// → 发 CERTS → 发 AUTH_CHALLENGE → 发 NETINFO → 收发起方 NETINFO
// （权威作为中继发起时还会先发 CERTS+AUTHENTICATE，读时跳过）。
func (h *LinkProtocolHandler) HandleConnection(ctx context.Context, conn net.Conn) (*ServerORConnection, error) {
	orConn := &ServerORConnection{
		conn:       conn,
		remoteAddr: conn.RemoteAddr().String(),
		circIDLen:  2,
	}

	// 协商前一律 2 字节 CircID。权威发 00 00|07|…（VERSIONS）；
	// 若按 4 字节解析会把长度低位 0x06 读成 CREATED_FAST，握手失败、无法进共识。
	h.setCircIDLen(2)

	// Step 1: Receive VERSIONS from client
	clientVersions, err := h.receiveVersions(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive client VERSIONS: %w", err)
	}

	// Step 2: Negotiate protocol version
	version := h.selectVersion(clientVersions)
	if version == 0 {
		return nil, fmt.Errorf("no compatible protocol version")
	}
	orConn.negotiatedVersion = version
	h.logger.Info("Negotiated protocol version", "version", version, "client_versions", clientVersions)

	// Send VERSIONS response（仍按 v=0 / 2 字节 CircID）
	if err := h.sendVersions(conn); err != nil {
		return nil, fmt.Errorf("failed to send VERSIONS: %w", err)
	}

	// VERSIONS 之后按协商版本切换 CircID 宽度（与出站 protocol.Handshake 对称）
	if version >= 4 {
		h.setCircIDLen(4)
	} else {
		h.setCircIDLen(2)
	}
	orConn.circIDLen = h.circIDWidth()

	if err := h.sendCerts(conn); err != nil {
		return nil, fmt.Errorf("failed to send CERTS: %w", err)
	}

	if err := h.sendAuthChallenge(conn); err != nil {
		return nil, fmt.Errorf("failed to send AUTH_CHALLENGE: %w", err)
	}

	if err := h.sendNetinfo(conn); err != nil {
		return nil, fmt.Errorf("failed to send NETINFO: %w", err)
	}

	if err := h.receiveNetinfo(ctx, conn); err != nil {
		return nil, fmt.Errorf("failed to receive client NETINFO: %w", err)
	}

	h.logger.Info("Link protocol handshake complete", "version", version, "remote", conn.RemoteAddr())
	return orConn, nil
}

// receiveVersions receives and parses a VERSIONS cell from the client
func (h *LinkProtocolHandler) receiveVersions(ctx context.Context, conn net.Conn) ([]int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Read cell with context
	cellData, err := h.readCellWithContext(ctx, conn)
	if err != nil {
		return nil, err
	}

	if cellData.Command != cell.CmdVersions {
		return nil, fmt.Errorf("expected VERSIONS cell, got %s", cellData.Command)
	}

	// Parse versions from payload (2 bytes per version, big-endian)
	if len(cellData.Payload)%2 != 0 {
		return nil, fmt.Errorf("invalid VERSIONS payload length: %d", len(cellData.Payload))
	}

	var versions []int
	for i := 0; i < len(cellData.Payload); i += 2 {
		version := int(cellData.Payload[i])<<8 | int(cellData.Payload[i+1])
		versions = append(versions, version)
	}

	h.logger.Debug("Received VERSIONS cell", "versions", versions)
	return versions, nil
}

// selectVersion selects the highest mutually supported version
func (h *LinkProtocolHandler) selectVersion(clientVersions []int) int {
	// We support versions 3-5
	supportedVersions := []int{5, 4, 3}

	for _, supported := range supportedVersions {
		for _, client := range clientVersions {
			if client == supported {
				return supported
			}
		}
	}
	return 0
}

// sendVersions sends a VERSIONS cell to the client
func (h *LinkProtocolHandler) sendVersions(conn net.Conn) error {
	// Send versions 3, 4, 5
	versions := []uint16{3, 4, 5}
	payload := make([]byte, len(versions)*2)
	for i, v := range versions {
		binary.BigEndian.PutUint16(payload[i*2:], v)
	}

	versionsCell := cell.NewCell(0, cell.CmdVersions)
	versionsCell.Payload = payload

	h.logger.Debug("Sending VERSIONS cell", "versions", versions)
	return h.writeCell(conn, versionsCell)
}

func (h *LinkProtocolHandler) sendCerts(conn net.Conn) error {
	payload, err := h.buildCERTSPayload()
	if err != nil {
		return err
	}
	certsCell := cell.NewCell(0, cell.CmdCerts)
	certsCell.Payload = payload
	h.logger.Debug("Sending CERTS cell", "num_certs", int(payload[0]))
	return h.writeCell(conn, certsCell)
}

// sendAuthChallenge 发应答方 AUTH_CHALLENGE。权威作为中继发起时必须能选方法 3。
// 本轮只发挑战，不校验 AUTHENTICATE（清单 LinkAuth=3 另做）。
func (h *LinkProtocolHandler) sendAuthChallenge(conn net.Conn) error {
	challenge := make([]byte, authChallengeLen)
	if _, err := rand.Read(challenge); err != nil {
		return fmt.Errorf("generate AUTH_CHALLENGE: %w", err)
	}
	methods := []uint16{authMethodRSASHA256TLSSecret, authMethodEd25519SHA256RFC5705}
	payload := make([]byte, 0, authChallengeLen+2+2*len(methods))
	payload = append(payload, challenge...)
	nMethods := uint16(len(methods))
	payload = append(payload, byte(nMethods>>8), byte(nMethods))
	for _, m := range methods {
		payload = append(payload, byte(m>>8), byte(m))
	}

	ch := cell.NewCell(0, cell.CmdAuthChallenge)
	ch.Payload = payload
	h.logger.Debug("Sending AUTH_CHALLENGE cell", "methods", methods)
	return h.writeCell(conn, ch)
}

func (h *LinkProtocolHandler) sendNetinfo(conn net.Conn) error {
	var payload []byte

	now := time.Now()
	timestamp, err := security.SafeUnixToUint32(now)
	if err != nil {
		h.logger.Warn("Failed to convert timestamp, using 0", "error", err)
		timestamp = 0
	}
	payload = append(payload,
		byte(timestamp>>24),
		byte(timestamp>>16),
		byte(timestamp>>8),
		byte(timestamp))

	payload = append(payload, encodeLinkAddress(addrIP(conn.RemoteAddr()))...)

	var my [][]byte
	if ip := usableIP(addrIP(conn.LocalAddr())); ip != nil {
		my = append(my, encodeLinkAddress(ip))
	}
	payload = append(payload, byte(len(my))) // #nosec G115 — 至多 1 个
	for _, a := range my {
		payload = append(payload, a...)
	}

	netinfoCell := cell.NewCell(0, cell.CmdNetinfo)
	netinfoCell.Payload = payload
	h.logger.Debug("Sending NETINFO cell")
	return h.writeCell(conn, netinfoCell)
}

func addrIP(addr net.Addr) net.IP {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok || tcp == nil {
		return nil
	}
	return tcp.IP
}

func usableIP(ip net.IP) net.IP {
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
		return nil
	}
	return ip
}

func encodeLinkAddress(ip net.IP) []byte {
	if v4 := ip.To4(); v4 != nil {
		return append([]byte{0x04, 4}, v4...)
	}
	if v6 := ip.To16(); v6 != nil && ip.To4() == nil {
		return append([]byte{0x06, 16}, v6...)
	}
	return []byte{0x04, 4, 0, 0, 0, 0}
}

// receiveNetinfo 等到发起方 NETINFO。NETINFO 是握手结束标记。
// 客户端只发 NETINFO；权威作为中继发起时会先发 CERTS+AUTHENTICATE。
// VPADDING 在 VERSIONS 之后任意数量、任意位置都允许。
func (h *LinkProtocolHandler) receiveNetinfo(ctx context.Context, conn net.Conn) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	for {
		cellData, err := h.readCellWithContext(ctx, conn)
		if err != nil {
			return err
		}
		switch cellData.Command {
		case cell.CmdNetinfo:
			h.logger.Debug("Received NETINFO cell")
			return nil
		case cell.CmdPadding, cell.CmdVPadding, cell.CmdCerts, cell.CmdAuthenticate, cell.CmdAuthChallenge:
			h.logger.Debug("Skipping cell while waiting for NETINFO", "command", cellData.Command)
			continue
		default:
			return fmt.Errorf("expected NETINFO cell, got %s", cellData.Command)
		}
	}
}

func (h *LinkProtocolHandler) circIDWidth() int {
	if h.circIDLen == 4 {
		return 4
	}
	return 2
}

func (h *LinkProtocolHandler) setCircIDLen(n int) {
	if n == 2 || n == 4 {
		h.circIDLen = n
	}
}

func (s *ServerORConnection) circIDWidth() int {
	if s.circIDLen == 2 {
		return 2
	}
	return 4
}

// readCellWithContext 按当前 CircID 宽度读一个 cell，并支持 context 取消。
// 协商前必须传 2：权威 VERSIONS 为 00 00 07 …，按 4 字节会读成 CREATED_FAST。
func (h *LinkProtocolHandler) readCellWithContext(ctx context.Context, conn net.Conn) (*cell.Cell, error) {
	type readResult struct {
		c   *cell.Cell
		err error
	}
	resultCh := make(chan readResult, 1)
	circIDLen := h.circIDWidth()

	go func() {
		c, err := cell.DecodeCellLink(conn, circIDLen)
		resultCh <- readResult{c, err}
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("read cancelled: %w", ctx.Err())
	case result := <-resultCh:
		return result.c, result.err
	}
}

// writeCell 按当前 CircID 宽度写出。VERSIONS 必须 EncodeLink(..., 2)。
func (h *LinkProtocolHandler) writeCell(conn net.Conn, c *cell.Cell) error {
	var buf bytes.Buffer
	if err := c.EncodeLink(&buf, h.circIDWidth()); err != nil {
		return fmt.Errorf("failed to encode cell: %w", err)
	}

	_, err := conn.Write(buf.Bytes())
	return err
}

// ReceiveCell 按握手后的 CircID 宽度读 cell。
func (s *ServerORConnection) ReceiveCell(ctx context.Context) (*cell.Cell, error) {
	type readResult struct {
		c   *cell.Cell
		err error
	}
	resultCh := make(chan readResult, 1)
	circIDLen := s.circIDWidth()

	go func() {
		c, err := cell.DecodeCellLink(s.conn, circIDLen)
		resultCh <- readResult{c, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-resultCh:
		return result.c, result.err
	}
}
