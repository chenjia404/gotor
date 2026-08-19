// Package relay — 出口流：RELAY_BEGIN → 拨号 → CONNECTED/DATA/END。
package relay

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/logger"
)

// ExitStreamManager 管理出口 TCP 流。
type ExitStreamManager struct {
	policy  *ExitPolicy
	logger  *logger.Logger
	mu      sync.Mutex
	streams map[streamKey]*exitStream
}

type streamKey struct {
	circID   uint32
	streamID uint16
}

type exitStream struct {
	conn   net.Conn
	cancel context.CancelFunc
}

func NewExitStreamManager(policy *ExitPolicy, log *logger.Logger) *ExitStreamManager {
	if log == nil {
		log = logger.NewDefault()
	}
	return &ExitStreamManager{
		policy:  policy,
		logger:  log.Component("exit-stream"),
		streams: make(map[streamKey]*exitStream),
	}
}

// HandleBegin 处理已解密的 RELAY_BEGIN。
func (m *ExitStreamManager) HandleBegin(ctx context.Context, circ *ServerCircuit, clientConn net.Conn, streamID uint16, data []byte) error {
	addr, port, err := parseBeginAddr(data)
	if err != nil {
		return m.sendEnd(circ, clientConn, streamID, cell.EndReasonMisc)
	}
	target := net.JoinHostPort(addr, strconv.Itoa(int(port)))
	if err := m.policy.ValidateExitAttempt(cell.RelayBegin, target, port); err != nil {
		reason := cell.EndReasonExitPolicy
		if v, ok := err.(*ExitPolicyViolation); ok {
			reason = v.Reason
		}
		return m.sendEnd(circ, clientConn, streamID, reason)
	}

	d := net.Dialer{Timeout: 15 * time.Second}
	c, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		m.logger.Debug("exit dial failed", "target", target, "error", err)
		return m.sendEnd(circ, clientConn, streamID, cell.EndReasonConnRefused)
	}

	remoteIP := net.ParseIP(addr)
	if host, _, e := net.SplitHostPort(c.RemoteAddr().String()); e == nil {
		remoteIP = net.ParseIP(host)
	}
	payload, err := cell.FormatConnectedPayload(remoteIP, 3600)
	if err != nil {
		_ = c.Close()
		return m.sendEnd(circ, clientConn, streamID, cell.EndReasonInternal)
	}
	if err := m.sendRelay(circ, clientConn, streamID, cell.RelayConnected, payload); err != nil {
		_ = c.Close()
		return err
	}

	sctx, cancel := context.WithCancel(ctx)
	key := streamKey{circ.CircuitID, streamID}
	m.mu.Lock()
	m.streams[key] = &exitStream{conn: c, cancel: cancel}
	m.mu.Unlock()

	go m.pumpRemoteToClient(sctx, circ, clientConn, streamID, c)
	return nil
}

// HandleData 将客户端 DATA 写入远端。
func (m *ExitStreamManager) HandleData(circID uint32, streamID uint16, data []byte) error {
	m.mu.Lock()
	es := m.streams[streamKey{circID, streamID}]
	m.mu.Unlock()
	if es == nil || es.conn == nil {
		return fmt.Errorf("unknown exit stream %d/%d", circID, streamID)
	}
	_, err := es.conn.Write(data)
	return err
}

// HandleEnd 关闭出口流。
func (m *ExitStreamManager) HandleEnd(circID uint32, streamID uint16) {
	m.mu.Lock()
	es := m.streams[streamKey{circID, streamID}]
	delete(m.streams, streamKey{circID, streamID})
	m.mu.Unlock()
	if es != nil {
		if es.cancel != nil {
			es.cancel()
		}
		if es.conn != nil {
			_ = es.conn.Close()
		}
	}
}

func (m *ExitStreamManager) pumpRemoteToClient(ctx context.Context, circ *ServerCircuit, clientConn net.Conn, streamID uint16, remote net.Conn) {
	defer m.HandleEnd(circ.CircuitID, streamID)
	buf := make([]byte, 498)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = remote.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := remote.Read(buf)
		if n > 0 {
			if err := m.sendRelay(circ, clientConn, streamID, cell.RelayData, buf[:n]); err != nil {
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				m.logger.Debug("exit remote read", "error", err)
			}
			_ = m.sendEnd(circ, clientConn, streamID, cell.EndReasonDone)
			return
		}
	}
}

func (m *ExitStreamManager) sendEnd(circ *ServerCircuit, clientConn net.Conn, streamID uint16, reason byte) error {
	return m.sendRelay(circ, clientConn, streamID, cell.RelayEnd, []byte{reason})
}

func (m *ExitStreamManager) sendRelay(circ *ServerCircuit, clientConn net.Conn, streamID uint16, cmd byte, data []byte) error {
	rc, err := cell.NewRelayCell(streamID, cmd, data)
	if err != nil {
		return err
	}
	plain, err := rc.Encode()
	if err != nil {
		return err
	}
	if len(plain) != 509 {
		// pad / truncate to 509
		out := make([]byte, 509)
		copy(out, plain)
		plain = out
	}
	enc, err := circ.crypto.encryptOutbound(plain)
	if err != nil {
		return err
	}
	c := &cell.Cell{CircID: circ.CircuitID, Command: cell.CmdRelay, Payload: enc}
	return c.Encode(clientConn)
}

func parseBeginAddr(data []byte) (host string, port uint16, err error) {
	s := string(data)
	if i := strings.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, fmt.Errorf("empty BEGIN")
	}
	// flags after space ignored
	if i := strings.IndexByte(s, ' '); i >= 0 {
		s = s[:i]
	}
	h, pstr, err := net.SplitHostPort(s)
	if err != nil {
		// maybe host only with default? require port
		return "", 0, err
	}
	p, err := strconv.Atoi(pstr)
	if err != nil || p < 1 || p > 65535 {
		return "", 0, fmt.Errorf("bad port")
	}
	return h, uint16(p), nil
}
