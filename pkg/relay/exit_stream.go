// Package relay — 出口流：RELAY_BEGIN → 解析/策略 → 拨号 → CONNECTED/DATA/END。
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

const (
	exitCircWindowInit     = 1000
	exitStreamWindowInit   = 500
	exitCircSendmeInc      = 100
	exitStreamSendmeInc    = 50
	exitMaxStreamsPerCirc  = 100
	exitMaxCircOutWindow   = 2000
	exitMaxStreamOutWindow = 1000
)

// ExitStreamManager 管理出口 TCP 流。
type ExitStreamManager struct {
	policy  *ExitPolicy
	logger  *logger.Logger
	mu      sync.Mutex
	streams map[streamKey]*exitStream
	// 每电路：出向窗、入向计数、流数量
	circOutWindow map[uint32]int
	circInCount   map[uint32]int
	circStreams   map[uint32]int
	// 最近一次入向 digest（20 字节），供电路级 SENDME v1
	lastFwdDigest map[uint32][]byte
}

type streamKey struct {
	circID   uint32
	streamID uint16
}

type exitStream struct {
	conn          net.Conn
	cancel        context.CancelFunc
	packageWindow int
	deliverCount  int
}

func NewExitStreamManager(policy *ExitPolicy, log *logger.Logger) *ExitStreamManager {
	if log == nil {
		log = logger.NewDefault()
	}
	return &ExitStreamManager{
		policy:        policy,
		logger:        log.Component("exit-stream"),
		streams:       make(map[streamKey]*exitStream),
		circOutWindow: make(map[uint32]int),
		circInCount:   make(map[uint32]int),
		circStreams:   make(map[uint32]int),
		lastFwdDigest: make(map[uint32][]byte),
	}
}

// NoteFwdDigest 在成功解密入向 cell 后记录滚动摘要（供电路 SENDME v1）。
func (m *ExitStreamManager) NoteFwdDigest(circID uint32, digest []byte) {
	if len(digest) != 20 {
		return
	}
	m.mu.Lock()
	m.lastFwdDigest[circID] = append([]byte(nil), digest...)
	m.mu.Unlock()
}

// CloseCircuit 关闭该电路全部出口流。
func (m *ExitStreamManager) CloseCircuit(circID uint32) {
	m.mu.Lock()
	var toClose []*exitStream
	for k, es := range m.streams {
		if k.circID == circID {
			toClose = append(toClose, es)
			delete(m.streams, k)
		}
	}
	delete(m.circOutWindow, circID)
	delete(m.circInCount, circID)
	delete(m.circStreams, circID)
	delete(m.lastFwdDigest, circID)
	m.mu.Unlock()
	for _, es := range toClose {
		m.teardown(es)
	}
}

// CloseAll 关闭全部出口流。
func (m *ExitStreamManager) CloseAll() {
	m.mu.Lock()
	all := make([]*exitStream, 0, len(m.streams))
	for _, es := range m.streams {
		all = append(all, es)
	}
	m.streams = make(map[streamKey]*exitStream)
	m.circOutWindow = make(map[uint32]int)
	m.circInCount = make(map[uint32]int)
	m.circStreams = make(map[uint32]int)
	m.lastFwdDigest = make(map[uint32][]byte)
	m.mu.Unlock()
	for _, es := range all {
		m.teardown(es)
	}
}

func (m *ExitStreamManager) teardown(es *exitStream) {
	if es == nil {
		return
	}
	if es.cancel != nil {
		es.cancel()
	}
	if es.conn != nil {
		_ = es.conn.Close()
	}
}

// HandleBegin 先解析 DNS、对候选 IP 检策略，再只拨允许的地址。
func (m *ExitStreamManager) HandleBegin(ctx context.Context, circ *ServerCircuit, clientConn net.Conn, streamID uint16, data []byte) error {
	addr, port, err := parseBeginAddr(data)
	if err != nil {
		return m.sendEnd(circ, clientConn, streamID, cell.EndReasonMisc)
	}

	key := streamKey{circ.CircuitID, streamID}
	m.mu.Lock()
	if old, exists := m.streams[key]; exists {
		delete(m.streams, key)
		m.circStreams[circ.CircuitID]--
		m.mu.Unlock()
		m.teardown(old)
		m.mu.Lock()
	}
	if m.circStreams[circ.CircuitID] >= exitMaxStreamsPerCirc {
		m.mu.Unlock()
		return m.sendEnd(circ, clientConn, streamID, cell.EndReasonResourceLimit)
	}
	m.mu.Unlock()

	ips, err := resolveBeginIPs(ctx, addr)
	if err != nil || len(ips) == 0 {
		return m.sendEnd(circ, clientConn, streamID, cell.EndReasonResolveFailed)
	}

	var dialIP net.IP
	for _, ip := range ips {
		ok, _ := m.policy.CheckExitAllowed(ip.String(), port)
		if ok {
			dialIP = ip
			break
		}
	}
	if dialIP == nil {
		return m.sendEnd(circ, clientConn, streamID, cell.EndReasonExitPolicy)
	}

	target := net.JoinHostPort(dialIP.String(), strconv.Itoa(int(port)))
	d := net.Dialer{Timeout: 15 * time.Second}
	c, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		m.logger.Debug("exit dial failed", "target", target, "error", err)
		return m.sendEnd(circ, clientConn, streamID, cell.EndReasonConnRefused)
	}

	// 再确认实际 Local/Remote（双重保险）
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		_ = c.Close()
		return m.sendEnd(circ, clientConn, streamID, cell.EndReasonInternal)
	}
	remoteIP := net.ParseIP(host)
	if remoteIP == nil {
		_ = c.Close()
		return m.sendEnd(circ, clientConn, streamID, cell.EndReasonInternal)
	}
	if ok, reason := m.policy.CheckExitAllowed(remoteIP.String(), port); !ok {
		_ = c.Close()
		return m.sendEnd(circ, clientConn, streamID, reason)
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
	m.mu.Lock()
	m.streams[key] = &exitStream{
		conn:          c,
		cancel:        cancel,
		packageWindow: exitStreamWindowInit,
	}
	m.circStreams[circ.CircuitID]++
	if _, ok := m.circOutWindow[circ.CircuitID]; !ok {
		m.circOutWindow[circ.CircuitID] = exitCircWindowInit
	}
	m.mu.Unlock()

	go m.pumpRemoteToClient(sctx, circ, clientConn, streamID, c)
	return nil
}

func resolveBeginIPs(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out, nil
}

// HandleData 将客户端 DATA 写入远端，并维护入向 SENDME。
func (m *ExitStreamManager) HandleData(circ *ServerCircuit, clientConn net.Conn, streamID uint16, data []byte) error {
	m.mu.Lock()
	es := m.streams[streamKey{circ.CircuitID, streamID}]
	m.mu.Unlock()
	if es == nil || es.conn == nil {
		return fmt.Errorf("unknown exit stream %d/%d", circ.CircuitID, streamID)
	}
	if _, err := es.conn.Write(data); err != nil {
		return err
	}

	sendCirc, sendStream := false, false
	var circDigest []byte
	m.mu.Lock()
	m.circInCount[circ.CircuitID]++
	if m.circInCount[circ.CircuitID] >= exitCircSendmeInc {
		m.circInCount[circ.CircuitID] = 0
		sendCirc = true
		circDigest = append([]byte(nil), m.lastFwdDigest[circ.CircuitID]...)
	}
	es.deliverCount++
	if es.deliverCount >= exitStreamSendmeInc {
		es.deliverCount = 0
		sendStream = true
	}
	m.mu.Unlock()

	if sendCirc && len(circDigest) == 20 {
		payload, err := cell.EncodeSendmeV1(circDigest)
		if err == nil {
			_ = m.sendRelay(circ, clientConn, 0, cell.RelaySendme, payload)
		}
	}
	if sendStream {
		// 流级 SENDME 体为空
		_ = m.sendRelay(circ, clientConn, streamID, cell.RelaySendme, nil)
	}
	return nil
}

// HandleSendme 客户端 SENDME：恢复出向窗口。
func (m *ExitStreamManager) HandleSendme(circID uint32, streamID uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if streamID == 0 {
		m.circOutWindow[circID] += exitCircSendmeInc
		if m.circOutWindow[circID] > exitMaxCircOutWindow {
			m.circOutWindow[circID] = exitMaxCircOutWindow
		}
		return
	}
	if es := m.streams[streamKey{circID, streamID}]; es != nil {
		es.packageWindow += exitStreamSendmeInc
		if es.packageWindow > exitMaxStreamOutWindow {
			es.packageWindow = exitMaxStreamOutWindow
		}
	}
}

// HandleEnd 关闭出口流。
func (m *ExitStreamManager) HandleEnd(circID uint32, streamID uint16) {
	m.mu.Lock()
	es := m.streams[streamKey{circID, streamID}]
	if es != nil {
		delete(m.streams, streamKey{circID, streamID})
		if m.circStreams[circID] > 0 {
			m.circStreams[circID]--
		}
	}
	m.mu.Unlock()
	m.teardown(es)
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
		if !m.waitOutWindow(ctx, circ.CircuitID, streamID) {
			return
		}
		_ = remote.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := remote.Read(buf)
		if n > 0 {
			if err := m.sendRelay(circ, clientConn, streamID, cell.RelayData, buf[:n]); err != nil {
				return
			}
			m.consumeOutWindow(circ.CircuitID, streamID)
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

func (m *ExitStreamManager) waitOutWindow(ctx context.Context, circID uint32, streamID uint16) bool {
	for {
		m.mu.Lock()
		cw := m.circOutWindow[circID]
		es := m.streams[streamKey{circID, streamID}]
		sw := 0
		if es != nil {
			sw = es.packageWindow
		}
		m.mu.Unlock()
		if es == nil {
			return false
		}
		if cw > 0 && sw > 0 {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (m *ExitStreamManager) consumeOutWindow(circID uint32, streamID uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.circOutWindow[circID] > 0 {
		m.circOutWindow[circID]--
	}
	if es := m.streams[streamKey{circID, streamID}]; es != nil && es.packageWindow > 0 {
		es.packageWindow--
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
		out := make([]byte, 509)
		copy(out, plain)
		plain = out
	}
	circ.mu.Lock()
	defer circ.mu.Unlock()
	if circ.crypto == nil {
		return fmt.Errorf("circuit crypto gone")
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
	if i := strings.IndexByte(s, ' '); i >= 0 {
		s = s[:i]
	}
	h, pstr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	p, err := strconv.Atoi(pstr)
	if err != nil || p < 1 || p > 65535 {
		return "", 0, fmt.Errorf("bad port")
	}
	return h, uint16(p), nil
}
