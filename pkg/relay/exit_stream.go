// Package relay — 出口流：RELAY_BEGIN → 解析/策略 → 拨号 → CONNECTED/DATA/END。
package relay

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/circuit"
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
	exitDialTimeout        = 15 * time.Second
	exitIdleTimeout        = 2 * time.Minute
	beginFlagIPv6OK        = 1
	beginFlagIPv4NotOK     = 2
	beginFlagIPv6Preferred = 4
	ccSendmeIncDefault     = 31
	exitOrconnSlowWrite    = 100 * time.Millisecond
)

// ExitStreamManager 管理出口 TCP 流。
type ExitStreamManager struct {
	policy    *ExitPolicy
	logger    *logger.Logger
	lookup    func(ctx context.Context, host string) ([]net.IP, error)
	lookupP   func(ctx context.Context, addr string) ([]string, error)
	dial      func(ctx context.Context, network, address string) (net.Conn, error)
	bw        *bandwidthLimiter
	gate      *exitConnGate
	dirDial   func(orAddr string) (net.Conn, error) // BEGIN_DIR：本机目录缓存
	exitStats *ExitStats

	mu                 sync.Mutex
	streams            map[streamKey]*exitStream
	circOutWindow      map[uint32]int
	circInCount        map[uint32]int
	circStreams        map[uint32]int
	circCC             map[uint32]circFlow
	lastFwdDigest      map[uint32][]byte
	circExpectedSendme map[uint32][]exitSendmePending
	orWrites           map[uint32]*orconnWriteStats
	ccParams           circuit.CCParams
}

type circFlow struct {
	cc        bool
	sendmeInc int
	vegas     *circuit.Vegas
}

// exitSendmePending 出口发出 DATA 后记下的 tag 与时刻，供客户端电路级 SENDME 校验并估 RTT。
type exitSendmePending struct {
	digest []byte
	sentAt time.Time
}

// orconnWriteStats 对齐客户端 Connection.WriteBlocked：排队 >1 或单次写出 ≥100ms（一次性）。
type orconnWriteStats struct {
	waiters atomic.Int32
	lastNs  atomic.Int64
}

func (s *orconnWriteStats) begin() {
	if s != nil {
		s.waiters.Add(1)
	}
}

func (s *orconnWriteStats) end(d time.Duration) {
	if s == nil {
		return
	}
	s.lastNs.Store(d.Nanoseconds())
	s.waiters.Add(-1)
}

func (s *orconnWriteStats) WriteBlocked() bool {
	if s == nil {
		return false
	}
	if s.waiters.Load() > 1 {
		return true
	}
	return time.Duration(s.lastNs.Swap(0)) >= exitOrconnSlowWrite
}

type streamKey struct {
	circID   uint32
	streamID uint16
}

type exitStream struct {
	conn          net.Conn
	cancel        context.CancelFunc
	packageWindow int // 向客户端发送
	deliverWindow int // 允许再收多少客户端 DATA
	deliverCount  int
	halfClosed    bool
	held          bool   // 已占用 gate
	exitPort      uint16 // RELAY_BEGIN 目标端口；0 表示 BEGIN_DIR，不计入 exit-*
}

func NewExitStreamManager(policy *ExitPolicy, log *logger.Logger) *ExitStreamManager {
	if log == nil {
		log = logger.NewDefault()
	}
	return &ExitStreamManager{
		policy:             policy,
		logger:             log.Component("exit-stream"),
		streams:            make(map[streamKey]*exitStream),
		circOutWindow:      make(map[uint32]int),
		circInCount:        make(map[uint32]int),
		circStreams:        make(map[uint32]int),
		circCC:             make(map[uint32]circFlow),
		lastFwdDigest:      make(map[uint32][]byte),
		circExpectedSendme: make(map[uint32][]exitSendmePending),
		orWrites:           make(map[uint32]*orconnWriteStats),
		ccParams:           circuit.DefaultCCParams(),
		gate:               newExitConnGate(1024),
		exitStats:          NewExitStats(),
	}
}

// SetBandwidthLimit 接线 RelayBandwidthRate/Burst。
func (m *ExitStreamManager) SetBandwidthLimit(rate, burst int64) {
	m.bw = newBandwidthLimiter(rate, burst)
}

// SetMaxExitConns 限制并发出口连接。
func (m *ExitStreamManager) SetMaxExitConns(n int) {
	m.gate = newExitConnGate(n)
}

// SetDirDial 设置 BEGIN_DIR 本机目录缓存拨号。orAddr 为相邻 OR 的 RemoteAddr。
func (m *ExitStreamManager) SetDirDial(fn func(orAddr string) (net.Conn, error)) {
	m.dirDial = fn
}

// SetCCParams 写入已验签共识的 FlowCtrl=2 参数。只影响之后新建的 Vegas。
func (m *ExitStreamManager) SetCCParams(p circuit.CCParams) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.ccParams = p
	m.mu.Unlock()
}

func (m *ExitStreamManager) lookupIP(ctx context.Context, host string) ([]net.IP, error) {
	if m.lookup != nil {
		return m.lookup(ctx, host)
	}
	return resolveBeginIPs(ctx, host)
}

func (m *ExitStreamManager) dialTCP(ctx context.Context, address string) (net.Conn, error) {
	if m.dial != nil {
		return m.dial(ctx, "tcp", address)
	}
	d := net.Dialer{Timeout: exitDialTimeout}
	return d.DialContext(ctx, "tcp", address)
}

// NoteFwdDigest 在成功解密入向 cell 后记录滚动摘要或 CGO tag（供电路 SENDME v1）。
func (m *ExitStreamManager) NoteFwdDigest(circID uint32, digest []byte) {
	if len(digest) != cell.SendmeV1DigestLen && len(digest) != cell.SendmeCGOTagLen {
		return
	}
	m.mu.Lock()
	m.lastFwdDigest[circID] = append([]byte(nil), digest...)
	m.mu.Unlock()
}

// NoteCircuitFlow 记录该电路是否协商了 FlowCtrl=2；协商后立刻建 Vegas，BEGIN 不得覆盖。
func (m *ExitStreamManager) NoteCircuitFlow(circID uint32, cc bool, sendmeInc int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cc {
		m.ensureCCLocked(circID, sendmeInc)
		return
	}
	if sendmeInc <= 0 {
		sendmeInc = exitCircSendmeInc
	}
	m.circCC[circID] = circFlow{cc: false, sendmeInc: sendmeInc}
}

// ensureCCLocked 在已持锁时为电路挂上 Vegas。已有状态机则不重建。
func (m *ExitStreamManager) ensureCCLocked(circID uint32, sendmeInc int) {
	if sendmeInc <= 0 {
		sendmeInc = ccSendmeIncDefault
	}
	if f, ok := m.circCC[circID]; ok && f.vegas != nil {
		return
	}
	v := circuit.NewVegas(m.ccParams, sendmeInc)
	m.circCC[circID] = circFlow{cc: true, sendmeInc: sendmeInc, vegas: v}
	if _, ok := m.circOutWindow[circID]; !ok {
		m.circOutWindow[circID] = v.PackageWindow()
	}
}

func (m *ExitStreamManager) flowOf(circID uint32) circFlow {
	if f, ok := m.circCC[circID]; ok {
		return f
	}
	return circFlow{sendmeInc: exitCircSendmeInc}
}

func (m *ExitStreamManager) orWriteOf(circID uint32) *orconnWriteStats {
	m.mu.Lock()
	s := m.orWriteLocked(circID)
	m.mu.Unlock()
	return s
}

func (m *ExitStreamManager) orWriteLocked(circID uint32) *orconnWriteStats {
	s := m.orWrites[circID]
	if s == nil {
		s = &orconnWriteStats{}
		if m.orWrites == nil {
			m.orWrites = make(map[uint32]*orconnWriteStats)
		}
		m.orWrites[circID] = s
	}
	return s
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
	delete(m.circCC, circID)
	delete(m.circExpectedSendme, circID)
	delete(m.orWrites, circID)
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
	m.circCC = make(map[uint32]circFlow)
	m.circExpectedSendme = make(map[uint32][]exitSendmePending)
	m.orWrites = make(map[uint32]*orconnWriteStats)
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
	if es.held {
		es.held = false
		m.gate.release()
	}
}

// HandleBegin 先解析 DNS、对候选 IP 检策略，再只拨允许的地址。
func (m *ExitStreamManager) HandleBegin(ctx context.Context, circ *ServerCircuit, clientConn net.Conn, streamID uint16, data []byte) error {
	if m.policy == nil || !m.policy.AllowExit {
		return m.sendEnd(circ, clientConn, streamID, cell.EndReasonExitPolicy)
	}
	addr, port, flags, flagsPresent, err := parseBeginAddr(data)
	if err != nil {
		return m.sendEnd(circ, clientConn, streamID, cell.EndReasonMisc)
	}
	if isOnionHost(addr) {
		return m.sendEnd(circ, clientConn, streamID, cell.EndReasonExitPolicy)
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

	if !m.gate.acquire() {
		return m.sendEnd(circ, clientConn, streamID, cell.EndReasonResourceLimit)
	}
	held := true
	defer func() {
		if held {
			m.gate.release()
		}
	}()

	rctx := ctx
	if circ != nil && circ.ctx != nil {
		rctx = circ.ctx
	}
	ips, err := m.lookupIP(rctx, addr)
	if err != nil || len(ips) == 0 {
		return m.sendEnd(circ, clientConn, streamID, cell.EndReasonResolveFailed)
	}
	ips = filterBeginIPs(ips, flags, flagsPresent)

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
	dctx, cancelDial := context.WithTimeout(rctx, exitDialTimeout)
	defer cancelDial()
	c, err := m.dialTCP(dctx, target)
	if err != nil {
		m.logger.Debug("exit dial failed", "target", target, "error", err)
		return m.sendEnd(circ, clientConn, streamID, dialEndReason(err))
	}

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

	sctx, cancel := context.WithCancel(rctx)
	m.mu.Lock()
	m.streams[key] = &exitStream{
		conn:          c,
		cancel:        cancel,
		packageWindow: exitStreamWindowInit,
		deliverWindow: exitStreamWindowInit,
		held:          true,
		exitPort:      port,
	}
	m.circStreams[circ.CircuitID]++
	if circ != nil && circ.ccEnabled {
		m.ensureCCLocked(circ.CircuitID, circ.sendmeInc)
	} else if _, ok := m.circOutWindow[circ.CircuitID]; !ok {
		m.circOutWindow[circ.CircuitID] = exitCircWindowInit
	}
	m.mu.Unlock()
	held = false

	m.exitStats.NoteOpened(port)
	go m.pumpRemoteToClient(sctx, circ, clientConn, streamID, c)
	return nil
}

// HandleBeginDir 连接本机目录缓存。无缓存则 NOTDIRECTORY。
func (m *ExitStreamManager) HandleBeginDir(ctx context.Context, circ *ServerCircuit, clientConn net.Conn, streamID uint16) error {
	if m.dirDial == nil {
		return m.sendEnd(circ, clientConn, streamID, cell.EndReasonNotDirectory)
	}
	m.mu.Lock()
	if m.circStreams[circ.CircuitID] >= exitMaxStreamsPerCirc {
		m.mu.Unlock()
		return m.sendEnd(circ, clientConn, streamID, cell.EndReasonResourceLimit)
	}
	m.circStreams[circ.CircuitID]++ // 先占名额，避免 TOCTOU 耗尽 goroutine
	m.mu.Unlock()
	releaseSlot := func() {
		m.mu.Lock()
		if m.circStreams[circ.CircuitID] > 0 {
			m.circStreams[circ.CircuitID]--
		}
		m.mu.Unlock()
	}
	if !m.gate.acquire() {
		releaseSlot()
		return m.sendEnd(circ, clientConn, streamID, cell.EndReasonResourceLimit)
	}
	orAddr := ""
	if clientConn != nil && clientConn.RemoteAddr() != nil {
		orAddr = clientConn.RemoteAddr().String()
	}
	c, err := m.dirDial(orAddr)
	if err != nil {
		m.gate.release()
		releaseSlot()
		return m.sendEnd(circ, clientConn, streamID, cell.EndReasonNotDirectory)
	}
	rctx := ctx
	if circ != nil && circ.ctx != nil {
		rctx = circ.ctx
	}
	sctx, cancel := context.WithCancel(rctx)
	key := streamKey{circ.CircuitID, streamID}
	m.mu.Lock()
	m.streams[key] = &exitStream{
		conn:          c,
		cancel:        cancel,
		packageWindow: exitStreamWindowInit,
		deliverWindow: exitStreamWindowInit,
		held:          true,
	}
	if circ != nil && circ.ccEnabled {
		m.ensureCCLocked(circ.CircuitID, circ.sendmeInc)
	} else if _, ok := m.circOutWindow[circ.CircuitID]; !ok {
		m.circOutWindow[circ.CircuitID] = exitCircWindowInit
	}
	m.mu.Unlock()
	if err := m.sendRelay(circ, clientConn, streamID, cell.RelayConnected, nil); err != nil {
		if es := m.removeStream(circ.CircuitID, streamID); es != nil {
			m.teardown(es)
		}
		return err
	}
	go m.pumpRemoteToClient(sctx, circ, clientConn, streamID, c)
	return nil
}

func resolveBeginIPs(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	// 出口按 Tor 规范在本机解析主机名（非客户端路径）
	r := &net.Resolver{PreferGo: true}
	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out, nil
}

func filterBeginIPs(ips []net.IP, flags uint32, flagsPresent bool) []net.IP {
	// 无 FLAGS 字段：兼容旧客户端，允许 IPv6。FLAGS 全 0：IPv6OK 未置位，只走 IPv4。
	ipv6OK := !flagsPresent || flags&beginFlagIPv6OK != 0
	ipv4OK := flags&beginFlagIPv4NotOK == 0
	prefer6 := flags&beginFlagIPv6Preferred != 0
	var v4, v6 []net.IP
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			if ipv4OK {
				v4 = append(v4, ip)
			}
		} else if ipv6OK {
			v6 = append(v6, ip)
		}
	}
	if prefer6 {
		return append(v6, v4...)
	}
	return append(v4, v6...)
}

func dialEndReason(err error) byte {
	if err == nil {
		return cell.EndReasonConnRefused
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return cell.EndReasonTimeout
	}
	s := err.Error()
	if strings.Contains(s, "refused") {
		return cell.EndReasonConnRefused
	}
	if strings.Contains(s, "reset") {
		return cell.EndReasonConnReset
	}
	if strings.Contains(s, "no route") || strings.Contains(s, "unreachable") {
		return cell.EndReasonNoRoute
	}
	return cell.EndReasonConnRefused
}

// HandleData 将客户端 DATA 写入远端，并维护入向 SENDME。
func (m *ExitStreamManager) HandleData(circ *ServerCircuit, clientConn net.Conn, streamID uint16, data []byte) error {
	m.mu.Lock()
	es := m.streams[streamKey{circ.CircuitID, streamID}]
	if es == nil || es.conn == nil {
		m.mu.Unlock()
		return fmt.Errorf("unknown exit stream %d/%d", circ.CircuitID, streamID)
	}
	if es.deliverWindow <= 0 {
		m.mu.Unlock()
		m.logger.Warn("inbound stream window exhausted", "circuit", circ.CircuitID, "stream", streamID)
		return m.sendEnd(circ, clientConn, streamID, cell.EndReasonMisc)
	}
	es.deliverWindow--
	conn := es.conn
	port := es.exitPort
	m.mu.Unlock()

	if err := m.bw.wait(context.Background(), len(data)); err != nil {
		return err
	}
	n, err := conn.Write(data)
	if n > 0 {
		m.exitStats.NoteBytes(port, uint64(n), 0)
	}
	if err != nil {
		return m.sendEnd(circ, clientConn, streamID, cell.EndReasonConnReset)
	}

	sendCirc, sendStream := false, false
	var circDigest []byte
	m.mu.Lock()
	es = m.streams[streamKey{circ.CircuitID, streamID}]
	flow := m.flowOf(circ.CircuitID)
	inc := flow.sendmeInc
	if inc <= 0 {
		inc = exitCircSendmeInc
	}
	m.circInCount[circ.CircuitID]++
	if m.circInCount[circ.CircuitID] >= inc {
		m.circInCount[circ.CircuitID] = 0
		sendCirc = true
		circDigest = append([]byte(nil), m.lastFwdDigest[circ.CircuitID]...)
	}
	if es != nil && !flow.cc && !(circ != nil && circ.crypto != nil && circ.crypto.usesCGO()) {
		es.deliverCount++
		if es.deliverCount >= exitStreamSendmeInc {
			es.deliverCount = 0
			es.deliverWindow += exitStreamSendmeInc
			if es.deliverWindow > exitMaxStreamOutWindow {
				es.deliverWindow = exitMaxStreamOutWindow
			}
			sendStream = true
		}
	} else if es != nil && (flow.cc || (circ != nil && circ.crypto != nil && circ.crypto.usesCGO())) {
		// FlowCtrl=2 / CGO：不发流级 SENDME，恢复本端防灌窗口
		es.deliverWindow++
		if es.deliverWindow > exitMaxStreamOutWindow {
			es.deliverWindow = exitMaxStreamOutWindow
		}
	}
	m.mu.Unlock()

	if sendCirc && (len(circDigest) == cell.SendmeV1DigestLen || len(circDigest) == cell.SendmeCGOTagLen) {
		payload, err := cell.EncodeSendmeV1(circDigest)
		if err == nil {
			_ = m.sendRelay(circ, clientConn, 0, cell.RelaySendme, payload)
		}
	}
	if sendStream {
		_ = m.sendRelay(circ, clientConn, streamID, cell.RelaySendme, nil)
	}
	return nil
}

// HandleSendme 客户端 SENDME：电路级必须 v1 且 FIFO 匹配发出 DATA 的 tag。
// 经典电路：已满窗口的多余 SENDME 丢弃，防止放大。FlowCtrl=2：跑 Vegas，不得 +sendme_inc。
func (m *ExitStreamManager) HandleSendme(circID uint32, streamID uint16, payload []byte) error {
	if streamID != 0 {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.flowOf(circID).vegas != nil {
			return nil
		}
		if es := m.streams[streamKey{circID, streamID}]; es != nil {
			if es.packageWindow >= exitStreamWindowInit {
				return nil
			}
			es.packageWindow += exitStreamSendmeInc
			if es.packageWindow > exitStreamWindowInit {
				es.packageWindow = exitStreamWindowInit
			}
		}
		return nil
	}
	version, digest, err := cell.DecodeSendme(payload)
	if err != nil {
		return err
	}
	if version < cell.SendmeVersion1 {
		return fmt.Errorf("SENDME v0 rejected")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	q := m.circExpectedSendme[circID]
	if len(q) == 0 {
		return fmt.Errorf("unexpected circuit SENDME")
	}
	pending := q[0]
	if len(pending.digest) != len(digest) || subtle.ConstantTimeCompare(pending.digest, digest) != 1 {
		return fmt.Errorf("SENDME digest mismatch")
	}
	m.circExpectedSendme[circID] = q[1:]
	flow := m.flowOf(circID)
	if flow.vegas != nil {
		rtt := int64(0)
		if !pending.sentAt.IsZero() {
			rtt = time.Since(pending.sentAt).Microseconds()
		}
		flow.vegas.SetBlockedChan(m.orWriteLocked(circID).WriteBlocked())
		flow.vegas.ProcessSendme(rtt)
		m.circOutWindow[circID] = flow.vegas.PackageWindow()
		return nil
	}
	initW := exitCircWindowInit
	cur := m.circOutWindow[circID]
	if cur >= initW {
		return nil
	}
	inc := flow.sendmeInc
	if inc <= 0 {
		inc = exitCircSendmeInc
	}
	cur += inc
	if cur > initW {
		cur = initW
	}
	m.circOutWindow[circID] = cur
	return nil
}

// HandleEnd 半关闭出口流（只关写侧，仍可读）。
func (m *ExitStreamManager) HandleEnd(circID uint32, streamID uint16) {
	m.mu.Lock()
	es := m.streams[streamKey{circID, streamID}]
	if es == nil {
		m.mu.Unlock()
		return
	}
	if es.halfClosed {
		delete(m.streams, streamKey{circID, streamID})
		if m.circStreams[circID] > 0 {
			m.circStreams[circID]--
		}
		m.mu.Unlock()
		m.teardown(es)
		return
	}
	es.halfClosed = true
	conn := es.conn
	m.mu.Unlock()
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
		return
	}
	m.mu.Lock()
	delete(m.streams, streamKey{circID, streamID})
	if m.circStreams[circID] > 0 {
		m.circStreams[circID]--
	}
	m.mu.Unlock()
	m.teardown(es)
}

func (m *ExitStreamManager) streamExitPort(circID uint32, streamID uint16) uint16 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	es := m.streams[streamKey{circID, streamID}]
	if es == nil {
		return 0
	}
	return es.exitPort
}

// StatsExit 已完成 24h 窗的 exit-*；非出口或不允许退出则空。
func (m *ExitStreamManager) StatsExit() map[string]string {
	if m == nil || m.exitStats == nil {
		return nil
	}
	if m.policy == nil || !m.policy.AllowExit {
		return nil
	}
	return m.exitStats.StatsMap()
}

func (m *ExitStreamManager) removeStream(circID uint32, streamID uint16) *exitStream {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := streamKey{circID, streamID}
	es := m.streams[key]
	if es != nil {
		delete(m.streams, key)
		if m.circStreams[circID] > 0 {
			m.circStreams[circID]--
		}
	}
	return es
}

func (m *ExitStreamManager) pumpRemoteToClient(ctx context.Context, circ *ServerCircuit, clientConn net.Conn, streamID uint16, remote net.Conn) {
	defer func() {
		if es := m.removeStream(circ.CircuitID, streamID); es != nil {
			m.teardown(es)
		}
	}()
	buf := make([]byte, exitRelayDataChunk(circ))
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if !m.waitOutWindow(ctx, circ.CircuitID, streamID) {
			return
		}
		_ = remote.SetReadDeadline(time.Now().Add(exitIdleTimeout))
		n, err := remote.Read(buf)
		if n > 0 {
			if err := m.bw.wait(ctx, n); err != nil {
				return
			}
			m.exitStats.NoteBytes(m.streamExitPort(circ.CircuitID, streamID), 0, uint64(n))
			if err := m.sendRelay(circ, clientConn, streamID, cell.RelayData, buf[:n]); err != nil {
				return
			}
		}
		if err != nil {
			reason := cell.EndReasonDone
			if err != io.EOF {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					reason = cell.EndReasonTimeout
				} else if !strings.Contains(err.Error(), "use of closed") {
					m.logger.Debug("exit remote read", "error", err)
					reason = cell.EndReasonConnReset
				}
			}
			_ = m.sendEnd(circ, clientConn, streamID, reason)
			return
		}
	}
}

func (m *ExitStreamManager) waitOutWindow(ctx context.Context, circID uint32, streamID uint16) bool {
	for {
		m.mu.Lock()
		flow := m.flowOf(circID)
		cw := m.circOutWindow[circID]
		if flow.vegas != nil {
			cw = flow.vegas.PackageWindow()
		}
		es := m.streams[streamKey{circID, streamID}]
		sw := 0
		if es != nil {
			sw = es.packageWindow
		}
		m.mu.Unlock()
		if es == nil {
			return false
		}
		if flow.vegas != nil {
			if cw > 0 {
				return true
			}
		} else if cw > 0 && sw > 0 {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func exitRelayDataChunk(circ *ServerCircuit) int {
	if circ != nil && circ.crypto != nil && circ.crypto.usesCGO() {
		return cell.RelayCellMaxDataV1(cell.RelayData)
	}
	return cell.PayloadLen - cell.RelayCellHeaderLen
}

func (m *ExitStreamManager) sendEnd(circ *ServerCircuit, clientConn net.Conn, streamID uint16, reason byte) error {
	return m.sendRelay(circ, clientConn, streamID, cell.RelayEnd, []byte{reason})
}

func (m *ExitStreamManager) sendRelay(circ *ServerCircuit, clientConn net.Conn, streamID uint16, cmd byte, data []byte) error {
	rc, err := cell.NewRelayCell(streamID, cmd, data)
	if err != nil {
		return err
	}
	circ.mu.Lock()
	if circ.crypto == nil {
		circ.mu.Unlock()
		return fmt.Errorf("circuit crypto gone")
	}
	enc, tag, err := circ.crypto.originateRelayTag(rc)
	circ.mu.Unlock()
	if err != nil {
		return err
	}
	c := &cell.Cell{CircID: circ.CircuitID, Command: cell.CmdRelay, Payload: enc}
	ws := m.orWriteOf(circ.CircuitID)
	ws.begin()
	start := time.Now()
	err = c.Encode(clientConn)
	ws.end(time.Since(start))
	if err != nil {
		return err
	}
	if cmd == cell.RelayData {
		m.afterOutboundDATA(circ.CircuitID, streamID, tag)
	}
	return nil
}

// afterOutboundDATA 减出向窗；落到 increment 倍数时记下 tag，供对端电路级 SENDME v1。
func (m *ExitStreamManager) afterOutboundDATA(circID uint32, streamID uint16, tag []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	flow := m.flowOf(circID)
	tagOK := len(tag) == cell.SendmeV1DigestLen || len(tag) == cell.SendmeCGOTagLen
	if flow.vegas != nil {
		flow.vegas.OnDataSent()
		m.circOutWindow[circID] = flow.vegas.PackageWindow()
		if tagOK && flow.vegas.ShouldRecordSendme() {
			m.circExpectedSendme[circID] = append(m.circExpectedSendme[circID], exitSendmePending{
				digest: append([]byte(nil), tag...),
				sentAt: time.Now(),
			})
		}
		return
	}
	if m.circOutWindow[circID] > 0 {
		m.circOutWindow[circID]--
	}
	if es := m.streams[streamKey{circID, streamID}]; es != nil && es.packageWindow > 0 {
		es.packageWindow--
	}
	inc := flow.sendmeInc
	if inc <= 0 {
		inc = exitCircSendmeInc
	}
	sent := exitCircWindowInit - m.circOutWindow[circID]
	if sent > 0 && inc > 0 && sent%inc == 0 && tagOK {
		m.circExpectedSendme[circID] = append(m.circExpectedSendme[circID], exitSendmePending{
			digest: append([]byte(nil), tag...),
			sentAt: time.Now(),
		})
	}
}

func parseBeginAddr(data []byte) (host string, port uint16, flags uint32, flagsPresent bool, err error) {
	nul := -1
	for i, b := range data {
		if b == 0 {
			nul = i
			break
		}
	}
	s := string(data)
	if nul >= 0 {
		s = string(data[:nul])
		rest := data[nul+1:]
		if len(rest) >= 4 {
			flagsPresent = true
			flags = uint32(rest[0])<<24 | uint32(rest[1])<<16 | uint32(rest[2])<<8 | uint32(rest[3])
		}
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, 0, false, fmt.Errorf("empty BEGIN")
	}
	if i := strings.IndexByte(s, ' '); i >= 0 {
		s = s[:i]
	}
	h, pstr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, 0, false, err
	}
	p, err := strconv.Atoi(pstr)
	if err != nil || p < 1 || p > 65535 {
		return "", 0, 0, false, fmt.Errorf("bad port")
	}
	return h, uint16(p), flags, flagsPresent, nil // #nosec G115 -- 已校验 1..65535
}

func isOnionHost(host string) bool {
	h := strings.ToLower(strings.Trim(host, "."))
	return h == "onion" || strings.HasSuffix(h, ".onion")
}
