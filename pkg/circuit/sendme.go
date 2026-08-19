package circuit

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
)

const (
	circWindowIncrement = 100
	sendmeAcceptMin     = cell.SendmeVersion1
	packageWindowWait   = 2 * time.Minute
	sendWakePoll        = 25 * time.Millisecond
)

// ErrWindowExhausted 表示电路或流的发送窗用尽，发送方应等待 SENDME。
var ErrWindowExhausted = errors.New("package window exhausted")

type sendmePending struct {
	digest []byte
	sentAt time.Time
}

func cloneDigest(tag []byte) []byte {
	if len(tag) == 0 {
		return nil
	}
	return append([]byte(nil), tag...)
}

// maybeRecordSendmeTag 在发出 DATA 后，若 package window 落到 increment 的倍数，
// 记下该 cell 的 20 字节滚动摘要，供对端电路级 SENDME v1 校验。
// 对照 spec flow-control 与 C Tor sendme_record_cell_digest_on_circ。
func (c *Circuit) maybeRecordSendmeTag(tag []byte) {
	if len(tag) != cell.SendmeV1DigestLen && len(tag) != cell.SendmeCGOTagLen {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.vegas != nil {
		if c.vegas.inflight > 0 && c.vegas.inflight%c.vegas.sendmeInc == 0 {
			c.enqueueSendmeLocked(tag)
		}
		return
	}
	// window==0 也是 increment 的倍数（第 N 个 DATA），必须入队。
	inc := c.sendmeIncrementLocked()
	if c.packageWindow%inc == 0 {
		c.enqueueSendmeLocked(tag)
	}
}

func (c *Circuit) enqueueSendmeLocked(tag []byte) {
	c.sendmeExpected = append(c.sendmeExpected, sendmePending{
		digest: cloneDigest(tag),
		sentAt: time.Now(),
	})
}

func (c *Circuit) sendmeIncrementLocked() int {
	if c.sendmeInc > 0 {
		return c.sendmeInc
	}
	return circWindowIncrement
}

// SetCCParams 在建路前写入已验签共识的 CC 参数。未调用则用 C Tor 默认。
func (c *Circuit) SetCCParams(p CCParams) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ccParams = p
}

// EnableCongestionControl 在 ntor-v3 协商到 CC_FIELD_RESPONSE 后启用 FlowCtrl=2 Vegas。
// sendme_inc 必须用握手结果，不能用共识默认值覆盖对端给出的值。
func (c *Circuit) EnableCongestionControl(sendmeInc int) {
	if c == nil || sendmeInc < 1 || sendmeInc > 250 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sendmeInc = sendmeInc
	p := c.ccParams
	if p.CwndInit < 1 {
		p = DefaultCCParams()
		c.ccParams = p
	}
	c.vegas = newVegasState(p, sendmeInc)
	c.packageWindow = c.vegas.cwnd
	c.deliverWindow = c.vegas.cwnd
}

// decrementPackageWindowForSendme 原子减窗，并标明本 cell 是否落在 SENDME 边界。
// Vegas：用 inflight；经典：用 packageWindow。边界判定必须与记账同一把锁。
func (c *Circuit) decrementPackageWindowForSendme() (record bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.vegas != nil {
		if c.vegas.inflight >= c.vegas.cwnd {
			return false, fmt.Errorf("%w: cannot send more cells until SENDME received", ErrWindowExhausted)
		}
		c.vegas.inflight++
		c.packageWindow = c.vegas.packageWindow()
		return c.vegas.inflight%c.vegas.sendmeInc == 0, nil
	}
	if c.packageWindow <= 0 {
		return false, fmt.Errorf("%w: cannot send more cells until SENDME received", ErrWindowExhausted)
	}
	c.packageWindow--
	return c.packageWindow%c.sendmeIncrementLocked() == 0, nil
}

func (c *Circuit) recordSendmeTag(tag []byte) {
	if len(tag) != cell.SendmeV1DigestLen && len(tag) != cell.SendmeCGOTagLen {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enqueueSendmeLocked(tag)
}

// decrementDeliverWindowAndTakeSendme 原子减 deliver 窗。
// 若凑满 increment 个 DATA，立即清零计数并返回 true，避免突发 DATA 重复发 SENDME。
func (c *Circuit) decrementDeliverWindowAndTakeSendme() (send bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.deliverWindow <= 0 {
		return false, fmt.Errorf("deliver window exhausted: cannot receive more cells until SENDME sent")
	}
	c.deliverWindow--
	c.sendmeReceived++
	inc := c.sendmeIncrementLocked()
	if c.sendmeReceived >= inc {
		c.sendmeReceived -= inc
		return true, nil
	}
	return false, nil
}

func (c *Circuit) snapshotBackwardDigest(hopIdx int) []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if hopIdx < 0 || hopIdx >= len(c.Hops) {
		return nil
	}
	hop := c.Hops[hopIdx]
	if hop == nil || hop.BackwardDigest == nil {
		return nil
	}
	return hop.BackwardDigest.Sum(nil)
}

// processCircuitSendme 校验电路级 SENDME v1 后更新发送窗口。
// 已协商 CC 时跑 Vegas；否则按经典 +increment。digest 不匹配必须拆路。
func (c *Circuit) processCircuitSendme(payload []byte) error {
	version, digest, err := cell.DecodeSendme(payload)
	if err != nil {
		return fmt.Errorf("invalid SENDME: %w", err)
	}
	if version < sendmeAcceptMin {
		return fmt.Errorf("SENDME version %d below accept min %d", version, sendmeAcceptMin)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.sendmeExpected) == 0 {
		return fmt.Errorf("unexpected circuit SENDME")
	}
	expected := c.sendmeExpected[0]
	if subtle.ConstantTimeCompare(expected.digest, digest) != 1 {
		return fmt.Errorf("SENDME digest mismatch")
	}
	c.sendmeExpected = c.sendmeExpected[1:]
	if c.vegas != nil {
		rtt := int64(0)
		if !expected.sentAt.IsZero() {
			rtt = time.Since(expected.sentAt).Microseconds()
		}
		c.sampleOrconnBlockedLocked()
		c.vegas.processSendme(rtt)
		c.packageWindow = c.vegas.packageWindow()
		c.wakeSenders()
		return nil
	}
	c.packageWindow += c.sendmeIncrementLocked()
	c.wakeSenders()
	return nil
}

type writeBlocker interface {
	WriteBlocked() bool
}

func (c *Circuit) sampleOrconnBlockedLocked() {
	if c.vegas == nil {
		return
	}
	wb, ok := c.conn.(writeBlocker)
	if !ok {
		return
	}
	c.vegas.blockedChan = wb.WriteBlocked()
}

func (c *Circuit) wakeSenders() {
	if c == nil || c.sendWake == nil {
		return
	}
	select {
	case c.sendWake <- struct{}{}:
	default:
	}
}

func isPackageWindowExhausted(err error) bool {
	return errors.Is(err, ErrWindowExhausted)
}

func (c *Circuit) refundPackageWindow() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.vegas != nil {
		if c.vegas.inflight > 0 {
			c.vegas.inflight--
		}
		c.packageWindow = c.vegas.packageWindow()
		return
	}
	c.packageWindow++
}

func (c *Circuit) refundStreamPackageWindow(streamID uint16) {
	c.mu.RLock()
	mgr := c.streamManager
	c.mu.RUnlock()
	if mgr == nil {
		return
	}
	type streamGetter interface {
		GetStream(uint16) (interface{}, error)
	}
	getter, ok := mgr.(streamGetter)
	if !ok {
		return
	}
	streamIface, err := getter.GetStream(streamID)
	if err != nil {
		return
	}
	type streamRefunder interface {
		RefundPackageWindow()
	}
	if s, ok := streamIface.(streamRefunder); ok {
		s.RefundPackageWindow()
	}
}

func (c *Circuit) refundReservedWindows(streamID uint16, destCGO bool) {
	c.refundPackageWindow()
	if !destCGO && streamID > 0 {
		c.refundStreamPackageWindow(streamID)
	}
}

func (c *Circuit) orconnDead() bool {
	c.mu.RLock()
	mux := c.mux
	conn := c.conn
	c.mu.RUnlock()
	if mux != nil && mux.isClosed() {
		return true
	}
	if o, ok := conn.(interface{ IsOpen() bool }); ok && !o.IsOpen() {
		return true
	}
	return false
}

func (c *Circuit) waitForSendWake(deadline time.Time) error {
	if st := c.GetState(); st == StateClosed || st == StateFailed {
		return fmt.Errorf("circuit %s while waiting for SENDME", st)
	}
	if c.orconnDead() {
		return fmt.Errorf("orconn dead while waiting for SENDME")
	}
	remain := time.Until(deadline)
	if remain <= 0 {
		return fmt.Errorf("timeout waiting for package window")
	}
	wait := sendWakePoll
	if remain < wait {
		wait = remain
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-c.destroyCh:
		return fmt.Errorf("circuit destroyed while waiting for SENDME")
	case <-c.sendWake:
		return nil
	case <-timer.C:
		return nil
	}
}

// reserveDataWindows 为一条 RELAY_DATA 预留电路窗（以及非 CGO 的流窗）。
// 窗口用尽时等待 SENDME，而不是立刻失败。
func (c *Circuit) reserveDataWindows(streamID uint16, destCGO bool) (recordSendme bool, err error) {
	deadline := time.Now().Add(packageWindowWait)
	for {
		recordSendme, err = c.decrementPackageWindowForSendme()
		if err != nil {
			if !isPackageWindowExhausted(err) {
				return false, fmt.Errorf("circuit flow control: %w", err)
			}
			if err := c.waitForSendWake(deadline); err != nil {
				return false, err
			}
			continue
		}
		if destCGO || streamID == 0 {
			return recordSendme, nil
		}
		if err := c.decrementStreamPackageWindow(streamID); err != nil {
			c.refundPackageWindow()
			if !isPackageWindowExhausted(err) {
				return false, fmt.Errorf("stream flow control: %w", err)
			}
			if err := c.waitForSendWake(deadline); err != nil {
				return false, err
			}
			continue
		}
		return recordSendme, nil
	}
}

func (c *Circuit) sendCircuitSendme(tag []byte) error {
	if len(tag) != cell.SendmeV1DigestLen && len(tag) != cell.SendmeCGOTagLen {
		return fmt.Errorf("missing SENDME v1 tag")
	}
	payload, err := cell.EncodeSendmeV1(tag)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.sendmeSent++
	c.deliverWindow += c.sendmeIncrementLocked()
	c.mu.Unlock()

	sendmeCell, err := cell.NewRelayCell(0, cell.RelaySendme, payload)
	if err != nil {
		return fmt.Errorf("failed to create SENDME cell: %w", err)
	}
	return c.SendRelayCell(sendmeCell)
}

// SendmeStats 供测试观察电路级 SENDME 收发次数。
func (c *Circuit) SendmeStats() (sent, expectedQueued int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sendmeSent, len(c.sendmeExpected)
}

// SendmeIncrement 返回当前电路级 SENDME 间隔（经典 100，或 FlowCtrl=2 的 sendme_inc）。
func (c *Circuit) SendmeIncrement() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sendmeIncrementLocked()
}

// CongestionControlEnabled 表示本电路已协商 FlowCtrl=2 并启用 Vegas。
func (c *Circuit) CongestionControlEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.vegas != nil
}

// VegasStats 返回当前 Vegas 快照；未启用时 Enabled=false。
func (c *Circuit) VegasStats() VegasSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.vegas.snapshot()
}
