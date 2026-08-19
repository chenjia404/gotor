package circuit

import (
	"crypto/subtle"
	"fmt"

	"github.com/opd-ai/go-tor/pkg/cell"
)

const (
	circWindowIncrement = 100
	sendmeAcceptMin     = cell.SendmeVersion1
)

func cloneDigest(tag []byte) []byte {
	if len(tag) == 0 {
		return nil
	}
	return append([]byte(nil), tag...)
}

// maybeRecordSendmeTag 在发出 DATA 后，若 package window 落到 100 的倍数，
// 记下该 cell 的 20 字节滚动摘要，供对端电路级 SENDME v1 校验。
// 对照 spec flow-control 与 C Tor sendme_record_cell_digest_on_circ。
func (c *Circuit) maybeRecordSendmeTag(tag []byte) {
	if len(tag) != cell.SendmeV1DigestLen {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// window==0 也是 100 的倍数（第 1000 个 DATA），必须入队。
	if c.packageWindow%circWindowIncrement == 0 {
		c.sendmeExpected = append(c.sendmeExpected, cloneDigest(tag))
	}
}

// decrementPackageWindowForSendme 原子减窗，并标明本 cell 是否落在 SENDME 边界。
// 与记 tag 分两步但边界判定必须与减窗同一把锁，避免并发漏记。
func (c *Circuit) decrementPackageWindowForSendme() (record bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.packageWindow <= 0 {
		return false, fmt.Errorf("package window exhausted: cannot send more cells until SENDME received")
	}
	c.packageWindow--
	return c.packageWindow%circWindowIncrement == 0, nil
}

func (c *Circuit) recordSendmeTag(tag []byte) {
	if len(tag) != cell.SendmeV1DigestLen {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sendmeExpected = append(c.sendmeExpected, cloneDigest(tag))
}

// decrementDeliverWindowAndTakeSendme 原子减 deliver 窗。
// 若凑满 100 个 DATA，立即清零计数并返回 true，避免突发 DATA 重复发 SENDME。
func (c *Circuit) decrementDeliverWindowAndTakeSendme() (send bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.deliverWindow <= 0 {
		return false, fmt.Errorf("deliver window exhausted: cannot receive more cells until SENDME sent")
	}
	c.deliverWindow--
	c.sendmeReceived++
	if c.sendmeReceived >= circWindowIncrement {
		c.sendmeReceived -= circWindowIncrement
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

// processCircuitSendme 校验电路级 SENDME v1 后增加 package window。
// digest 不匹配或 version < 1 必须拆路（spec：tear down）。
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
	if subtle.ConstantTimeCompare(expected, digest) != 1 {
		return fmt.Errorf("SENDME digest mismatch")
	}
	c.sendmeExpected = c.sendmeExpected[1:]
	c.packageWindow += circWindowIncrement
	return nil
}

func (c *Circuit) sendCircuitSendme(tag []byte) error {
	if len(tag) != cell.SendmeV1DigestLen {
		return fmt.Errorf("missing SENDME v1 digest")
	}
	payload, err := cell.EncodeSendmeV1(tag)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.sendmeSent++
	c.deliverWindow += circWindowIncrement
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
