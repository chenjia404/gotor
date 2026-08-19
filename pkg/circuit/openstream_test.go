package circuit

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
)

// TestWaitStreamConnectedDemux 复现错误分流：
// 电路上先到其它流的 DATA，OpenStream 不得因此失败。
func TestWaitStreamConnectedDemux(t *testing.T) {
	c := NewCircuit(1)
	mgr := newMockStreamManager()
	other := mgr.AddStream(7)
	c.SetStreamManager(mgr)

	go func() {
		c.relayReceiveChan <- &cell.RelayCell{StreamID: 7, Command: cell.RelayData, Data: []byte("other")}
		c.relayReceiveChan <- &cell.RelayCell{StreamID: 3, Command: cell.RelaySendme, Data: nil}
		c.relayReceiveChan <- &cell.RelayCell{StreamID: 3, Command: cell.RelayConnected, Data: []byte{1, 2, 3, 4, 0, 0, 0, 0}}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.waitStreamConnected(ctx, 3); err != nil {
		t.Fatalf("waitStreamConnected: %v", err)
	}
	got := other.GetReceivedData()
	if len(got) != 1 || string(got[0]) != "other" {
		t.Fatalf("其它流数据未投递: %v", got)
	}
}

func TestWaitStreamConnectedEnd(t *testing.T) {
	c := NewCircuit(2)
	go func() {
		c.relayReceiveChan <- &cell.RelayCell{StreamID: 9, Command: cell.RelayEnd, Data: []byte{6}}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := c.waitStreamConnected(ctx, 9)
	if err == nil || !strings.Contains(err.Error(), "reason=6") {
		t.Fatalf("want RELAY_END reason=6, got %v", err)
	}
}
