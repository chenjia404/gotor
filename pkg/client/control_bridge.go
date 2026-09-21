package client

import (
	"github.com/opd-ai/go-tor/pkg/control"
	"github.com/opd-ai/go-tor/pkg/security"
)

// controlEventBridge 把 SOCKS 流事件桥接到 Control EventDispatcher。
type controlEventBridge struct {
	dispatcher *control.EventDispatcher
}

func (b *controlEventBridge) PublishStream(streamID, circuitID uint32, status, target string) {
	if b == nil || b.dispatcher == nil {
		return
	}
	b.dispatcher.Dispatch(&control.StreamEvent{
		StreamID:  security.Uint32ToUint16(streamID),
		Status:    status,
		CircuitID: circuitID,
		Target:    target,
	})
}

func (b *controlEventBridge) PublishNotice(msg string) {
	if b == nil || b.dispatcher == nil {
		return
	}
	b.dispatcher.Dispatch(&control.NoticeEvent{Message: msg})
}
