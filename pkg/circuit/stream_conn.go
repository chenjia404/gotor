package circuit

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
)

// StreamConn 把已 OpenStream 的电路流做成 net.Conn。
// Read/Write 可并行（HTTP CONNECT / SOCKS 双向拷贝）。
type StreamConn struct {
	circ    *Circuit
	id      uint16
	ctx     context.Context
	cancel  context.CancelFunc
	onClose func()

	rmu      sync.Mutex
	leftover []byte

	closeOnce sync.Once
}

// OpenStreamConn 发送 RELAY_BEGIN，等到 RELAY_CONNECTED 后返回可读写连接。
// onClose 在 Close 时调用（例如把电路放回池）；StreamID 由本函数分配并在 Close 时释放。
func OpenStreamConn(ctx context.Context, circ *Circuit, host string, port uint16, onClose func()) (*StreamConn, error) {
	if circ == nil {
		return nil, io.ErrClosedPipe
	}
	sid, err := circ.AllocateStreamID()
	if err != nil {
		return nil, err
	}
	if err := circ.OpenStream(ctx, sid, host, port); err != nil {
		circ.ReleaseStreamID(sid)
		return nil, err
	}
	// BEGIN→CONNECTED 用调用方超时；成功后 Read 必须独立于 dial ctx，
	// 否则 HTTPTunnel 在 200 前 cancel 拨号超时会立刻掐断流。
	cctx, cancel := context.WithCancel(context.Background())
	return &StreamConn{
		circ:    circ,
		id:      sid,
		ctx:     cctx,
		cancel:  cancel,
		onClose: onClose,
	}, nil
}

func (s *StreamConn) Read(p []byte) (int, error) {
	if s == nil {
		return 0, io.ErrClosedPipe
	}
	s.rmu.Lock()
	defer s.rmu.Unlock()
	if len(s.leftover) > 0 {
		n := copy(p, s.leftover)
		s.leftover = s.leftover[n:]
		return n, nil
	}
	data, err := s.circ.ReadFromStream(s.ctx, s.id)
	if err != nil {
		return 0, err
	}
	n := copy(p, data)
	if n < len(data) {
		s.leftover = append(s.leftover[:0], data[n:]...)
	}
	return n, nil
}

func (s *StreamConn) Write(p []byte) (int, error) {
	if s == nil || s.circ == nil {
		return 0, io.ErrClosedPipe
	}
	if err := s.circ.WriteToStream(s.id, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *StreamConn) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.cancel()
		_ = s.circ.EndStream(s.id, 6)
		s.circ.ReleaseStreamID(s.id)
		if s.onClose != nil {
			s.onClose()
		}
	})
	return nil
}

func (s *StreamConn) LocalAddr() net.Addr  { return streamAddr("tor-stream") }
func (s *StreamConn) RemoteAddr() net.Addr { return streamAddr("tor-exit") }

// StreamID 是本连接占用的电路 StreamID。
func (s *StreamConn) StreamID() uint16 {
	if s == nil {
		return 0
	}
	return s.id
}

// AfterClose 在已有 onClose 之后追加清理（例如 stream.Manager.RemoveStream）。
func (s *StreamConn) AfterClose(fn func()) {
	if s == nil || fn == nil {
		return
	}
	prev := s.onClose
	s.onClose = func() {
		if prev != nil {
			prev()
		}
		fn()
	}
}

func (s *StreamConn) SetDeadline(t time.Time) error {
	_ = t
	return nil
}
func (s *StreamConn) SetReadDeadline(t time.Time) error {
	_ = t
	return nil
}
func (s *StreamConn) SetWriteDeadline(t time.Time) error {
	_ = t
	return nil
}

type streamAddr string

func (a streamAddr) Network() string { return "tor" }
func (a streamAddr) String() string  { return string(a) }
