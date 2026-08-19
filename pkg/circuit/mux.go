package circuit

import (
	"context"
	"fmt"
	"sync"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/debug"
	"github.com/opd-ai/go-tor/pkg/logger"
)

// CellMux 在一条 OR 连接上分发 cell：CREATED2 交给握手等待者，RELAY 交给对应 circuit。
type CellMux struct {
	conn      CellConnection
	logger    *logger.Logger
	mu        sync.Mutex
	circuits  map[uint32]*Circuit
	created   map[uint32]chan *cell.Cell
	closed    chan struct{}
	closeOnce sync.Once
}

// NewCellMux 创建连接级 cell 分发器。
func NewCellMux(conn CellConnection, log *logger.Logger) *CellMux {
	if log == nil {
		log = logger.NewDefault()
	}
	return &CellMux{
		conn:     conn,
		logger:   log.Component("cellmux"),
		circuits: make(map[uint32]*Circuit),
		created:  make(map[uint32]chan *cell.Cell),
		closed:   make(chan struct{}),
	}
}

// RegisterCircuit 注册已建立/正在建立的 circuit。
func (m *CellMux) RegisterCircuit(c *Circuit) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.circuits[c.ID] = c
}

// ExpectCreated2 在发出 CREATE2 之前登记 waiter，避免快回的 CREATED2 被丢掉。
func (m *CellMux) ExpectCreated2(circID uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.created[circID]; !ok {
		m.created[circID] = make(chan *cell.Cell, 1)
	}
}

// ForgetCreated2 发送失败时撤销 waiter。
func (m *CellMux) ForgetCreated2(circID uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.created, circID)
}

// WaitCreated2 等待指定 circuit 的 CREATED2 或 DESTROY。
func (m *CellMux) WaitCreated2(ctx context.Context, circID uint32) (*cell.Cell, error) {
	m.mu.Lock()
	ch, ok := m.created[circID]
	if !ok {
		ch = make(chan *cell.Cell, 1)
		m.created[circID] = ch
	}
	m.mu.Unlock()
	defer m.ForgetCreated2(circID)

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout waiting for CREATED2: %w", ctx.Err())
	case <-m.closed:
		return nil, fmt.Errorf("cell mux closed while waiting for CREATED2")
	case c := <-ch:
		if c == nil {
			return nil, fmt.Errorf("connection closed while waiting for CREATED2")
		}
		if c.Command == cell.CmdDestroy {
			reason := byte(0)
			if len(c.Payload) > 0 {
				reason = c.Payload[0]
			}
			return nil, fmt.Errorf("circuit %d destroyed during CREATE2: reason=%d", circID, reason)
		}
		return c, nil
	}
}

// Start 启动读循环。handshake 完成后才能调用。
func (m *CellMux) Start() {
	go m.loop()
}

// Close 停止读循环并关闭底层连接，避免失败建路泄漏读 goroutine。
func (m *CellMux) isClosed() bool {
	if m == nil {
		return false
	}
	select {
	case <-m.closed:
		return true
	default:
		return false
	}
}

func (m *CellMux) Close() {
	m.closeOnce.Do(func() {
		close(m.closed)
		if closer, ok := m.conn.(interface{ Close() error }); ok && m.conn != nil {
			_ = closer.Close()
		}
	})
}

func (m *CellMux) loop() {
	for {
		select {
		case <-m.closed:
			return
		default:
		}
		received, err := m.conn.ReceiveCell()
		if err != nil {
			m.logger.Error("Cell mux receive failed", "error", err)
			m.Close()
			return
		}
		debug.TraceRX("", received.CircID, received.Command.String(), 0, len(received.Payload), false, false)
		m.dispatch(received)
	}
}

func (m *CellMux) dispatch(c *cell.Cell) {
	switch c.Command {
	case cell.CmdPadding, cell.CmdVPadding:
		return
	case cell.CmdCreated2, cell.CmdDestroy:
		m.mu.Lock()
		ch, ok := m.created[c.CircID]
		m.mu.Unlock()
		if ok {
			select {
			case ch <- c:
			default:
			}
			return
		}
		if c.Command == cell.CmdDestroy {
			m.mu.Lock()
			circ := m.circuits[c.CircID]
			m.mu.Unlock()
			if circ != nil {
				reason := byte(0)
				if len(c.Payload) > 0 {
					reason = c.Payload[0]
				}
				circ.NotifyDestroyed(reason)
				// Close 才会走 Conflux onLegClosed，拆掉另一条腿。
				circ.Close()
			}
		}
	case cell.CmdRelay, cell.CmdRelayEarly:
		m.mu.Lock()
		circ := m.circuits[c.CircID]
		m.mu.Unlock()
		if circ == nil {
			m.logger.Debug("RELAY cell for unknown circuit", "circuit_id", c.CircID)
			return
		}
		if err := circ.DeliverRelayCell(c); err != nil {
			m.logger.Warn("Failed to deliver RELAY cell", "circuit_id", c.CircID, "error", err)
		}
	default:
		m.logger.Debug("Ignoring unexpected cell", "command", c.Command, "circuit_id", c.CircID)
	}
}
