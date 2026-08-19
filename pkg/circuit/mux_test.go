package circuit

import (
	"context"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/cell"
)

type stubMuxConn struct{}

func (stubMuxConn) SendCell(*cell.Cell) error        { return nil }
func (stubMuxConn) ReceiveCell() (*cell.Cell, error) { return nil, context.Canceled }
func (stubMuxConn) Close() error                     { return nil }

func TestExpectCreated2CatchesEarlyResponse(t *testing.T) {
	mux := NewCellMux(stubMuxConn{}, nil)
	mux.ExpectCreated2(42)

	created := &cell.Cell{CircID: 42, Command: cell.CmdCreated2, Payload: []byte{0x00, 0x40}}
	mux.dispatch(created)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	got, err := mux.WaitCreated2(ctx, 42)
	if err != nil {
		t.Fatalf("CREATED2 registered before send must not be dropped: %v", err)
	}
	if got.Command != cell.CmdCreated2 {
		t.Fatalf("command=%v", got.Command)
	}
}

func TestDispatchCreated2WithoutWaiterIsDropped(t *testing.T) {
	mux := NewCellMux(stubMuxConn{}, nil)
	mux.dispatch(&cell.Cell{CircID: 7, Command: cell.CmdCreated2})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := mux.WaitCreated2(ctx, 7); err == nil {
		t.Fatal("late waiter must not see a CREATED2 that arrived before ExpectCreated2")
	}
}

func TestMuxCloseIdempotent(t *testing.T) {
	mux := NewCellMux(stubMuxConn{}, nil)
	mux.Close()
	mux.Close()
}
