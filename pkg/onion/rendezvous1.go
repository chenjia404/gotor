// Package onion - RENDEZVOUS1 Cell Construction
// Following rend-spec-v3.txt §3.3（hs-ntor，非电路 ntor）
package onion

import (
	"context"
	"fmt"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/crypto"
)

// Rendezvous1Cell represents a RENDEZVOUS1 cell to send to a rendezvous point
type Rendezvous1Cell struct {
	RendezvousCookie []byte // 20-byte cookie from INTRODUCE2
	HandshakeData    []byte // hs-ntor: Y || AUTH_INPUT_MAC (64 bytes)
}

// BuildRendezvous1Cell 构造洋葱服务侧 RENDEZVOUS1（hs-ntor）。
//
// 参数：
//   - rendezvousCookie: INTRODUCE2 中的 20 字节 cookie
//   - clientEphemeralX: 客户端 INTRODUCE 中的 X（32 字节）
//   - serviceNtorPriv: KP_hss_ntor 对应私钥 b（32 字节）
//   - introAuthKey: 引言点 AUTH_KEY（Ed25519 公钥，32 字节）
//   - serviceEphemeralYPriv: 服务端临时 y（32 字节）；若 nil 则现场生成
//
// 返回 relay cell、NTOR_KEY_SEED（32 字节）、error。
func BuildRendezvous1Cell(rendezvousCookie, clientEphemeralX, serviceNtorPriv, introAuthKey, serviceEphemeralYPriv []byte, circuitID uint32, streamID uint16) (*cell.RelayCell, []byte, error) {
	if len(rendezvousCookie) != 20 {
		return nil, nil, fmt.Errorf("invalid rendezvous cookie length: %d, expected 20", len(rendezvousCookie))
	}
	if len(clientEphemeralX) != 32 {
		return nil, nil, fmt.Errorf("invalid client ephemeral X length: %d, expected 32", len(clientEphemeralX))
	}
	if len(serviceNtorPriv) != 32 {
		return nil, nil, fmt.Errorf("invalid service ntor private key length: %d", len(serviceNtorPriv))
	}
	if len(introAuthKey) != 32 {
		return nil, nil, fmt.Errorf("invalid intro auth key length: %d, expected 32 (Ed25519)", len(introAuthKey))
	}

	yPriv := serviceEphemeralYPriv
	if yPriv == nil {
		var err error
		yPriv, err = crypto.GenerateCurve25519PrivateKey()
		if err != nil {
			return nil, nil, fmt.Errorf("generate ephemeral y: %w", err)
		}
	}
	if len(yPriv) != 32 {
		return nil, nil, fmt.Errorf("invalid ephemeral y length: %d", len(yPriv))
	}

	handshakeResponse, keySeed, err := crypto.HsNtorServiceRend(yPriv, serviceNtorPriv, clientEphemeralX, introAuthKey)
	if err != nil {
		return nil, nil, fmt.Errorf("hs-ntor service rend: %w", err)
	}

	payload := make([]byte, 20+64)
	copy(payload[0:20], rendezvousCookie)
	copy(payload[20:84], handshakeResponse)

	rendezvous1 := &cell.RelayCell{
		Command:  cell.RelayRendezvous1,
		StreamID: streamID,
		Data:     payload,
	}
	_ = circuitID // 由上层发送时设置 CircID
	return rendezvous1, keySeed, nil
}

// CircuitInterface abstracts circuit operations needed for onion service hosting.
type CircuitInterface interface {
	SendRelayCell(relayCell *cell.RelayCell) error
	ReceiveRelayCell(ctx context.Context) (*cell.RelayCell, error)
	GetID() uint32
}

// SendRendezvous1 在 rendezvous 电路上发送 RENDEZVOUS1。
func SendRendezvous1(circuit CircuitInterface, circuitID uint32, rendezvousCookie, clientEphemeralX, serviceNtorPriv, introAuthKey []byte) ([]byte, error) {
	if circuit == nil {
		return nil, fmt.Errorf("circuit is nil")
	}
	rendezvous1Cell, keySeed, err := BuildRendezvous1Cell(
		rendezvousCookie, clientEphemeralX, serviceNtorPriv, introAuthKey, nil, circuitID, 0,
	)
	if err != nil {
		return nil, err
	}
	if err := circuit.SendRelayCell(rendezvous1Cell); err != nil {
		return nil, fmt.Errorf("failed to send RENDEZVOUS1: %w", err)
	}
	return keySeed, nil
}
