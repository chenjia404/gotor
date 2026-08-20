// Package relay — 服务端电路加密状态（出口/末端跳）。
package relay

import (
	"crypto/cipher"
	"crypto/sha1" // #nosec G505 — Tor1 摘要
	"fmt"
	"hash"
	"sync"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/crypto"
)

// CGO 附加数据是链路命令：RELAY=3、RELAY_EARLY=9。
const (
	cgoADRelay      byte = 3
	cgoADRelayEarly byte = 9
)

// circuitCrypto 持有单跳服务端加解密状态。
// tor1：客户端→中继用 Kf/Df；中继→客户端用 Kb/Db。
// CGO：中继两向 ENC_UIV（与客户端 DEC_UIV 成对）。
type circuitCrypto struct {
	mu        sync.Mutex
	fwdCipher cipher.Stream // 解密入站（Kf）
	bwdCipher cipher.Stream // 加密出站（Kb）
	fwdDigest hash.Hash     // Df
	bwdDigest hash.Hash     // Db
	cgo       *crypto.CGOPair
}

func newCircuitCrypto(keyMaterial []byte) (*circuitCrypto, error) {
	switch len(keyMaterial) {
	case crypto.CGOKeyMaterialLen:
		pair, err := crypto.NewCGORelayPairFromKeyMaterial(keyMaterial)
		if err != nil {
			return nil, err
		}
		return &circuitCrypto{cgo: pair}, nil
	case 72:
	default:
		return nil, fmt.Errorf("key material length %d, want 72 (tor1) or %d (CGO)", len(keyMaterial), crypto.CGOKeyMaterialLen)
	}
	df := keyMaterial[0:20]
	db := keyMaterial[20:40]
	kf := keyMaterial[40:56]
	kb := keyMaterial[56:72]
	zeroIV := make([]byte, 16)
	fwdW, err := crypto.NewAESCTRCipher(kf, zeroIV)
	if err != nil {
		return nil, err
	}
	bwdW, err := crypto.NewAESCTRCipher(kb, zeroIV)
	if err != nil {
		return nil, err
	}
	fwdDig := sha1.New() // #nosec G401
	_, _ = fwdDig.Write(df)
	bwdDig := sha1.New() // #nosec G401
	_, _ = bwdDig.Write(db)
	return &circuitCrypto{
		fwdCipher: fwdW.Stream(),
		bwdCipher: bwdW.Stream(),
		fwdDigest: fwdDig,
		bwdDigest: bwdDig,
	}, nil
}

func (cc *circuitCrypto) usesCGO() bool {
	return cc != nil && cc.cgo != nil
}

func cgoAD(cmd cell.Command) byte {
	if cmd == cell.CmdRelayEarly {
		return cgoADRelayEarly
	}
	return cgoADRelay
}

// peelInbound 始终推进本跳密码；仅 recognized 时 forUs。
// 默认 AD=RELAY(3)。RELAY_EARLY 请用 peelInboundWithAD。
func (cc *circuitCrypto) peelInbound(payload []byte) (peeled []byte, forUs bool, digest []byte, err error) {
	return cc.peelInboundWithAD(payload, cgoADRelay)
}

func (cc *circuitCrypto) peelInboundWithAD(payload []byte, ad byte) (peeled []byte, forUs bool, digest []byte, err error) {
	if cc == nil || len(payload) != 509 {
		return nil, false, nil, fmt.Errorf("invalid inbound payload")
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.peelInboundLocked(payload, ad)
}

func (cc *circuitCrypto) peelInboundLocked(payload []byte, ad byte) (peeled []byte, forUs bool, digest []byte, err error) {
	if cc.cgo != nil {
		out := append([]byte(nil), payload...)
		rec, tag, err := cc.cgo.Fwd.RelayForward(ad, out)
		if err != nil {
			return nil, false, nil, err
		}
		return out, rec, tag, nil
	}
	out := append([]byte(nil), payload...)
	cc.fwdCipher.XORKeyStream(out, out)

	if out[1] != 0 || out[2] != 0 {
		return out, false, nil, nil
	}
	cellCopy := append([]byte(nil), out...)
	cellCopy[5], cellCopy[6], cellCopy[7], cellCopy[8] = 0, 0, 0, 0

	probe, err := crypto.CloneHash(cc.fwdDigest)
	if err != nil {
		return nil, false, nil, fmt.Errorf("clone digest: %w", err)
	}
	if _, err := probe.Write(cellCopy); err != nil {
		return nil, false, nil, err
	}
	sum := probe.Sum(nil)
	if sum[0] != out[5] || sum[1] != out[6] || sum[2] != out[7] || sum[3] != out[8] {
		return out, false, nil, nil
	}
	if _, err := cc.fwdDigest.Write(cellCopy); err != nil {
		return nil, false, nil, err
	}
	return out, true, sum, nil
}

// decryptInbound 解密且要求本跳识别（出口/末端）。默认 AD=RELAY(3)。
func (cc *circuitCrypto) decryptInbound(payload []byte) (plain []byte, digest []byte, err error) {
	return cc.decryptInboundWithAD(payload, cgoADRelay)
}

func (cc *circuitCrypto) decryptInboundWithAD(payload []byte, ad byte) (plain []byte, digest []byte, err error) {
	if cc == nil || len(payload) != 509 {
		return nil, nil, fmt.Errorf("invalid inbound payload")
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	peeled, forUs, digest, err := cc.peelInboundLocked(payload, ad)
	if err != nil {
		return nil, nil, err
	}
	if !forUs {
		if cc.cgo != nil {
			return nil, nil, fmt.Errorf("relay cell not recognized")
		}
		if peeled != nil && (peeled[1] != 0 || peeled[2] != 0) {
			return nil, nil, fmt.Errorf("relay cell not recognized")
		}
		return nil, nil, fmt.Errorf("relay digest mismatch")
	}
	return peeled, digest, nil
}

// encryptOutbound 本跳发出一条消息（填 digest / CGO originate）。AD=RELAY(3)。
func (cc *circuitCrypto) encryptOutbound(payload []byte) ([]byte, error) {
	if cc == nil || len(payload) != 509 {
		return nil, fmt.Errorf("invalid outbound payload")
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if cc.cgo != nil {
		out := append([]byte(nil), payload...)
		if _, err := cc.cgo.Back.RelayOriginate(cgoADRelay, out); err != nil {
			return nil, err
		}
		return out, nil
	}

	out := append([]byte(nil), payload...)
	out[1], out[2] = 0, 0
	out[5], out[6], out[7], out[8] = 0, 0, 0, 0
	cellCopy := append([]byte(nil), out...)
	if _, err := cc.bwdDigest.Write(cellCopy); err != nil {
		return nil, err
	}
	sum := cc.bwdDigest.Sum(nil)
	copy(out[5:9], sum[:4])
	cc.bwdCipher.XORKeyStream(out, out)
	return out, nil
}

// wrapOutbound 中间跳回程只加一层，不 originate（不改 nonce / digest）。
func (cc *circuitCrypto) wrapOutbound(payload []byte, ad byte) ([]byte, error) {
	if cc == nil || len(payload) != 509 {
		return nil, fmt.Errorf("invalid outbound payload")
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()

	out := append([]byte(nil), payload...)
	if cc.cgo != nil {
		if err := cc.cgo.Back.RelayBackward(ad, out); err != nil {
			return nil, err
		}
		return out, nil
	}
	cc.bwdCipher.XORKeyStream(out, out)
	return out, nil
}

func (cc *circuitCrypto) decodeRelay(peeled []byte) (*cell.RelayCell, error) {
	if cc.usesCGO() {
		return cell.DecodeRelayCellV1(peeled)
	}
	return cell.DecodeRelayCell(peeled)
}

func (cc *circuitCrypto) originateRelay(rc *cell.RelayCell) ([]byte, error) {
	if cc == nil || rc == nil {
		return nil, fmt.Errorf("nil circuit crypto or relay cell")
	}
	var plain []byte
	var err error
	if cc.usesCGO() {
		plain, err = cell.EncodeRelayCellV1(rc)
	} else {
		plain, err = rc.Encode()
		if err == nil && len(plain) != 509 {
			pad := make([]byte, 509)
			copy(pad, plain)
			plain = pad
		}
	}
	if err != nil {
		return nil, err
	}
	return cc.encryptOutbound(plain)
}
