// Package relay — 服务端电路加密状态（出口/末端跳）。
package relay

import (
	"crypto/cipher"
	"crypto/sha1" // #nosec G505 — Tor1 摘要
	"fmt"
	"hash"
	"sync"

	"github.com/opd-ai/go-tor/pkg/crypto"
)

// circuitCrypto 持有单跳服务端加解密状态。
// 客户端→中继用 Kf/Df；中继→客户端用 Kb/Db。
type circuitCrypto struct {
	mu        sync.Mutex
	fwdCipher cipher.Stream // 解密入站（Kf）
	bwdCipher cipher.Stream // 加密出站（Kb）
	fwdDigest hash.Hash     // Df
	bwdDigest hash.Hash     // Db
}

func newCircuitCrypto(keyMaterial []byte) (*circuitCrypto, error) {
	if len(keyMaterial) < 72 {
		return nil, fmt.Errorf("key material too short: %d", len(keyMaterial))
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

// peelInbound 始终推进 AES；仅当 recognized+digest 匹配时提交 digest。
// forUs 表示本跳应处理该继电器单元。
func (cc *circuitCrypto) peelInbound(payload []byte) (peeled []byte, forUs bool, digest []byte, err error) {
	if cc == nil || len(payload) != 509 {
		return nil, false, nil, fmt.Errorf("invalid inbound payload")
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.peelInboundLocked(payload)
}

func (cc *circuitCrypto) peelInboundLocked(payload []byte) (peeled []byte, forUs bool, digest []byte, err error) {
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

// decryptInbound 解密且要求本跳识别（出口/末端）。
func (cc *circuitCrypto) decryptInbound(payload []byte) (plain []byte, digest []byte, err error) {
	if cc == nil || len(payload) != 509 {
		return nil, nil, fmt.Errorf("invalid inbound payload")
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	peeled, forUs, digest, err := cc.peelInboundLocked(payload)
	if err != nil {
		return nil, nil, err
	}
	if !forUs {
		if peeled != nil && (peeled[1] != 0 || peeled[2] != 0) {
			return nil, nil, fmt.Errorf("relay cell not recognized")
		}
		return nil, nil, fmt.Errorf("relay digest mismatch")
	}
	return peeled, digest, nil
}

// encryptOutbound 加密发往客户端的明文 509 字节 payload（填 digest）。
func (cc *circuitCrypto) encryptOutbound(payload []byte) ([]byte, error) {
	if cc == nil || len(payload) != 509 {
		return nil, fmt.Errorf("invalid outbound payload")
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()

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
