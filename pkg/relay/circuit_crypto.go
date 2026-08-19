// Package relay — 服务端电路加密状态（出口/末端跳）。
package relay

import (
	"crypto/cipher"
	"crypto/sha1" // #nosec G505 — Tor1 摘要
	"fmt"
	"hash"

	"github.com/opd-ai/go-tor/pkg/crypto"
)

// circuitCrypto 持有单跳服务端加解密状态。
// 客户端→中继用 Kf/Df；中继→客户端用 Kb/Db。
type circuitCrypto struct {
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

// decryptInbound 解密客户端发来的 509 字节 RELAY payload，校验 recognized。
func (cc *circuitCrypto) decryptInbound(payload []byte) ([]byte, error) {
	if cc == nil || len(payload) != 509 {
		return nil, fmt.Errorf("invalid inbound payload")
	}
	out := append([]byte(nil), payload...)
	cc.fwdCipher.XORKeyStream(out, out)
	// recognized: bytes 1-2 of digest field (offset 5-6 in relay header) — tor1
	// 布局: cmd(1) recognized(2) streamID(2) digest(4) length(2) data...
	if out[1] != 0 || out[2] != 0 {
		return nil, fmt.Errorf("relay cell not recognized")
	}
	cellCopy := append([]byte(nil), out...)
	cellCopy[5], cellCopy[6], cellCopy[7], cellCopy[8] = 0, 0, 0, 0
	if _, err := cc.fwdDigest.Write(cellCopy); err != nil {
		return nil, err
	}
	sum := cc.fwdDigest.Sum(nil)
	if sum[0] != out[5] || sum[1] != out[6] || sum[2] != out[7] || sum[3] != out[8] {
		return nil, fmt.Errorf("relay digest mismatch")
	}
	return out, nil
}

// encryptOutbound 加密发往客户端的明文 509 字节 payload（填 digest）。
func (cc *circuitCrypto) encryptOutbound(payload []byte) ([]byte, error) {
	if cc == nil || len(payload) != 509 {
		return nil, fmt.Errorf("invalid outbound payload")
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
