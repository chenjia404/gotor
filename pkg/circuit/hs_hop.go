package circuit

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/opd-ai/go-tor/pkg/crypto"
	"golang.org/x/crypto/sha3"
)

// NewHopFromHSKeyMaterial 从 hs-ntor 展开的 128 字节密钥材料构造会合末跳。
// 布局：Df(32) || Db(32) || Kf(32) || Kb(32)；摘要为 SHA3-256，密码为 AES-256-CTR。
func NewHopFromHSKeyMaterial(keyMaterial []byte) (*Hop, error) {
	if len(keyMaterial) < crypto.HsNtorCircuitKeyLen {
		return nil, fmt.Errorf("HS key material too short: %d", len(keyMaterial))
	}
	df := keyMaterial[0:32]
	db := keyMaterial[32:64]
	kf := keyMaterial[64:96]
	kb := keyMaterial[96:128]

	fwdBlock, err := aes.NewCipher(kf)
	if err != nil {
		return nil, fmt.Errorf("AES-256 forward: %w", err)
	}
	bwdBlock, err := aes.NewCipher(kb)
	if err != nil {
		return nil, fmt.Errorf("AES-256 backward: %w", err)
	}
	// rend-spec：会合层 AES-CTR 用全零 IV，Kf/Kb 由 hs-ntor 派生且每条电路唯一。
	ivFwd := make([]byte, aes.BlockSize)
	ivBwd := make([]byte, aes.BlockSize)
	fwd := cipher.NewCTR(fwdBlock, ivFwd) // #nosec G407
	bwd := cipher.NewCTR(bwdBlock, ivBwd) // #nosec G407

	fwdDig := sha3.New256()
	_, _ = fwdDig.Write(df)
	bwdDig := sha3.New256()
	_, _ = bwdDig.Write(db)

	return &Hop{
		Fingerprint:    "hs-rendezvous",
		IsExit:         true,
		ForwardCipher:  fwd,
		BackwardCipher: bwd,
		ForwardDigest:  fwdDig,
		BackwardDigest: bwdDig,
	}, nil
}

// NewHopFromHSKeyMaterialResponder 服务端会合末跳：与客户端方向对调（Kf/Df 为入站，Kb/Db 为出站）。
func NewHopFromHSKeyMaterialResponder(keyMaterial []byte) (*Hop, error) {
	hop, err := NewHopFromHSKeyMaterial(keyMaterial)
	if err != nil {
		return nil, err
	}
	hop.ForwardCipher, hop.BackwardCipher = hop.BackwardCipher, hop.ForwardCipher
	hop.ForwardDigest, hop.BackwardDigest = hop.BackwardDigest, hop.ForwardDigest
	return hop, nil
}
