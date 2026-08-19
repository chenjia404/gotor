package circuit

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/opd-ai/go-tor/pkg/crypto"
)

func (h *Hop) usesCGO() bool {
	return h != nil && h.CGO != nil
}

// encryptOnion 从 dest 跳 originate，再向外层 hop 包一层。
// ad 是链路命令 RELAY(3) 或 RELAY_EARLY(9)。
func (c *Circuit) encryptOnion(ad byte, dest int, payload []byte) ([]byte, []byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if dest < 0 || dest >= len(c.Hops) {
		return nil, nil, fmt.Errorf("onion dest hop %d out of range", dest)
	}
	out := append([]byte(nil), payload...)
	destHop := c.Hops[dest]
	var tag []byte
	if destHop.usesCGO() {
		if len(out) != crypto.CGOMsgLen {
			return nil, nil, fmt.Errorf("CGO payload length %d", len(out))
		}
		t, err := destHop.CGO.Fwd.ClientOriginate(ad, out)
		if err != nil {
			return nil, nil, err
		}
		tag = t
	} else {
		if destHop.ForwardDigest != nil && len(out) >= 9 {
			cellCopy := append([]byte(nil), out...)
			cellCopy[5], cellCopy[6], cellCopy[7], cellCopy[8] = 0, 0, 0, 0
			if _, err := destHop.ForwardDigest.Write(cellCopy); err != nil {
				return nil, nil, fmt.Errorf("forward digest: %w", err)
			}
			sum := destHop.ForwardDigest.Sum(nil)
			copy(out[5:9], sum[:4])
			tag = sum
		}
		if destHop.ForwardCipher != nil {
			destHop.ForwardCipher.XORKeyStream(out, out)
		}
	}
	for i := dest - 1; i >= 0; i-- {
		hop := c.Hops[i]
		if hop.usesCGO() {
			if err := hop.CGO.Fwd.ClientForward(ad, out); err != nil {
				return nil, nil, err
			}
			continue
		}
		if hop.ForwardCipher != nil {
			hop.ForwardCipher.XORKeyStream(out, out)
		}
	}
	return out, tag, nil
}

// decryptOnion 从 Guard 向 Exit 逐跳解开，在识别到的 hop 停下。
func (c *Circuit) decryptOnion(ad byte, payload []byte) (out []byte, hopIdx int, tag []byte, v1 bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out = append([]byte(nil), payload...)
	for i, hop := range c.Hops {
		if hop.usesCGO() {
			rec, t, err := hop.CGO.Back.ClientBackward(ad, out)
			if err != nil {
				return nil, -1, nil, false, err
			}
			if rec {
				return out, i, t, true, nil
			}
			continue
		}
		if hop.BackwardCipher != nil {
			hop.BackwardCipher.XORKeyStream(out, out)
		}
		if rec, t := tor1Recognized(hop, out); rec {
			return out, i, t, false, nil
		}
	}
	return out, -1, nil, false, nil
}

func tor1Recognized(hop *Hop, payload []byte) (bool, []byte) {
	if hop == nil || hop.BackwardDigest == nil || len(payload) < 11 {
		return false, nil
	}
	if binary.BigEndian.Uint16(payload[1:3]) != 0 {
		return false, nil
	}
	var cellDigest [4]byte
	copy(cellDigest[:], payload[5:9])
	cellCopy := append([]byte(nil), payload...)
	cellCopy[5], cellCopy[6], cellCopy[7], cellCopy[8] = 0, 0, 0, 0
	hashClone, err := crypto.CloneHash(hop.BackwardDigest)
	if err != nil {
		return false, nil
	}
	if _, err := hashClone.Write(cellCopy); err != nil {
		return false, nil
	}
	sum := hashClone.Sum(nil)
	expected := [4]byte{sum[0], sum[1], sum[2], sum[3]}
	if subtle.ConstantTimeCompare(expected[:], cellDigest[:]) != 1 {
		return false, nil
	}
	if _, err := hop.BackwardDigest.Write(cellCopy); err != nil {
		return false, nil
	}
	return true, sum
}
