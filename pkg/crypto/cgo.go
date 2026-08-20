package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"fmt"
)

// CGO（Counter Galois Onion，proposal 359 / C Tor relay_crypto_cgo.c）。
//
// C Tor 生产路径 CGO_AES_BITS=128（与论文、官方向量一致），不是 AES-256。
// 每方向密钥：UIV(64) || N(16) = 80 字节；双向共 160 字节。
// 客户端只用 DEC_UIV；中继用 ENC_UIV。二者不可对调。

const (
	CGOMsgLen         = 509
	CGOBlkLen         = 16
	CGOTagLen         = 16
	CGOPayloadLen     = CGOMsgLen - CGOBlkLen   // 493
	CGOHLen           = CGOBlkLen + 1           // T' || AD
	CGOETTweakLen     = CGOHLen + CGOPayloadLen // 510
	CGOETKeyLen       = 32                      // AES-128 + POLYVAL
	CGOPRFKeyLen      = 32
	CGOUIVKeyLen      = CGOETKeyLen + CGOPRFKeyLen // 64
	CGODirKeyLen      = CGOUIVKeyLen + CGOBlkLen   // 80
	CGOKeyMaterialLen = CGODirKeyLen * 2           // 160
	CGOPRFOffsetC     = 31
	cgoPRFMask        = 0xC0
)

// CGODir 是一个方向上的 CGO 状态（K, N, T'）。
type CGODir struct {
	etKB     []byte // AES-128 key
	etKU     []byte // POLYVAL key
	prfK     []byte // AES-CTR key
	prfB     []byte // POLYVAL key
	etBlock  cipher.Block
	prfBlock cipher.Block
	nonce    [CGOBlkLen]byte
	tprime   [CGOBlkLen]byte
	decrypt  bool // 客户端为 true（DEC_UIV）；中继为 false（ENC_UIV）
}

// CGOPair 是一跳的前向 + 后向 CGO。客户端两向都走 DEC_UIV。
type CGOPair struct {
	Fwd  *CGODir
	Back *CGODir
}

// NewCGOPairFromKeyMaterial 从 ntor-v3 KDF 的 160 字节建立客户端 CGO。
// 布局对照 C Tor cgo_pair_init(is_relay=false)：
//
//	fwd: keys[0:80]   UIV || N
//	back: keys[80:160] UIV || N
func NewCGOPairFromKeyMaterial(keys []byte) (*CGOPair, error) {
	if len(keys) != CGOKeyMaterialLen {
		return nil, fmt.Errorf("CGO key material length %d, want %d", len(keys), CGOKeyMaterialLen)
	}
	fwd, err := newCGODir(keys[:CGODirKeyLen], true)
	if err != nil {
		return nil, err
	}
	back, err := newCGODir(keys[CGODirKeyLen:], true)
	if err != nil {
		return nil, err
	}
	return &CGOPair{Fwd: fwd, Back: back}, nil
}

// NewCGORelayPairFromKeyMaterial 从同一 160 字节建立中继 CGO（ENC_UIV）。
// 布局与客户端相同；decrypt=false。二者不可对调。
func NewCGORelayPairFromKeyMaterial(keys []byte) (*CGOPair, error) {
	if len(keys) != CGOKeyMaterialLen {
		return nil, fmt.Errorf("CGO key material length %d, want %d", len(keys), CGOKeyMaterialLen)
	}
	fwd, err := newCGODir(keys[:CGODirKeyLen], false)
	if err != nil {
		return nil, err
	}
	back, err := newCGODir(keys[CGODirKeyLen:], false)
	if err != nil {
		return nil, err
	}
	return &CGOPair{Fwd: fwd, Back: back}, nil
}

func newCGODir(keys []byte, decrypt bool) (*CGODir, error) {
	if len(keys) != CGODirKeyLen {
		return nil, fmt.Errorf("CGO direction key length %d, want %d", len(keys), CGODirKeyLen)
	}
	d := &CGODir{
		etKB:    append([]byte(nil), keys[0:16]...),
		etKU:    append([]byte(nil), keys[16:32]...),
		prfK:    append([]byte(nil), keys[32:48]...),
		prfB:    append([]byte(nil), keys[48:64]...),
		decrypt: decrypt,
	}
	copy(d.nonce[:], keys[64:80])
	if err := d.refreshCiphers(); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *CGODir) ensureET() error {
	if d.etBlock != nil {
		return nil
	}
	b, err := aes.NewCipher(d.etKB)
	if err != nil {
		return err
	}
	d.etBlock = b
	return nil
}

func (d *CGODir) ensurePRF() error {
	if d.prfBlock != nil {
		return nil
	}
	b, err := aes.NewCipher(d.prfK)
	if err != nil {
		return err
	}
	d.prfBlock = b
	return nil
}

func (d *CGODir) refreshCiphers() error {
	d.etBlock = nil
	d.prfBlock = nil
	if err := d.ensureET(); err != nil {
		return err
	}
	return d.ensurePRF()
}

func (d *CGODir) snapshotKeys() []byte {
	out := make([]byte, CGOUIVKeyLen)
	copy(out[0:16], d.etKB)
	copy(out[16:32], d.etKU)
	copy(out[32:48], d.prfK)
	copy(out[48:64], d.prfB)
	return out
}

func (d *CGODir) loadKeys(keys []byte) {
	copy(d.etKB, keys[0:16])
	copy(d.etKU, keys[16:32])
	copy(d.prfK, keys[32:48])
	copy(d.prfB, keys[48:64])
	_ = d.refreshCiphers()
}

// encET / decET 是 LRW2 可调分组密码。tweak = T' || AD || X_R（510 字节）。
func (d *CGODir) etMask(tprime [CGOBlkLen]byte, ad byte, xr []byte) [16]byte {
	tweak := make([]byte, CGOETTweakLen)
	copy(tweak[:16], tprime[:])
	tweak[16] = ad
	copy(tweak[17:], xr)
	return polyval(d.etKU, tweak)
}

func xor16(dst, a, b *[16]byte) {
	for i := 0; i < 16; i++ {
		dst[i] = a[i] ^ b[i]
	}
}

func (d *CGODir) aesBlock(encrypt bool, block *[16]byte) error {
	if err := d.ensureET(); err != nil {
		return err
	}
	if encrypt {
		d.etBlock.Encrypt(block[:], block[:])
	} else {
		d.etBlock.Decrypt(block[:], block[:])
	}
	return nil
}

func (d *CGODir) encET(tprime [CGOBlkLen]byte, ad byte, xr []byte, m *[16]byte) error {
	mask := d.etMask(tprime, ad, xr)
	xor16(m, m, &mask)
	if err := d.aesBlock(true, m); err != nil {
		return err
	}
	xor16(m, m, &mask)
	return nil
}

func (d *CGODir) decET(tprime [CGOBlkLen]byte, ad byte, xr []byte, m *[16]byte) error {
	mask := d.etMask(tprime, ad, xr)
	xor16(m, m, &mask)
	if err := d.aesBlock(false, m); err != nil {
		return err
	}
	xor16(m, m, &mask)
	return nil
}

func (d *CGODir) prfCTR(t [16]byte, bit byte, n int) ([]byte, error) {
	h := polyval(d.prfB, t[:])
	h[15] &= cgoPRFMask
	if bit != 0 {
		h[15] += CGOPRFOffsetC
	}
	if err := d.ensurePRF(); err != nil {
		return nil, err
	}
	out := make([]byte, n)
	cipher.NewCTR(d.prfBlock, h[:]).XORKeyStream(out, out)
	return out, nil
}

func (d *CGODir) prfXOR0(yl [16]byte, xr []byte) error {
	ks, err := d.prfCTR(yl, 0, CGOPayloadLen)
	if err != nil {
		return err
	}
	for i := range xr {
		xr[i] ^= ks[i]
	}
	return nil
}

func (d *CGODir) updateUIV() error {
	ks, err := d.prfCTR(d.nonce, 1, CGOUIVKeyLen+CGOBlkLen)
	if err != nil {
		return err
	}
	d.loadKeys(ks[:CGOUIVKeyLen])
	copy(d.nonce[:], ks[CGOUIVKeyLen:])
	return nil
}

func (d *CGODir) encUIV(ad byte, cell []byte) error {
	if len(cell) != CGOMsgLen {
		return fmt.Errorf("CGO cell length %d, want %d", len(cell), CGOMsgLen)
	}
	var xl [16]byte
	copy(xl[:], cell[:16])
	xr := cell[16:]
	if err := d.encET(d.tprime, ad, xr, &xl); err != nil {
		return err
	}
	copy(cell[:16], xl[:])
	return d.prfXOR0(xl, xr)
}

func (d *CGODir) decUIV(ad byte, cell []byte) error {
	if len(cell) != CGOMsgLen {
		return fmt.Errorf("CGO cell length %d, want %d", len(cell), CGOMsgLen)
	}
	var yl [16]byte
	copy(yl[:], cell[:16])
	xr := cell[16:]
	if err := d.prfXOR0(yl, xr); err != nil {
		return err
	}
	if err := d.decET(d.tprime, ad, xr, &yl); err != nil {
		return err
	}
	copy(cell[:16], yl[:])
	return nil
}

// ClientForward 是客户端对非目的跳的前向处理（ENC_OP_MID / DEC_UIV）。
func (d *CGODir) ClientForward(ad byte, cell []byte) error {
	var tIn [CGOBlkLen]byte
	copy(tIn[:], cell[:CGOBlkLen])
	if err := d.decUIV(ad, cell); err != nil {
		return err
	}
	d.tprime = tIn
	return nil
}

// ClientOriginate 在目的跳发出一条消息：payload[0:16] 填 N，然后 ClientForward + UPDATE。
// 返回处理后的 tag T（SENDME 用）。cell 必须已是 509 字节，且 [16:] 已放好 v1 明文。
func (d *CGODir) ClientOriginate(ad byte, cell []byte) ([]byte, error) {
	if len(cell) != CGOMsgLen {
		return nil, fmt.Errorf("CGO cell length %d, want %d", len(cell), CGOMsgLen)
	}
	copy(cell[:CGOBlkLen], d.nonce[:])
	if err := d.ClientForward(ad, cell); err != nil {
		return nil, err
	}
	if err := d.updateUIV(); err != nil {
		return nil, err
	}
	tag := append([]byte(nil), cell[:CGOBlkLen]...)
	return tag, nil
}

// ClientBackward 处理入站 cell。recognized 时 tag 是 16 字节 SENDME 标签。
func (d *CGODir) ClientBackward(ad byte, cell []byte) (recognized bool, tag []byte, err error) {
	if len(cell) != CGOMsgLen {
		return false, nil, fmt.Errorf("CGO cell length %d, want %d", len(cell), CGOMsgLen)
	}
	var tOrig [CGOBlkLen]byte
	copy(tOrig[:], cell[:CGOBlkLen])
	if err := d.decUIV(ad, cell); err != nil {
		return false, nil, err
	}
	d.tprime = tOrig
	if subtle.ConstantTimeCompare(cell[:CGOBlkLen], d.nonce[:]) == 1 {
		copy(d.nonce[:], tOrig[:])
		if err := d.updateUIV(); err != nil {
			return false, nil, err
		}
		return true, append([]byte(nil), d.tprime[:]...), nil
	}
	return false, nil, nil
}

// RelayForward 是中继出站处理（ENC_UIV）。测试与向量用。
func (d *CGODir) RelayForward(ad byte, cell []byte) (recognized bool, tag []byte, err error) {
	if len(cell) != CGOMsgLen {
		return false, nil, fmt.Errorf("CGO cell length %d, want %d", len(cell), CGOMsgLen)
	}
	var lastTag [CGOBlkLen]byte
	copy(lastTag[:], cell[:CGOBlkLen])
	if err := d.encUIV(ad, cell); err != nil {
		return false, nil, err
	}
	copy(d.tprime[:], cell[:CGOBlkLen])
	if subtle.ConstantTimeCompare(cell[:CGOBlkLen], d.nonce[:]) == 1 {
		if err := d.updateUIV(); err != nil {
			return false, nil, err
		}
		return true, append([]byte(nil), lastTag[:]...), nil
	}
	return false, nil, nil
}

// RelayBackward 是中继入站转发（ENC_UIV，不识别）。
func (d *CGODir) RelayBackward(ad byte, cell []byte) error {
	if err := d.encUIV(ad, cell); err != nil {
		return err
	}
	copy(d.tprime[:], cell[:CGOBlkLen])
	return nil
}

// RelayOriginate 中继发出入站消息（ENC_OR）。
func (d *CGODir) RelayOriginate(ad byte, cell []byte) ([]byte, error) {
	if len(cell) != CGOMsgLen {
		return nil, fmt.Errorf("CGO cell length %d, want %d", len(cell), CGOMsgLen)
	}
	copy(cell[:CGOBlkLen], d.nonce[:])
	if err := d.encUIV(ad, cell); err != nil {
		return nil, err
	}
	copy(d.tprime[:], cell[:CGOBlkLen])
	copy(d.nonce[:], cell[:CGOBlkLen])
	tag := append([]byte(nil), d.tprime[:]...)
	if err := d.updateUIV(); err != nil {
		return nil, err
	}
	return tag, nil
}

// ClientOriginateHops 对 hops[0..n) 做 ENC_OP，dest 为 0-based 目的跳。
func ClientOriginateHops(hops []*CGODir, dest int, ad byte, cell []byte) ([]byte, error) {
	if dest < 0 || dest >= len(hops) {
		return nil, fmt.Errorf("CGO dest hop %d out of range", dest)
	}
	tag, err := hops[dest].ClientOriginate(ad, cell)
	if err != nil {
		return nil, err
	}
	for i := dest - 1; i >= 0; i-- {
		if err := hops[i].ClientForward(ad, cell); err != nil {
			return nil, err
		}
	}
	return tag, nil
}

// ClientDecryptHops 对 hops 做 DEC_OP_INNER。返回识别到的 hop 下标与 SENDME tag。
func ClientDecryptHops(hops []*CGODir, ad byte, cell []byte) (hop int, tag []byte, err error) {
	for i, h := range hops {
		rec, t, err := h.ClientBackward(ad, cell)
		if err != nil {
			return -1, nil, err
		}
		if rec {
			return i, t, nil
		}
	}
	return -1, nil, fmt.Errorf("CGO inbound cell not recognized")
}

// newCGODirForTest 用显式 K/N/T' 构造（官方向量）。
func newCGODirForTest(uivKeys, nonce, tprime []byte, decrypt bool) (*CGODir, error) {
	if len(uivKeys) != CGOUIVKeyLen || len(nonce) != CGOBlkLen || len(tprime) != CGOBlkLen {
		return nil, fmt.Errorf("CGO test state length")
	}
	keys := make([]byte, CGODirKeyLen)
	copy(keys[:CGOUIVKeyLen], uivKeys)
	copy(keys[CGOUIVKeyLen:], nonce)
	d, err := newCGODir(keys, decrypt)
	if err != nil {
		return nil, err
	}
	copy(d.tprime[:], tprime)
	return d, nil
}
