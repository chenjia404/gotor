// Package onion — HS 描述符密封（双层加密 + type-8/9/0B 证书）。
package onion

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"time"

	"golang.org/x/crypto/curve25519"
)

// buildEd25519Cert 构造 proposal-220 证书（可选 signed-with-ed25519-key 扩展）。
func buildEd25519Cert(certType byte, certifiedKey ed25519.PublicKey, signer ed25519.PrivateKey, expires time.Time, includeSigningExt bool) ([]byte, error) {
	if len(certifiedKey) != 32 {
		return nil, fmt.Errorf("certified key must be 32 bytes")
	}
	hours := expires.Unix() / 3600
	if hours < 0 {
		hours = 0
	}
	if hours > 0xffffffff {
		hours = 0xffffffff
	}

	body := make([]byte, 0, 104)
	body = append(body, 1)        // version
	body = append(body, certType) // cert_type
	var exp [4]byte
	binary.BigEndian.PutUint32(exp[:], uint32(hours)) // #nosec G115
	body = append(body, exp[:]...)
	body = append(body, 1) // Ed25519 key type
	body = append(body, certifiedKey...)

	if includeSigningExt {
		pub := signer.Public().(ed25519.PublicKey)
		body = append(body, 1) // n_extensions
		var extLen [2]byte
		binary.BigEndian.PutUint16(extLen[:], 32)
		body = append(body, extLen[:]...)
		body = append(body, 0x04) // ExtTypeSignedWithEd25519Key
		body = append(body, 0x00) // flags
		body = append(body, pub...)
	} else {
		body = append(body, 0)
	}

	sig := ed25519.Sign(signer, body)
	out := make([]byte, 0, len(body)+64)
	out = append(out, body...)
	out = append(out, sig...)
	return out, nil
}

func writeEd25519CertArmor(buf *bytes.Buffer, cert []byte) {
	fmt.Fprintf(buf, "-----BEGIN ED25519 CERT-----\n")
	writeB64Lines(buf, cert)
	fmt.Fprintf(buf, "-----END ED25519 CERT-----\n")
}

// encodeIntroPointsPlaintext 编码第二层明文（含 create2-formats 与合法 auth-key/enc-key-cert）。
func encodeIntroPointsPlaintext(intros []IntroductionPoint, descSigningPriv ed25519.PrivateKey, expires time.Time) ([]byte, error) {
	var out bytes.Buffer
	fmt.Fprintf(&out, "create2-formats 2 3\n")

	for _, intro := range intros {
		lsCombined := make([]byte, 0, 64)
		nSpec := len(intro.LinkSpecifiers)
		if nSpec > 255 {
			nSpec = 255
		}
		lsCombined = append(lsCombined, byte(nSpec)) // #nosec G115
		for i, ls := range intro.LinkSpecifiers {
			if i >= nSpec {
				break
			}
			dlen := len(ls.Data)
			if dlen > 255 {
				dlen = 255
			}
			lsCombined = append(lsCombined, ls.Type, byte(dlen)) // #nosec G115
			lsCombined = append(lsCombined, ls.Data[:dlen]...)
		}
		fmt.Fprintf(&out, "introduction-point %s\n", base64.RawStdEncoding.EncodeToString(lsCombined))
		if len(intro.OnionKey) > 0 {
			fmt.Fprintf(&out, "onion-key ntor %s\n", base64.RawStdEncoding.EncodeToString(intro.OnionKey))
		}

		authPub := intro.AuthKey
		if len(authPub) == 32 {
			// type 09：引言点认证公钥由描述符签名密钥签发
			cert, err := buildEd25519Cert(0x09, ed25519.PublicKey(authPub), descSigningPriv, expires, true)
			if err != nil {
				return nil, fmt.Errorf("auth-key cert: %w", err)
			}
			fmt.Fprintf(&out, "auth-key\n")
			writeEd25519CertArmor(&out, cert)
		}

		if len(intro.EncKey) > 0 {
			fmt.Fprintf(&out, "enc-key ntor %s\n", base64.RawStdEncoding.EncodeToString(intro.EncKey))
			// type 0B：用描述符签名密钥签发「enc 公钥的 ed25519 等价」；无完整 prop228 时用 AuthKey 占位避免客户端丢字段
			subj := intro.AuthKey
			if len(subj) != 32 {
				subj = make([]byte, 32)
				copy(subj, intro.EncKey)
			}
			encCert, err := buildEd25519Cert(0x0B, ed25519.PublicKey(subj), descSigningPriv, expires, true)
			if err != nil {
				return nil, fmt.Errorf("enc-key-cert: %w", err)
			}
			fmt.Fprintf(&out, "enc-key-cert\n")
			writeEd25519CertArmor(&out, encCert)
		}
	}
	return out.Bytes(), nil
}

// SealDescriptorLayers 构建 outer（desc-auth + encrypted）→ superencrypted。
func SealDescriptorLayers(blinded, subcred []byte, revision uint64, introPlain []byte) (superBlob []byte, err error) {
	innerCT, err := encryptHSDescLayer(blinded, subcred, revision, "hsdir-encrypted-data", introPlain)
	if err != nil {
		return nil, fmt.Errorf("encrypt inner: %w", err)
	}

	// 第一层明文：desc-auth-* + encrypted MESSAGE
	ephemeral := make([]byte, 32)
	if _, err := rand.Read(ephemeral); err != nil {
		return nil, err
	}
	// 发布为 X25519 公钥
	ephemPub, err := curve25519.X25519(ephemeral, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	var mid bytes.Buffer
	fmt.Fprintf(&mid, "desc-auth-type x25519\n")
	fmt.Fprintf(&mid, "desc-auth-ephemeral-key %s\n", base64.RawStdEncoding.EncodeToString(ephemPub))
	fmt.Fprintf(&mid, "encrypted\n-----BEGIN MESSAGE-----\n")
	writeB64Lines(&mid, innerCT)
	fmt.Fprintf(&mid, "-----END MESSAGE-----\n")

	superBlob, err = encryptHSDescLayer(blinded, subcred, revision, "hsdir-superencrypted-data", mid.Bytes())
	if err != nil {
		return nil, fmt.Errorf("encrypt outer: %w", err)
	}
	return superBlob, nil
}

func writeB64Lines(buf *bytes.Buffer, data []byte) {
	b64 := base64.StdEncoding.EncodeToString(data)
	for i := 0; i < len(b64); i += 64 {
		end := i + 64
		if end > len(b64) {
			end = len(b64)
		}
		fmt.Fprintf(buf, "%s\n", b64[i:end])
	}
}

// buildType8SigningKeyCert 构造 type=8（BLINDED_ID_V_SIGNING）证书并由致盲密钥签名。
func buildType8SigningKeyCert(blinded *BlindedSigningMaterial, signingPub ed25519.PublicKey, expires time.Time) ([]byte, error) {
	certContent := make([]byte, 0, 40)
	certContent = append(certContent, 1)
	certContent = append(certContent, 8)
	hours := expires.Unix() / 3600
	if hours < 0 {
		hours = 0
	}
	if hours > 0xffffffff {
		hours = 0xffffffff
	}
	var expiry [4]byte
	binary.BigEndian.PutUint32(expiry[:], uint32(hours)) // #nosec G115
	certContent = append(certContent, expiry[:]...)
	certContent = append(certContent, 1)
	certContent = append(certContent, signingPub...)
	certContent = append(certContent, 0)
	sig, err := blinded.Sign(certContent)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(certContent)+64)
	out = append(out, certContent...)
	out = append(out, sig...)
	return out, nil
}
