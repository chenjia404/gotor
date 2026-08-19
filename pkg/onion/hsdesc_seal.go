// Package onion — HS 描述符密封（双层加密 + type-8 证书）。
package onion

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"time"
)

// encodeIntroPointsPlaintext 将引言点编码为加密层内明文。
func encodeIntroPointsPlaintext(intros []IntroductionPoint) []byte {
	var out bytes.Buffer
	for _, intro := range intros {
		lsCombined := make([]byte, 0, 64)
		nSpec := len(intro.LinkSpecifiers)
		if nSpec > 255 {
			nSpec = 255
		}
		lsCombined = append(lsCombined, byte(nSpec)) // #nosec G115 -- LSTYPE 规范为 1 字节计数
		for i, ls := range intro.LinkSpecifiers {
			if i >= nSpec {
				break
			}
			dlen := len(ls.Data)
			if dlen > 255 {
				dlen = 255
			}
			lsCombined = append(lsCombined, ls.Type, byte(dlen)) // #nosec G115 -- LSLEN 为 1 字节
			lsCombined = append(lsCombined, ls.Data[:dlen]...)
		}
		fmt.Fprintf(&out, "introduction-point %s\n", base64.RawStdEncoding.EncodeToString(lsCombined))
		if len(intro.OnionKey) > 0 {
			fmt.Fprintf(&out, "onion-key ntor %s\n", base64.RawStdEncoding.EncodeToString(intro.OnionKey))
		}
		if len(intro.AuthKey) > 0 {
			fmt.Fprintf(&out, "auth-key\n-----BEGIN ED25519 CERT-----\n")
			b64 := base64.StdEncoding.EncodeToString(intro.AuthKey)
			for i := 0; i < len(b64); i += 64 {
				end := i + 64
				if end > len(b64) {
					end = len(b64)
				}
				fmt.Fprintf(&out, "%s\n", b64[i:end])
			}
			fmt.Fprintf(&out, "-----END ED25519 CERT-----\n")
		}
		if len(intro.EncKey) > 0 {
			fmt.Fprintf(&out, "enc-key ntor %s\n", base64.RawStdEncoding.EncodeToString(intro.EncKey))
		}
	}
	return out.Bytes()
}

// SealDescriptorLayers 构建 encrypted → superencrypted 双层密文。
func SealDescriptorLayers(blinded, subcred []byte, revision uint64, introPlain []byte) (superBlob []byte, err error) {
	innerCT, err := encryptHSDescLayer(blinded, subcred, revision, "hsdir-encrypted-data", introPlain)
	if err != nil {
		return nil, fmt.Errorf("encrypt inner: %w", err)
	}
	var mid bytes.Buffer
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
	certContent = append(certContent, 1) // version
	certContent = append(certContent, 8) // cert_type = BLINDED_ID_V_SIGNING
	var expiry [4]byte
	hours := expires.Unix() / 3600
	if hours < 0 {
		hours = 0
	}
	if hours > 0xffffffff {
		hours = 0xffffffff
	}
	binary.BigEndian.PutUint32(expiry[:], uint32(hours)) // #nosec G115 -- cert-spec 到期为 uint32 小时
	certContent = append(certContent, expiry[:]...)
	certContent = append(certContent, 1) // Ed25519 key type
	certContent = append(certContent, signingPub...)
	certContent = append(certContent, 0) // n_extensions
	sig, err := blinded.Sign(certContent)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(certContent)+64)
	out = append(out, certContent...)
	out = append(out, sig...)
	return out, nil
}
