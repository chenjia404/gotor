package protocol

// type7IdentityCertificate 构造仅含 Ed25519 身份公钥的 type 7 条目。
// type 4 的 CertifiedKey 是 signing key，不能当作 identity。
func type7IdentityCertificate(identity []byte) *Certificate {
	key := append([]byte(nil), identity...)
	return &Certificate{
		CertType: CertTypeEd25519Identity,
		Ed25519Cert: &Ed25519Certificate{
			CertType:     7,
			CertifiedKey: key,
		},
	}
}
