// Package relay implements Tor relay (bridge/non-exit) functionality.
package relay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 - SHA1 required by Tor protocol
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/opd-ai/go-tor/pkg/crypto"
	"github.com/opd-ai/go-tor/pkg/protocol"
	"golang.org/x/crypto/curve25519"
)

// ServerDescriptor represents a Tor relay server descriptor
// Per dir-spec.txt §2.1, server descriptors advertise a relay's capabilities
type ServerDescriptor struct {
	// Metadata
	Nickname       string    // Relay nickname (1-19 alphanumeric characters)
	Address        string    // IPv4 address
	ORPort         uint16    // OR protocol port
	DirPort        uint16    // Directory port (0 for bridges)
	Platform       string    // Platform information (e.g., "Tor 0.4.8.0 on Linux")
	PublishedTime  time.Time // Descriptor publication time
	Uptime         int       // Relay uptime in seconds
	BandwidthAvg   uint64    // Average bandwidth (bytes/sec)
	BandwidthBurst uint64    // Burst bandwidth (bytes/sec)
	BandwidthObs   uint64    // Observed bandwidth (bytes/sec)
	Contact        string    // Contact information (optional)
	Family         []string  // Relay family members (optional)
	ExitPolicy     string    // Exit policy 行（可多行，默认 "reject *:*"）
	IPv6Policy     string    // ipv6-policy 行
	IPv6Addr       string    // IPv6 address (optional, e.g., "[2001:db8::1]:9001")

	// Cryptographic keys
	RSAIdentity     *rsa.PublicKey    // RSA-1024 identity public key
	Ed25519Identity ed25519.PublicKey // Ed25519 identity public key
	NtorOnionKey    []byte            // Curve25519 ntor onion key (32 bytes)
	NtorPrivate     []byte            // ntor 私钥，签发 ntor-onion-key-crosscert

	// Internal fields
	rsaPrivate      *rsa.PrivateKey    // RSA private key for signing
	ed25519Private  ed25519.PrivateKey // Ed25519 主身份私钥，签发 type-04
	Digest          []byte             // SHA-1 digest of descriptor (computed)
	Signature       []byte             // RSA signature of descriptor
	RawDescriptor   []byte             // Complete descriptor text
	extraInfoSHA1   []byte             // 对应 extra-info 的 SHA-1
	extraInfoSHA256 []byte             // 对应 extra-info 的 SHA-256
}

// ExtraInfoDescriptor represents optional extra-info descriptor
// Per dir-spec.txt §2.2, extra-info contains additional statistics
type ExtraInfoDescriptor struct {
	Nickname      string
	Fingerprint   string
	PublishedTime time.Time
	Statistics    map[string]string
	Digest        []byte // SHA-1（签到 router-signature\n，不含 PEM）
	DigestSHA256  []byte // SHA-256（整份含签名，dir-spec 既有实现差）
	Signature     []byte
	RawDescriptor []byte // Complete extra-info descriptor text
}

// DescriptorConfig holds configuration for descriptor generation
type DescriptorConfig struct {
	Nickname        string    // Relay nickname (default: auto-generated)
	Address         string    // IPv4 address (required)
	ORPort          uint16    // OR port (required)
	DirPort         uint16    // Directory port (0 for bridges)
	Contact         string    // Contact info (optional)
	Family          []string  // Family members (optional)
	BandwidthAvg    uint64    // Average bandwidth (default: 1MB/s)
	BandwidthBurst  uint64    // Burst bandwidth (default: 2MB/s)
	IPv6Addr        string    // IPv6 address:port (optional)
	IsBridge        bool      // Whether this is a bridge relay
	Uptime          int       // 已运行秒数
	ExitPolicyLines []string  // 真实 accept/reject 行；空则 reject *:*
	IPv6Policy      string    // ipv6-policy 行（可含关键字）
	PublishedTime   time.Time // 零值则用现在；与 extra-info 必须同一时刻
	ExtraInfoSHA1   []byte    // extra-info SHA-1（20 字节）；空则不写 extra-info-digest
	ExtraInfoSHA256 []byte    // extra-info SHA-256（32 字节）；与 SHA-1 一起写
}

// GenerateServerDescriptor creates a signed server descriptor
// This implements dir-spec.txt §2.1 server descriptor format
func GenerateServerDescriptor(keys *RelayKeys, config *DescriptorConfig) (*ServerDescriptor, error) {
	if keys == nil {
		return nil, fmt.Errorf("relay keys cannot be nil")
	}
	if config == nil {
		return nil, fmt.Errorf("descriptor config cannot be nil")
	}
	if config.Address == "" {
		return nil, fmt.Errorf("relay address is required")
	}
	if config.ORPort == 0 {
		return nil, fmt.Errorf("OR port is required")
	}

	// Validate address
	if net.ParseIP(config.Address) == nil {
		return nil, fmt.Errorf("invalid IPv4 address: %s", config.Address)
	}

	// Set defaults
	nickname := config.Nickname
	if nickname == "" {
		nickname = generateNickname(keys)
	}

	bandwidthAvg := config.BandwidthAvg
	if bandwidthAvg == 0 {
		bandwidthAvg = 1024 * 1024 // 1 MB/s default
	}

	bandwidthBurst := config.BandwidthBurst
	if bandwidthBurst == 0 {
		bandwidthBurst = bandwidthAvg * 2 // 2x average
	}

	// Observed bandwidth starts at average (will be updated by bandwidth measurement)
	bandwidthObs := bandwidthAvg

	exitPolicy := "reject *:*"
	if len(config.ExitPolicyLines) > 0 {
		exitPolicy = strings.Join(config.ExitPolicyLines, "\n")
	}

	// Compute ntor onion public key from private key
	var ntorPublic [32]byte
	curve25519.ScalarBaseMult(&ntorPublic, (*[32]byte)(keys.NtorOnionKey))

	published := config.PublishedTime.UTC()
	if published.IsZero() {
		published = time.Now().UTC()
	}

	desc := &ServerDescriptor{
		Nickname:        nickname,
		Address:         config.Address,
		ORPort:          config.ORPort,
		DirPort:         config.DirPort,
		Platform:        "go-tor 0.1.0 on Go",
		PublishedTime:   published,
		Uptime:          config.Uptime,
		BandwidthAvg:    bandwidthAvg,
		BandwidthBurst:  bandwidthBurst,
		BandwidthObs:    bandwidthObs,
		Contact:         config.Contact,
		Family:          config.Family,
		ExitPolicy:      exitPolicy,
		IPv6Policy:      strings.TrimSpace(config.IPv6Policy),
		IPv6Addr:        config.IPv6Addr,
		RSAIdentity:     &keys.RSAPrivate.PublicKey,
		Ed25519Identity: keys.Ed25519Public,
		NtorOnionKey:    ntorPublic[:],
		NtorPrivate:     append([]byte(nil), keys.NtorOnionKey...),
		rsaPrivate:      keys.RSAPrivate,
		ed25519Private:  keys.Ed25519Private,
		extraInfoSHA1:   append([]byte(nil), config.ExtraInfoSHA1...),
		extraInfoSHA256: append([]byte(nil), config.ExtraInfoSHA256...),
	}

	// Build and sign descriptor
	if err := desc.build(); err != nil {
		return nil, fmt.Errorf("failed to build descriptor: %w", err)
	}

	return desc, nil
}

// build constructs the descriptor text and computes digest/signature
func (d *ServerDescriptor) build() error {
	if d.rsaPrivate == nil {
		return fmt.Errorf("RSA private key is required to sign descriptor")
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate descriptor signing key: %w", err)
	}
	idCert, err := makeEd25519SigningCert(d.ed25519Private, signPub)
	if err != nil {
		return fmt.Errorf("identity-ed25519 cert: %w", err)
	}
	tapKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return fmt.Errorf("generate TAP onion-key: %w", err)
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "router %s %s %d 0 %d\n",
		d.Nickname, d.Address, d.ORPort, d.DirPort)
	if d.IPv6Addr != "" {
		fmt.Fprintf(&buf, "or-address %s\n", d.IPv6Addr)
	}
	writePEMBlock(&buf, "identity-ed25519", "ED25519 CERT", idCert)
	fmt.Fprintf(&buf, "master-key-ed25519 %s\n",
		base64.RawStdEncoding.EncodeToString(d.Ed25519Identity))
	fmt.Fprintf(&buf, "platform %s\n", d.Platform)
	// proto 只写已实现能力。
	// DirCache 已能对外提供最多 72 小时历史→当前的 limited-ed、gzip/deflate/x-zstd/x-tor-lzma 与 304，
	// 但仍缺真网被当缓存的证据，禁止写 DirCache=2。
	// HS 中继可转发 INTRODUCE1→INTRODUCE2、RENDEZVOUS1→RENDEZVOUS2，
	// 以及 BEGIN_DIR /tor/hs/3 收/服外层描述符；仍缺限速/生命周期/真网被选，
	// 禁止写 HSDir= / HSIntro= / HSRend=。
	// LinkAuth=3：入站已校验 AUTHENTICATE type 3（SLOG/CLOG/SCERT/TLSSECRETS/SIG）。
	fmt.Fprintf(&buf, "proto Link=3-5 LinkAuth=3 Circuit=1-4 Relay=1-4 FlowCtrl=1-2 Padding=2 Conflux=1\n")
	fmt.Fprintf(&buf, "published %s\n",
		d.PublishedTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&buf, "fingerprint %s\n", formatFingerprintGroups(d.Fingerprint()))
	fmt.Fprintf(&buf, "uptime %d\n", d.Uptime)
	fmt.Fprintf(&buf, "bandwidth %d %d %d\n",
		d.BandwidthAvg, d.BandwidthBurst, d.BandwidthObs)
	if len(d.extraInfoSHA1) == sha1.Size {
		sha1Hex := strings.ToUpper(hex.EncodeToString(d.extraInfoSHA1))
		if len(d.extraInfoSHA256) == sha256.Size {
			fmt.Fprintf(&buf, "extra-info-digest %s %s\n", sha1Hex,
				base64.RawStdEncoding.EncodeToString(d.extraInfoSHA256))
		} else {
			fmt.Fprintf(&buf, "extra-info-digest %s\n", sha1Hex)
		}
	}
	if err := writeRSAPublicPEM(&buf, "onion-key", &tapKey.PublicKey); err != nil {
		return err
	}
	tapCross, err := signOnionKeyCrosscert(tapKey, d.RSAIdentity, d.Ed25519Identity)
	if err != nil {
		return err
	}
	writePEMBlock(&buf, "onion-key-crosscert", "CROSSCERT", tapCross)
	fmt.Fprintf(&buf, "ntor-onion-key %s\n",
		base64.RawStdEncoding.EncodeToString(d.NtorOnionKey))
	ntorBit, ntorCert, err := makeNtorOnionKeyCrosscert(d.NtorPrivate, d.Ed25519Identity)
	if err != nil {
		return err
	}
	fmt.Fprintf(&buf, "ntor-onion-key-crosscert %d\n", ntorBit)
	writePEMBlock(&buf, "", "ED25519 CERT", ntorCert)
	if err := writeRSAPublicPEM(&buf, "signing-key", d.RSAIdentity); err != nil {
		return err
	}
	if d.Contact != "" {
		fmt.Fprintf(&buf, "contact %s\n", d.Contact)
	}
	if len(d.Family) > 0 {
		fmt.Fprintf(&buf, "family %s\n", strings.Join(d.Family, " "))
	}
	if strings.Contains(d.ExitPolicy, "\n") || strings.HasPrefix(d.ExitPolicy, "accept") || strings.HasPrefix(d.ExitPolicy, "reject") {
		for _, line := range strings.Split(d.ExitPolicy, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			fmt.Fprintf(&buf, "%s\n", line)
		}
	} else {
		fmt.Fprintf(&buf, "reject *:*\n")
	}
	if ipv6 := strings.TrimSpace(d.IPv6Policy); ipv6 != "" {
		if !strings.HasPrefix(ipv6, "ipv6-policy") {
			ipv6 = "ipv6-policy " + ipv6
		}
		fmt.Fprintf(&buf, "%s\n", ipv6)
	}
	if d.DirPort == 0 {
		fmt.Fprintf(&buf, "tunnelled-dir-server\n")
	}

	edSig := signRouterEd25519(signPriv, buf.Bytes())
	fmt.Fprintf(&buf, "router-sig-ed25519 %s\n",
		base64.RawStdEncoding.EncodeToString(edSig))

	// RSA 签名覆盖含 router-signature 行、不含 PEM 签名体（dir-spec）
	rsaBody := buf.String() + "router-signature\n"
	h := sha1.New() // #nosec G401
	h.Write([]byte(rsaBody))
	d.Digest = h.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, d.rsaPrivate, 0, d.Digest)
	if err != nil {
		return fmt.Errorf("failed to sign descriptor: %w", err)
	}
	d.Signature = signature
	fmt.Fprintf(&buf, "router-signature\n")
	writePEMBlock(&buf, "", "SIGNATURE", signature)
	d.RawDescriptor = buf.Bytes()
	if err := VerifyServerDescriptorDocument(d.RawDescriptor, d.Ed25519Identity, d.RSAIdentity, d.NtorOnionKey); err != nil {
		return fmt.Errorf("descriptor self-check failed: %w", err)
	}
	// 私钥只用于签发交叉证书，自检通过后从描述符结构体清掉，避免误日志。
	for i := range d.NtorPrivate {
		d.NtorPrivate[i] = 0
	}
	d.NtorPrivate = nil
	return nil
}

func writeRSAPublicPEM(buf *bytes.Buffer, keyword string, pub *rsa.PublicKey) error {
	pemBytes, err := crypto.RSAPublicKeyToPEM(pub)
	if err != nil {
		return fmt.Errorf("encode %s: %w", keyword, err)
	}
	if keyword != "" {
		fmt.Fprintf(buf, "%s\n", keyword)
	}
	buf.Write(pemBytes)
	if !bytes.HasSuffix(pemBytes, []byte("\n")) {
		buf.WriteByte('\n')
	}
	return nil
}

func writePEMBlock(buf *bytes.Buffer, keyword, pemType string, der []byte) {
	if keyword != "" {
		fmt.Fprintf(buf, "%s\n", keyword)
	}
	fmt.Fprintf(buf, "-----BEGIN %s-----\n", pemType)
	b64 := base64.StdEncoding.EncodeToString(der)
	for i := 0; i < len(b64); i += 64 {
		end := i + 64
		if end > len(b64) {
			end = len(b64)
		}
		fmt.Fprintf(buf, "%s\n", b64[i:end])
	}
	fmt.Fprintf(buf, "-----END %s-----\n", pemType)
}

func formatFingerprintGroups(hex40 string) string {
	hex40 = strings.ToUpper(hex40)
	if len(hex40) != 40 {
		return hex40
	}
	var b strings.Builder
	for i := 0; i < 40; i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(hex40[i : i+4])
	}
	return b.String()
}

const routerEd25519SigPrefix = "Tor router descriptor signature v1"

// signRouterEd25519 按 dir-spec：Ed25519(SHA256(PREFIX || 文档含 "router-sig-ed25519 "))。
func signRouterEd25519(signPriv ed25519.PrivateKey, body []byte) []byte {
	signed := make([]byte, 0, len(routerEd25519SigPrefix)+len(body)+len("router-sig-ed25519 "))
	signed = append(signed, routerEd25519SigPrefix...)
	signed = append(signed, body...)
	signed = append(signed, []byte("router-sig-ed25519 ")...)
	sum := sha256.Sum256(signed)
	return ed25519.Sign(signPriv, sum[:])
}

// signOnionKeyCrosscert 用 TAP 私钥签 SHA1(PKCS1(RSA id)) || Ed25519 id（52 字节）。
func signOnionKeyCrosscert(tap *rsa.PrivateKey, rsaID *rsa.PublicKey, edID ed25519.PublicKey) ([]byte, error) {
	if tap == nil || rsaID == nil || len(edID) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("onion-key-crosscert: missing keys")
	}
	payload := onionKeyCrosscertPayload(rsaID, edID)
	sig, err := rsa.SignPKCS1v15(rand.Reader, tap, 0, payload)
	if err != nil {
		return nil, fmt.Errorf("onion-key-crosscert sign: %w", err)
	}
	return sig, nil
}

func onionKeyCrosscertPayload(rsaID *rsa.PublicKey, edID ed25519.PublicKey) []byte {
	der := x509.MarshalPKCS1PublicKey(rsaID)
	sum := sha1.Sum(der) // #nosec G401
	out := make([]byte, 0, 52)
	out = append(out, sum[:]...)
	out = append(out, edID...)
	return out
}

// makeNtorOnionKeyCrosscert 生成 type-0A 证书：ntor 私钥签主身份。
func makeNtorOnionKeyCrosscert(ntorPriv []byte, edID ed25519.PublicKey) (int, []byte, error) {
	kp, err := crypto.Ed25519KeypairFromCurve25519(ntorPriv)
	if err != nil {
		return 0, nil, err
	}
	cert := &protocol.Ed25519Certificate{
		Version:      1,
		CertType:     uint8(protocol.CertTypeNtorOnionKeyCrossCert),
		ExpiresAt:    time.Now().UTC().Add(30 * 24 * time.Hour),
		CertKeyType:  1,
		CertifiedKey: append([]byte(nil), edID...),
	}
	msg := cert.PrepareSignedBytes()
	sig, err := kp.Sign(msg)
	if err != nil {
		return 0, nil, err
	}
	cert.Signature = sig
	return kp.SignBit, protocol.EncodeEd25519Certificate(cert), nil
}

// makeEd25519SigningCert 生成 cert-spec type-04：Ed25519 签名钥由主身份签发。
func makeEd25519SigningCert(idPriv ed25519.PrivateKey, signPub ed25519.PublicKey) ([]byte, error) {
	if len(idPriv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 identity private key")
	}
	idPub, ok := idPriv.Public().(ed25519.PublicKey)
	if !ok || len(idPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 identity public key")
	}
	cert := &protocol.Ed25519Certificate{
		Version:      1,
		CertType:     uint8(protocol.CertTypeEd25519Signing),
		ExpiresAt:    time.Now().UTC().Add(30 * 24 * time.Hour),
		CertKeyType:  1,
		CertifiedKey: append([]byte(nil), signPub...),
		Extensions: []protocol.Ed25519Extension{{
			ExtType: protocol.ExtTypeSignedWithEd25519Key,
			Flags:   0,
			ExtData: append([]byte(nil), idPub...),
		}},
	}
	protocol.SignEd25519Certificate(cert, idPriv)
	return protocol.EncodeEd25519Certificate(cert), nil
}

// generateNickname creates a default nickname from relay fingerprint
func generateNickname(keys *RelayKeys) string {
	// Use first 8 chars of hex-encoded Ed25519 public key
	if len(keys.Ed25519Public) >= 4 {
		return "Unnamed" + hex.EncodeToString(keys.Ed25519Public[:4])
	}
	return "UnnamedRelay"
}

// Fingerprint returns the relay's SHA-1 fingerprint (40 hex chars)
func (d *ServerDescriptor) Fingerprint() string {
	if d.RSAIdentity == nil {
		return ""
	}
	der := x509.MarshalPKCS1PublicKey(d.RSAIdentity)
	sum := sha1.Sum(der) // #nosec G401
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// Ed25519Fingerprint returns base64-encoded Ed25519 identity
func (d *ServerDescriptor) Ed25519Fingerprint() string {
	return base64.StdEncoding.EncodeToString(d.Ed25519Identity)
}

// Validate checks descriptor integrity
func (d *ServerDescriptor) Validate() error {
	if d.Nickname == "" {
		return fmt.Errorf("nickname is required")
	}
	if len(d.Nickname) > 19 {
		return fmt.Errorf("nickname too long (max 19 chars): %s", d.Nickname)
	}
	if d.Address == "" {
		return fmt.Errorf("address is required")
	}
	if d.ORPort == 0 {
		return fmt.Errorf("OR port is required")
	}
	if d.RSAIdentity == nil {
		return fmt.Errorf("RSA identity key is required")
	}
	if len(d.Ed25519Identity) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid Ed25519 key size: %d", len(d.Ed25519Identity))
	}
	if len(d.NtorOnionKey) != 32 {
		return fmt.Errorf("invalid ntor key size: %d", len(d.NtorOnionKey))
	}
	if len(d.Signature) == 0 {
		return fmt.Errorf("descriptor signature is required")
	}
	if len(d.RawDescriptor) == 0 {
		return fmt.Errorf("raw descriptor is empty")
	}
	return nil
}

// GenerateDescriptorPair 先签 extra-info，再把 extra-info-digest 写入 server descriptor。
// published 两边相同。stats 只应含观测值；nil/空则不写 write-history / read-history。
func GenerateDescriptorPair(keys *RelayKeys, config *DescriptorConfig, stats map[string]string) (*ServerDescriptor, *ExtraInfoDescriptor, error) {
	if keys == nil {
		return nil, nil, fmt.Errorf("relay keys cannot be nil")
	}
	if config == nil {
		return nil, nil, fmt.Errorf("descriptor config cannot be nil")
	}
	cfg := *config
	if cfg.PublishedTime.IsZero() {
		cfg.PublishedTime = time.Now().UTC()
	}
	nickname := cfg.Nickname
	if nickname == "" {
		nickname = generateNickname(keys)
	}
	extra, err := generateExtraInfoAt(keys, nickname, strings.ToUpper(keys.Fingerprint()), cfg.PublishedTime, stats)
	if err != nil {
		return nil, nil, err
	}
	cfg.Nickname = nickname
	cfg.ExtraInfoSHA1 = extra.Digest
	cfg.ExtraInfoSHA256 = extra.DigestSHA256
	desc, err := GenerateServerDescriptor(keys, &cfg)
	if err != nil {
		return nil, nil, err
	}
	return desc, extra, nil
}

// GenerateExtraInfo creates an extra-info descriptor with statistics
// Per dir-spec.txt §2.2, extra-info provides bandwidth and usage statistics
func GenerateExtraInfo(keys *RelayKeys, desc *ServerDescriptor, stats map[string]string) (*ExtraInfoDescriptor, error) {
	if keys == nil {
		return nil, fmt.Errorf("relay keys cannot be nil")
	}
	if desc == nil {
		return nil, fmt.Errorf("server descriptor cannot be nil")
	}
	published := desc.PublishedTime
	if published.IsZero() {
		published = time.Now().UTC()
	}
	return generateExtraInfoAt(keys, desc.Nickname, desc.Fingerprint(), published, stats)
}

func generateExtraInfoAt(keys *RelayKeys, nickname, fingerprint string, published time.Time, stats map[string]string) (*ExtraInfoDescriptor, error) {
	if keys == nil {
		return nil, fmt.Errorf("relay keys cannot be nil")
	}
	if nickname == "" {
		return nil, fmt.Errorf("extra-info nickname is required")
	}
	fingerprint = strings.ToUpper(strings.ReplaceAll(fingerprint, " ", ""))
	if len(fingerprint) != 40 {
		return nil, fmt.Errorf("extra-info fingerprint must be 40 hex chars")
	}
	if published.IsZero() {
		published = time.Now().UTC()
	}
	extraInfo := &ExtraInfoDescriptor{
		Nickname:      nickname,
		Fingerprint:   fingerprint,
		PublishedTime: published.UTC(),
		Statistics:    stats,
	}

	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("extra-info signing key: %w", err)
	}
	idCert, err := makeEd25519SigningCert(keys.Ed25519Private, signPub)
	if err != nil {
		return nil, fmt.Errorf("extra-info identity-ed25519: %w", err)
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "extra-info %s %s\n", extraInfo.Nickname, extraInfo.Fingerprint)
	writePEMBlock(&buf, "identity-ed25519", "ED25519 CERT", idCert)
	fmt.Fprintf(&buf, "published %s\n",
		extraInfo.PublishedTime.Format("2006-01-02 15:04:05"))
	writeExtraInfoStats(&buf, stats)

	edSig := signRouterEd25519(signPriv, buf.Bytes())
	fmt.Fprintf(&buf, "router-sig-ed25519 %s\n",
		base64.RawStdEncoding.EncodeToString(edSig))

	rsaBody := buf.String() + "router-signature\n"
	h := sha1.New() // #nosec G401
	h.Write([]byte(rsaBody))
	extraInfo.Digest = h.Sum(nil)
	sig, err := rsa.SignPKCS1v15(rand.Reader, keys.RSAPrivate, 0, extraInfo.Digest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign extra-info: %w", err)
	}
	extraInfo.Signature = sig
	fmt.Fprintf(&buf, "router-signature\n")
	writePEMBlock(&buf, "", "SIGNATURE", sig)
	extraInfo.RawDescriptor = buf.Bytes()
	sum256 := sha256.Sum256(extraInfo.RawDescriptor)
	extraInfo.DigestSHA256 = sum256[:]
	if err := VerifyExtraInfoDocument(extraInfo.RawDescriptor, keys.Ed25519Public, &keys.RSAPrivate.PublicKey); err != nil {
		return nil, fmt.Errorf("extra-info self-check failed: %w", err)
	}
	return extraInfo, nil
}

func writeExtraInfoStats(buf *bytes.Buffer, stats map[string]string) {
	if len(stats) == 0 {
		return
	}
	preferred := []string{"write-history", "read-history", "ipv6-write-history", "ipv6-read-history"}
	seen := make(map[string]bool, len(preferred))
	for _, k := range preferred {
		v := strings.TrimSpace(stats[k])
		if v == "" {
			continue
		}
		fmt.Fprintf(buf, "%s %s\n", k, v)
		seen[k] = true
	}
	rest := make([]string, 0, len(stats))
	for k, v := range stats {
		if seen[k] || strings.TrimSpace(v) == "" {
			continue
		}
		rest = append(rest, k)
	}
	sort.Strings(rest)
	for _, k := range rest {
		fmt.Fprintf(buf, "%s %s\n", k, strings.TrimSpace(stats[k]))
	}
}

// String returns human-readable descriptor summary
func (d *ServerDescriptor) String() string {
	return fmt.Sprintf("ServerDescriptor{nickname=%s, address=%s:%d, fingerprint=%s}",
		d.Nickname, d.Address, d.ORPort, d.Fingerprint()[:16]+"...")
}
