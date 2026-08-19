// Package crypto provides cryptographic primitives for the Tor protocol.
// This package wraps Go's standard crypto libraries for Tor-specific operations.
//
// Security considerations:
// - All random number generation uses crypto/rand (CSPRNG)
// - Sensitive data should be zeroed after use (see security.SecureZeroMemory)
// - Key comparisons should use constant-time operations (see security.ConstantTimeCompare)
// - Memory containing keys should be zeroed before being freed
package crypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 - SHA1 required by Tor protocol specification (tor-spec.txt)
	"crypto/sha256"
	"crypto/x509"
	"encoding"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
	"strings"
	"sync"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/sha3"
)

// Key sizes
const (
	// AES128KeySize is the size of AES-128 keys
	AES128KeySize = 16
	// AES256KeySize is the size of AES-256 keys
	AES256KeySize = 32
	// SHA1Size is the size of SHA-1 digests
	SHA1Size = 20
	// SHA256Size is the size of SHA-256 digests
	SHA256Size = 32
)

// GenerateRandomBytes generates n random bytes using crypto/rand
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}

// SHA1Hash computes the SHA-1 hash of the input
// #nosec G401 - SHA1 required by Tor specification (tor-spec.txt section 0.3)
// SHA1 is mandated by the Tor protocol for specific operations and cannot be replaced
// without breaking protocol compatibility. It is not used for collision-resistant purposes.
func SHA1Hash(data []byte) []byte {
	h := sha1.Sum(data) // #nosec G401
	return h[:]
}

// SHA256Hash computes the SHA-256 hash of the input
func SHA256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// AESCTRCipher represents an AES-CTR cipher for encryption/decryption
type AESCTRCipher struct {
	stream cipher.Stream
}

// bufferPool provides pooling for temporary buffers used in cipher operations (SEC-L003)
// This reduces allocation pressure in high-throughput scenarios
var bufferPool = sync.Pool{
	New: func() interface{} {
		// Create 512-byte buffers (standard cell size)
		buf := make([]byte, 512)
		return &buf
	},
}

// GetBuffer retrieves a buffer from the pool (SEC-L003)
func GetBuffer() []byte {
	// Safe type assertion with ok check (AUDIT-R-002: Fixed)
	obj := bufferPool.Get()
	bufPtr, ok := obj.(*[]byte)
	if !ok {
		// This should never happen with our pool, but be defensive
		// Return a new buffer instead of panicking (AUDIT-R-002)
		// This prevents crashing the entire process on unexpected pool behavior
		buf := make([]byte, 512)
		return buf
	}
	return (*bufPtr)[:512]
}

// PutBuffer returns a buffer to the pool (SEC-L003)
func PutBuffer(buf []byte) {
	if cap(buf) >= 512 {
		buf = buf[:512]
		bufferPool.Put(&buf)
	}
}

// NewAESCTRCipher creates a new AES-CTR cipher with the given key and IV
func NewAESCTRCipher(key, iv []byte) (*AESCTRCipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("invalid IV size: %d, expected %d", len(iv), aes.BlockSize)
	}

	stream := cipher.NewCTR(block, iv)
	return &AESCTRCipher{
		stream: stream,
	}, nil
}

// Encrypt encrypts the plaintext in-place using AES-CTR
func (c *AESCTRCipher) Encrypt(plaintext []byte) {
	c.stream.XORKeyStream(plaintext, plaintext)
}

// Decrypt decrypts the ciphertext in-place using AES-CTR
func (c *AESCTRCipher) Decrypt(ciphertext []byte) {
	// In CTR mode, encryption and decryption are the same operation
	c.stream.XORKeyStream(ciphertext, ciphertext)
}

// Stream returns the underlying cipher.Stream for direct use
// This is useful when the cipher needs to be used with the cipher.Stream interface
func (c *AESCTRCipher) Stream() cipher.Stream {
	return c.stream
}

// DecryptAES256CTR decrypts data using AES-256-CTR
func DecryptAES256CTR(ciphertext, key, iv []byte) ([]byte, error) {
	if len(key) != AES256KeySize {
		return nil, fmt.Errorf("invalid key size: %d, expected %d", len(key), AES256KeySize)
	}

	plaintext := make([]byte, len(ciphertext))
	copy(plaintext, ciphertext)

	cipher, err := NewAESCTRCipher(key, iv)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	cipher.Decrypt(plaintext)
	return plaintext, nil
}

// EncryptAES256CTR encrypts data using AES-256-CTR
func EncryptAES256CTR(plaintext, key, iv []byte) ([]byte, error) {
	if len(key) != AES256KeySize {
		return nil, fmt.Errorf("invalid key size: %d, expected %d", len(key), AES256KeySize)
	}

	ciphertext := make([]byte, len(plaintext))
	copy(ciphertext, plaintext)

	cipher, err := NewAESCTRCipher(key, iv)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	cipher.Encrypt(ciphertext)
	return ciphertext, nil
}

// RSAPublicKey wraps an RSA public key
type RSAPublicKey struct {
	key *rsa.PublicKey
}

// RSAPrivateKey wraps an RSA private key
type RSAPrivateKey struct {
	key *rsa.PrivateKey
}

// GenerateRSAKey generates a new RSA key pair with the given bit size
func GenerateRSAKey(bits int) (*RSAPrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}
	return &RSAPrivateKey{key: key}, nil
}

// ParseRSAPublicKey parses an RSA public key from PKCS#1 DER format
// This is used for parsing hardcoded Tor directory authority keys
func ParseRSAPublicKey(derBytes []byte) (*RSAPublicKey, error) {
	key, err := x509.ParsePKCS1PublicKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
	}
	return &RSAPublicKey{key: key}, nil
}

// PublicKey returns the public key corresponding to the private key
func (k *RSAPrivateKey) PublicKey() *RSAPublicKey {
	return &RSAPublicKey{key: &k.key.PublicKey}
}

// Encrypt encrypts data using RSA OAEP with SHA-1
// #nosec G401 - SHA1 with RSA-OAEP required by Tor specification (tor-spec.txt section 0.3)
// The Tor protocol mandates RSA-1024-OAEP-SHA1 for hybrid encryption.
func (k *RSAPublicKey) Encrypt(plaintext []byte) ([]byte, error) {
	ciphertext, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, k.key, plaintext, nil) // #nosec G401
	if err != nil {
		return nil, fmt.Errorf("RSA encryption failed: %w", err)
	}
	return ciphertext, nil
}

// Decrypt decrypts data using RSA OAEP with SHA-1
// #nosec G401 - SHA1 with RSA-OAEP required by Tor specification (tor-spec.txt section 0.3)
// The Tor protocol mandates RSA-1024-OAEP-SHA1 for hybrid encryption.
func (k *RSAPrivateKey) Decrypt(ciphertext []byte) ([]byte, error) {
	plaintext, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, k.key, ciphertext, nil) // #nosec G401
	if err != nil {
		return nil, fmt.Errorf("RSA decryption failed: %w", err)
	}
	return plaintext, nil
}

// VerifySignatureSHA1 verifies an RSA-PKCS1v15 signature with SHA-1 hash
// #nosec G401 - SHA1 with RSA-PKCS1v15 required by Tor specification (dir-spec.txt §3.4)
// Tor directory signatures use SHA-1 or SHA-256 with RSA-PKCS1v15
func (k *RSAPublicKey) VerifySignatureSHA1(message, signature []byte) error {
	hash := sha1.Sum(message) // #nosec G401
	if err := rsa.VerifyPKCS1v15(k.key, crypto.SHA1, hash[:], signature); err != nil {
		return fmt.Errorf("RSA signature verification failed: %w", err)
	}
	return nil
}

// VerifySignatureSHA256 verifies an RSA-PKCS1v15 signature with SHA-256 hash
func (k *RSAPublicKey) VerifySignatureSHA256(message, signature []byte) error {
	hash := sha256.Sum256(message)
	if err := rsa.VerifyPKCS1v15(k.key, crypto.SHA256, hash[:], signature); err != nil {
		return fmt.Errorf("RSA signature verification failed: %w", err)
	}
	return nil
}

// DigestWriter wraps a hash writer for computing running digests
type DigestWriter struct {
	hash io.Writer
}

// NewSHA1DigestWriter creates a new SHA-1 digest writer
// #nosec G401 - SHA1 required by Tor specification (tor-spec.txt)
// SHA1 is mandated by the Tor protocol for computing digests in various protocol operations.
func NewSHA1DigestWriter() *DigestWriter {
	return &DigestWriter{hash: sha1.New()} // #nosec G401
}

// Write writes data to the digest
func (d *DigestWriter) Write(p []byte) (n int, err error) {
	return d.hash.Write(p)
}

// DeriveKey derives key material using KDF-TOR
// KDF-TOR uses iterative SHA-1 hashing to expand a shared secret
//
// Security note: The caller is responsible for zeroing the returned key material
// when it's no longer needed using security.SecureZeroMemory()
func DeriveKey(secret []byte, keyLen int) ([]byte, error) {
	if keyLen <= 0 {
		return nil, fmt.Errorf("invalid key length: %d", keyLen)
	}

	// KDF-TOR: K = K_0 | K_1 | K_2 | ...
	// Where K_i = H(K_0 | [i])
	// And K_0 = H(secret)

	k0 := SHA1Hash(secret)
	result := make([]byte, 0, keyLen)

	// Append K_0
	result = append(result, k0...)

	// Generate additional blocks if needed
	i := byte(1)
	for len(result) < keyLen {
		// K_i = H(K_0 | [i])
		data := append(k0, i)
		ki := SHA1Hash(data)
		result = append(result, ki...)
		i++
	}

	// Return exactly keyLen bytes
	return result[:keyLen], nil
}

// NtorKeyPair represents a Curve25519 key pair for ntor handshake
type NtorKeyPair struct {
	Private [32]byte
	Public  [32]byte
}

// GenerateNtorKeyPair generates a new Curve25519 key pair for ntor handshake
// This implements tor-spec.txt section 5.1.4 (ntor handshake)
func GenerateNtorKeyPair() (*NtorKeyPair, error) {
	kp := &NtorKeyPair{}

	// Generate random private key
	if _, err := rand.Read(kp.Private[:]); err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Compute public key: X = x*G
	curve25519.ScalarBaseMult(&kp.Public, &kp.Private)

	return kp, nil
}

// NtorClientHandshake / NtorProcessResponse 的规范实现见 ntor.go。

// constantTimeCompare performs constant-time comparison of two byte slices
// This prevents timing attacks when comparing cryptographic values
func constantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte = 0
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// ConstantTimeCompare is the exported version of constantTimeCompare
func ConstantTimeCompare(a, b []byte) bool {
	return constantTimeCompare(a, b)
}

// CloneHash clones a hash.Hash by marshaling and unmarshaling its state
// This is used for non-destructive digest verification in relay cells
// Per tor-spec.txt §6.1, relay cell digest verification requires checking
// the hash state before and after updating with the cell
func CloneHash(h hash.Hash) (hash.Hash, error) {
	marshaler, ok := h.(encoding.BinaryMarshaler)
	if !ok {
		return nil, fmt.Errorf("hash does not support binary marshaling: %T", h)
	}
	state, err := marshaler.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal hash state: %w", err)
	}

	typeName := fmt.Sprintf("%T", h)
	var candidates []hash.Hash
	switch {
	case strings.Contains(typeName, "sha3"):
		candidates = []hash.Hash{sha3.New256()}
	case h.Size() == 20:
		candidates = []hash.Hash{sha1.New()}
	case h.Size() == 32 && strings.Contains(typeName, "sha256"):
		candidates = []hash.Hash{sha256.New(), sha3.New256()}
	case h.Size() == 32:
		candidates = []hash.Hash{sha3.New256(), sha256.New()}
	default:
		return nil, fmt.Errorf("unsupported hash: %T size=%d", h, h.Size())
	}

	var lastErr error
	for _, newHash := range candidates {
		u, ok := newHash.(encoding.BinaryUnmarshaler)
		if !ok {
			lastErr = fmt.Errorf("no BinaryUnmarshaler: %T", newHash)
			continue
		}
		if err := u.UnmarshalBinary(state); err != nil {
			lastErr = err
			continue
		}
		return newHash, nil
	}
	return nil, fmt.Errorf("failed to unmarshal hash state (%T): %w", h, lastErr)
}

// Ed25519Verify verifies an Ed25519 signature
// This is used for onion service descriptor signature verification
// Implements rend-spec-v3.txt section 2.1
func Ed25519Verify(publicKey, message, signature []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	if len(signature) != ed25519.SignatureSize {
		return false
	}

	return ed25519.Verify(ed25519.PublicKey(publicKey), message, signature)
}

// Ed25519Sign signs a message with an Ed25519 private key
func Ed25519Sign(privateKey, message []byte) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length: %d", len(privateKey))
	}

	signature := ed25519.Sign(ed25519.PrivateKey(privateKey), message)
	return signature, nil
}

// GenerateEd25519KeyPair generates a new Ed25519 key pair
func GenerateEd25519KeyPair() (publicKey, privateKey []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}
	return pub, priv, nil
}

// RSAPublicKeyToPEM converts an RSA public key to PEM format
// This is used for encoding relay identity keys in server descriptors
func RSAPublicKeyToPEM(key *rsa.PublicKey) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("public key is nil")
	}

	derBytes := x509.MarshalPKCS1PublicKey(key)
	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derBytes,
	}

	return pem.EncodeToMemory(block), nil
}
