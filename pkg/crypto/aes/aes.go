// Package aes provides AES-GCM encryption/decryption utilities
package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	fastrand "github.com/pocketsizefund/microservice-vault/pkg/crypto/rand"
)

const (
	// NonceSize is the size of the nonce for AES-GCM (12 bytes)
	NonceSize = 12
	// KeySize256 is the size of AES-256 key (32 bytes)
	KeySize256 = 32
	// KeySize128 is the size of AES-128 key (16 bytes)
	KeySize128 = 16
	// CiphertextPrefix is the prefix for all ciphertexts
	CiphertextPrefix = "vault"
)

var (
	ErrInvalidKeySize      = errors.New("invalid key size: must be 16, 24, or 32 bytes")
	ErrInvalidCiphertext   = errors.New("invalid ciphertext format")
	ErrDecryptionFailed    = errors.New("decryption failed: authentication error")
	ErrInvalidNonceSize    = errors.New("invalid nonce size")
	ErrCiphertextTooShort  = errors.New("ciphertext too short")
)

// Cipher wraps AES-GCM operations
type Cipher struct {
	aead    cipher.AEAD
	version int
}

// NewCipher creates a new AES-GCM cipher with the given key and version
func NewCipher(key []byte, version int) (*Cipher, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &Cipher{
		aead:    aead,
		version: version,
	}, nil
}

// Encrypt encrypts plaintext with optional additional authenticated data (AAD)
// Returns ciphertext in format: vault:v{version}:{base64(nonce + ciphertext + tag)}
func (c *Cipher) Encrypt(plaintext, aad []byte) (string, error) {
	// Get nonce from pool and fill with buffered random bytes
	noncePtr := fastrand.GetNonce()
	defer fastrand.PutNonce(noncePtr)

	if _, err := fastrand.Read(*noncePtr); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	return c.EncryptWithNonce(plaintext, aad, *noncePtr)
}

// EncryptWithNonce encrypts using a provided nonce (for convergent encryption)
func (c *Cipher) EncryptWithNonce(plaintext, aad, nonce []byte) (string, error) {
	if len(nonce) != NonceSize {
		return "", ErrInvalidNonceSize
	}

	// Encrypt: nonce is prepended to ciphertext
	ciphertext := c.aead.Seal(nonce, nonce, plaintext, aad)

	// Encode to base64
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	// Format: vault:v{version}:{base64}
	return fmt.Sprintf("%s:v%d:%s", CiphertextPrefix, c.version, encoded), nil
}

// Decrypt decrypts ciphertext in vault format
func (c *Cipher) Decrypt(ciphertext string, aad []byte) ([]byte, int, error) {
	// Parse version and data
	version, data, err := ParseCiphertext(ciphertext)
	if err != nil {
		return nil, 0, err
	}

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	// Check minimum length (nonce + at least 1 byte + tag)
	if len(decoded) < NonceSize+c.aead.Overhead()+1 {
		return nil, 0, ErrCiphertextTooShort
	}

	// Extract nonce and ciphertext
	nonce := decoded[:NonceSize]
	encrypted := decoded[NonceSize:]

	// Decrypt
	plaintext, err := c.aead.Open(nil, nonce, encrypted, aad)
	if err != nil {
		return nil, 0, ErrDecryptionFailed
	}

	return plaintext, version, nil
}

// DecryptRaw decrypts raw base64 encoded ciphertext (nonce + ciphertext + tag)
func (c *Cipher) DecryptRaw(encoded string, aad []byte) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode: %w", err)
	}

	if len(decoded) < NonceSize+c.aead.Overhead()+1 {
		return nil, ErrCiphertextTooShort
	}

	nonce := decoded[:NonceSize]
	encrypted := decoded[NonceSize:]

	plaintext, err := c.aead.Open(nil, nonce, encrypted, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// Version returns the cipher version
func (c *Cipher) Version() int {
	return c.version
}

// ParseCiphertext parses vault-format ciphertext and returns version and base64 data
func ParseCiphertext(ciphertext string) (int, string, error) {
	parts := strings.Split(ciphertext, ":")
	if len(parts) != 3 {
		return 0, "", ErrInvalidCiphertext
	}

	if parts[0] != CiphertextPrefix {
		return 0, "", ErrInvalidCiphertext
	}

	// Parse version (v1, v2, etc.)
	if len(parts[1]) < 2 || parts[1][0] != 'v' {
		return 0, "", ErrInvalidCiphertext
	}

	version, err := strconv.Atoi(parts[1][1:])
	if err != nil {
		return 0, "", ErrInvalidCiphertext
	}

	return version, parts[2], nil
}

// GenerateKey generates a random AES key of the specified size
func GenerateKey(size int) ([]byte, error) {
	if size != KeySize128 && size != KeySize256 && size != 24 {
		return nil, ErrInvalidKeySize
	}

	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	return key, nil
}
