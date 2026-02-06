package aes

import (
	"bytes"
	"testing"
)

func TestNewCipher(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
		version int
		wantErr bool
	}{
		{"valid 16-byte key", 16, 1, false},
		{"valid 24-byte key", 24, 1, false},
		{"valid 32-byte key", 32, 1, false},
		{"invalid 15-byte key", 15, 1, true},
		{"invalid 17-byte key", 17, 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			for i := range key {
				key[i] = byte(i)
			}

			cipher, err := NewCipher(key, tt.version)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if cipher == nil {
					t.Error("expected cipher but got nil")
				}
			}
		})
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	cipher, err := NewCipher(key, 1)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	tests := []struct {
		name      string
		plaintext []byte
		aad       []byte
	}{
		{"simple message", []byte("Hello, World!"), nil},
		{"with AAD", []byte("secret data"), []byte("context")},
		{"binary data", []byte{0x00, 0x01, 0x02, 0xff, 0xfe}, nil},
		{"large message", bytes.Repeat([]byte("x"), 10000), nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := cipher.Encrypt(tt.plaintext, tt.aad)
			if err != nil {
				t.Fatalf("encrypt failed: %v", err)
			}

			// Verify format: vault:v1:base64
			if len(ciphertext) < len(CiphertextPrefix)+5 {
				t.Errorf("ciphertext too short")
			}

			plaintext, version, err := cipher.Decrypt(ciphertext, tt.aad)
			if err != nil {
				t.Fatalf("decrypt failed: %v", err)
			}

			if version != 1 {
				t.Errorf("version mismatch: got %d, want 1", version)
			}

			if !bytes.Equal(plaintext, tt.plaintext) {
				t.Errorf("plaintext mismatch")
			}
		})
	}
}

func TestDecryptWithWrongAAD(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	cipher, _ := NewCipher(key, 1)

	plaintext := []byte("secret")
	aad := []byte("correct-context")
	wrongAad := []byte("wrong-context")

	ciphertext, _ := cipher.Encrypt(plaintext, aad)

	_, _, err := cipher.Decrypt(ciphertext, wrongAad)
	if err == nil {
		t.Error("expected error when decrypting with wrong AAD")
	}
}

func TestCiphertextFormat(t *testing.T) {
	key := make([]byte, 32)
	cipher, _ := NewCipher(key, 5)

	ciphertext, _ := cipher.Encrypt([]byte("test"), nil)

	// Should start with vault:v5:
	expected := "vault:v5:"
	if len(ciphertext) < len(expected) {
		t.Fatalf("ciphertext too short")
	}

	if ciphertext[:len(expected)] != expected {
		t.Errorf("wrong prefix: got %s, want %s", ciphertext[:len(expected)], expected)
	}
}

func TestEncryptionIsDeterministic(t *testing.T) {
	key := make([]byte, 32)
	cipher, _ := NewCipher(key, 1)

	plaintext := []byte("same message")

	ct1, _ := cipher.Encrypt(plaintext, nil)
	ct2, _ := cipher.Encrypt(plaintext, nil)

	// Due to random nonce, ciphertexts should be different
	if ct1 == ct2 {
		t.Error("encryption should be non-deterministic (random nonce)")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	key := make([]byte, 32)
	cipher, _ := NewCipher(key, 1)
	plaintext := []byte("benchmark test message for encryption")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.Encrypt(plaintext, nil)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key := make([]byte, 32)
	cipher, _ := NewCipher(key, 1)
	plaintext := []byte("benchmark test message for encryption")
	ciphertext, _ := cipher.Encrypt(plaintext, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.Decrypt(ciphertext, nil)
	}
}
